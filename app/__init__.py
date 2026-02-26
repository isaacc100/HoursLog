from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_migrate import Migrate
from config import Config

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
bcrypt = Bcrypt()
mail = Mail()
migrate = Migrate()


def create_app(config_class=Config):
    """Application factory pattern."""
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)
    
    # Configure login manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    # Register blueprints
    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')
    
    from app.main import bp as main_bp
    app.register_blueprint(main_bp)
    
    from app.admin import bp as admin_bp
    app.register_blueprint(admin_bp, url_prefix='/admin')
    
    # Create database tables
    with app.app_context():
        db.create_all()
        _migrate_permission_levels(app)
    
    # Ensure upload directory exists
    import os
    os.makedirs(app.config.get('UPLOAD_FOLDER', 'uploads'), exist_ok=True)
    
    # Context processor — inject globals into all templates
    @app.context_processor
    def inject_globals():
        footer = app.config.get('FOOTER_TEXT', '© 2026 HoursLog.')
        try:
            from app.models import AppSettings
            settings = AppSettings.get_settings()
            if settings.footer_text:
                footer = settings.footer_text
        except Exception:
            pass  # DB column may not exist yet (pre-migration)
        return dict(
            footer_text=footer,
            google_sso_enabled=bool(app.config.get('GOOGLE_CLIENT_ID') and app.config.get('GOOGLE_CLIENT_SECRET')),
            azure_sso_enabled=bool(app.config.get('AZURE_CLIENT_ID') and app.config.get('AZURE_CLIENT_SECRET')),
        )
    
    return app


def _migrate_permission_levels(app):
    """One-time migration: add new columns and convert is_admin/is_active to permission_level."""
    from app.models import User, PermissionLevelConfig
    from sqlalchemy import inspect, text

    inspector = inspect(db.engine)
    user_columns = [c['name'] for c in inspector.get_columns('users')]
    entry_columns = [c['name'] for c in inspector.get_columns('log_entries')]

    # ---- Step 1: Add missing columns via ALTER TABLE ----
    # (db.create_all() does NOT add columns to existing tables)
    alter_stmts = []

    if 'permission_level' not in user_columns:
        alter_stmts.append(
            "ALTER TABLE users ADD COLUMN permission_level INTEGER NOT NULL DEFAULT 1"
        )
    if 'review_status' not in entry_columns:
        alter_stmts.append(
            "ALTER TABLE log_entries ADD COLUMN review_status VARCHAR(20) NOT NULL DEFAULT 'active'"
        )
    if 'reviewed_by_id' not in entry_columns:
        alter_stmts.append(
            "ALTER TABLE log_entries ADD COLUMN reviewed_by_id INTEGER REFERENCES users(id)"
        )
    if 'reviewed_at' not in entry_columns:
        alter_stmts.append(
            "ALTER TABLE log_entries ADD COLUMN reviewed_at TIMESTAMP"
        )
    if 'denial_reason' not in entry_columns:
        alter_stmts.append(
            "ALTER TABLE log_entries ADD COLUMN denial_reason TEXT"
        )

    for stmt in alter_stmts:
        try:
            db.session.execute(text(stmt))
            db.session.commit()
            app.logger.info(f'Migration: {stmt}')
        except Exception as e:
            db.session.rollback()
            app.logger.debug(f'Column already exists or migration skipped: {e}')

    # ---- Step 2: Migrate is_admin/is_active → permission_level ----
    # Always attempt; succeeds when both old & new columns exist, harmless if not
    try:
        # Use boolean-compatible syntax (works on both SQLite and PostgreSQL)
        db.session.execute(text(
            "UPDATE users SET permission_level = CASE "
            "WHEN is_admin = true THEN 7 "
            "WHEN is_active = false THEN 0 "
            "ELSE 1 END "
            "WHERE permission_level = 1"  # only migrate un-migrated rows
        ))
        db.session.commit()
        app.logger.info('Migrated users from is_admin/is_active to permission_level.')
    except Exception as e:
        db.session.rollback()
        app.logger.debug(f'Permission level data migration skipped: {e}')

    # ---- Step 3: Set review_status default for existing entries ----
    try:
        db.session.execute(text(
            "UPDATE log_entries SET review_status = 'active' WHERE review_status IS NULL"
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()

    # ---- Step 4: Seed PermissionLevelConfig rows for levels 3-6 ----
    try:
        PermissionLevelConfig.seed_defaults()
    except Exception as e:
        db.session.rollback()
        app.logger.warning(f'PermissionLevelConfig seed skipped: {e}')


from app import models
