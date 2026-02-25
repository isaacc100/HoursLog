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


from app import models
