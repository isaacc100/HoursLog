from datetime import datetime
import hashlib
from app import db, login_manager, bcrypt
from flask_login import UserMixin


# ── Permission constants ──────────────────────────────────────────────────
PERMISSION_LEVEL_NAMES = {
    0: 'Deactivated',
    1: 'Standard User',
    2: 'Entry Reviewer',
    7: 'Full Admin',
}

# All granular permission keys
ALL_PERMISSIONS = [
    'can_manage_users',
    'can_change_user_level',
    'can_deactivate_users',
    'can_delete_users',
    'can_manage_roles',
    'can_manage_categories',
    'can_view_audit_log',
    'can_view_all_entries',
    'can_action_entries',
    'can_deny_entries',
    'can_edit_setting_display_name',
    'can_edit_setting_password_reset',
    'can_edit_setting_profile_pic',
    'can_edit_setting_leaderboard_size',
    'can_edit_setting_footer_text',
    'can_view_statistics',
]

# Hardcoded permissions for level 2 (Entry Reviewer)
LEVEL_2_PERMISSIONS = frozenset([
    'can_view_all_entries',
    'can_action_entries',
    'can_deny_entries',
])


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Association table for secondary roles on log entries
log_entry_secondary_roles = db.Table(
    'log_entry_secondary_roles',
    db.Column('log_entry_id', db.Integer, db.ForeignKey('log_entries.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True)
)


class User(db.Model, UserMixin):
    """User model for authentication and user management."""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    display_name = db.Column(db.String(100))
    profile_pic = db.Column(db.String(255))  # Relative path to uploaded avatar
    permission_level = db.Column(db.Integer, default=1, nullable=False, index=True)
    email_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.utcnow())
    last_login = db.Column(db.DateTime)
    
    # Relationships
    log_entries = db.relationship('LogEntry', backref='user', lazy='dynamic',
                                  cascade='all, delete-orphan',
                                  foreign_keys='LogEntry.user_id')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    # ── Backward-compatible properties ────────────────────────────────
    @property
    def is_admin(self):
        """True when user has full admin (level 7)."""
        return self.permission_level == 7
    
    @is_admin.setter
    def is_admin(self, value):
        """Backward compat: setting is_admin=True → level 7, False → level 1."""
        self.permission_level = 7 if value else 1
    
    @property
    def is_active(self):
        """Flask-Login uses this; deactivated users (level 0) cannot log in."""
        return self.permission_level > 0
    
    @is_active.setter
    def is_active(self, value):
        """Backward compat: setting is_active=False → level 0."""
        if not value:
            self.permission_level = 0
        elif self.permission_level == 0:
            self.permission_level = 1
    
    @property
    def is_reviewer(self):
        """True when user can review entries (level >= 2)."""
        return self.permission_level >= 2
    
    @property
    def level_name(self):
        """Human-readable name for this user's permission level."""
        if self.permission_level in PERMISSION_LEVEL_NAMES:
            return PERMISSION_LEVEL_NAMES[self.permission_level]
        # Configurable levels 3-6: look up PermissionLevelConfig
        config = PermissionLevelConfig.query.get(self.permission_level)
        if config and config.name:
            return config.name
        return f'Level {self.permission_level}'
    
    def can(self, permission):
        """Check if this user has a specific permission.
        
        Level 0 → always False
        Level 1 → always False (no admin permissions)
        Level 2 → hardcoded set (entry review only)
        Levels 3-6 → look up PermissionLevelConfig
        Level 7 → always True
        """
        if self.permission_level <= 0:
            return False
        if self.permission_level == 1:
            return False
        if self.permission_level == 7:
            return True
        if self.permission_level == 2:
            return permission in LEVEL_2_PERMISSIONS
        # Levels 3-6: look up config
        config = PermissionLevelConfig.query.get(self.permission_level)
        if config is None:
            return False
        return getattr(config, permission, False)
    
    def has_any_admin_permission(self):
        """True if user has at least one admin-level permission."""
        if self.permission_level >= 7:
            return True
        if self.permission_level == 2:
            return True  # always has entry review permissions
        if self.permission_level <= 1:
            return False
        # Levels 3-6
        config = PermissionLevelConfig.query.get(self.permission_level)
        if config is None:
            return False
        return any(getattr(config, p, False) for p in ALL_PERMISSIONS)
    
    def has_any_settings_permission(self):
        """True if user can edit at least one setting."""
        if self.permission_level == 7:
            return True
        if self.permission_level <= 2:
            return False
        config = PermissionLevelConfig.query.get(self.permission_level)
        if config is None:
            return False
        return any(getattr(config, p, False) for p in ALL_PERMISSIONS if p.startswith('can_edit_setting_'))
    
    def set_password(self, password):
        """Hash and set the user's password."""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        """Check if the provided password matches the hash."""
        return bcrypt.check_password_hash(self.password_hash, password)
    
    @property
    def get_display_name(self):
        """Return display name, falling back to username."""
        if self.display_name:
            return self.display_name
        if self.first_name or self.last_name:
            return f"{self.first_name or ''} {self.last_name or ''}".strip()
        return self.username
    
    @property
    def initials(self):
        """Return user initials for avatar."""
        if self.first_name and self.last_name:
            return (self.first_name[0] + self.last_name[0]).upper()
        if self.display_name:
            parts = self.display_name.split()
            if len(parts) >= 2:
                return (parts[0][0] + parts[1][0]).upper()
            return self.display_name[0].upper()
        return self.username[0].upper()
    
    @property
    def avatar_color(self):
        """Return a deterministic color based on user ID."""
        colors = [
            '#007bff', '#28a745', '#dc3545', '#ffc107', '#17a2b8',
            '#6610f2', '#e83e8c', '#fd7e14', '#20c997', '#6f42c1'
        ]
        hash_val = int(hashlib.md5(str(self.id).encode()).hexdigest(), 16)
        return colors[hash_val % len(colors)]
    
    def __repr__(self):
        return f'<User {self.username}>'


class Category(db.Model):
    """Category model for organizing log entries."""
    __tablename__ = 'categories'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    color = db.Column(db.String(7), default='#007bff')  # Hex color code
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.utcnow())
    
    # Relationships
    log_entries = db.relationship('LogEntry', backref='category', lazy='dynamic')
    
    def __repr__(self):
        return f'<Category {self.name}>'


class Role(db.Model):
    """Role model for different volunteer roles."""
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.utcnow())
    
    # Relationships
    log_entries = db.relationship('LogEntry', backref='role', lazy='dynamic')
    
    def __repr__(self):
        return f'<Role {self.name}>'


class LogEntry(db.Model):
    """LogEntry model for tracking volunteer hours."""
    __tablename__ = 'log_entries'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    notes = db.Column(db.Text)
    hours = db.Column(db.Float, nullable=False)
    travel_hours = db.Column(db.Float, nullable=False, default=0.0)
    date = db.Column(db.Date, nullable=False, default=lambda: datetime.utcnow().date(), index=True)
    
    # Review / approval workflow
    review_status = db.Column(db.String(20), default='active', nullable=False, index=True)
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    denial_reason = db.Column(db.Text, nullable=True)
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.utcnow())
    updated_at = db.Column(db.DateTime, default=lambda: datetime.utcnow(), onupdate=lambda: datetime.utcnow())
    
    # Secondary roles (many-to-many)
    secondary_roles = db.relationship('Role', secondary=log_entry_secondary_roles,
                                       backref=db.backref('secondary_log_entries', lazy='dynamic'),
                                       lazy='select')
    
    # Reviewer relationship
    reviewed_by = db.relationship('User', foreign_keys=[reviewed_by_id],
                                   backref=db.backref('reviewed_entries', lazy='dynamic'))
    
    @property
    def total_hours(self):
        """Return activity hours + travel hours."""
        return self.hours + (self.travel_hours or 0)
    
    @property
    def is_denied(self):
        return self.review_status == 'denied'
    
    @property
    def is_actioned(self):
        return self.review_status == 'actioned'
    
    def __repr__(self):
        return f'<LogEntry {self.title} - {self.hours}h>'


class AppSettings(db.Model):
    """Singleton settings model for global application configuration."""
    __tablename__ = 'app_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    allow_display_name_change = db.Column(db.Boolean, default=True)
    allow_password_reset = db.Column(db.Boolean, default=True)
    allow_profile_pic_change = db.Column(db.Boolean, default=True)
    leaderboard_size = db.Column(db.Integer, default=50)
    footer_text = db.Column(db.String(500), default='')
    
    @classmethod
    def get_settings(cls):
        """Return the singleton settings row, creating it if needed."""
        settings = cls.query.first()
        if not settings:
            settings = cls(
                allow_display_name_change=True,
                allow_password_reset=True,
                allow_profile_pic_change=True,
                leaderboard_size=50
            )
            db.session.add(settings)
            db.session.commit()
        return settings
    
    def __repr__(self):
        return '<AppSettings>'


class AuditLog(db.Model):
    """AuditLog model for tracking user and admin actions."""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=lambda: datetime.utcnow(), index=True)
    
    def __repr__(self):
        return f'<AuditLog {self.action} at {self.timestamp}>'


class PermissionLevelConfig(db.Model):
    """Configurable permission sets for levels 3-6."""
    __tablename__ = 'permission_level_configs'
    
    level = db.Column(db.Integer, primary_key=True)  # 3, 4, 5, or 6
    name = db.Column(db.String(50), default='')
    
    # User management
    can_manage_users = db.Column(db.Boolean, default=False)
    can_change_user_level = db.Column(db.Boolean, default=False)
    can_deactivate_users = db.Column(db.Boolean, default=False)
    can_delete_users = db.Column(db.Boolean, default=False)
    
    # Content management
    can_manage_roles = db.Column(db.Boolean, default=False)
    can_manage_categories = db.Column(db.Boolean, default=False)
    
    # Audit & statistics
    can_view_audit_log = db.Column(db.Boolean, default=False)
    can_view_statistics = db.Column(db.Boolean, default=False)
    
    # Entry review
    can_view_all_entries = db.Column(db.Boolean, default=False)
    can_action_entries = db.Column(db.Boolean, default=False)
    can_deny_entries = db.Column(db.Boolean, default=False)
    
    # Individual settings
    can_edit_setting_display_name = db.Column(db.Boolean, default=False)
    can_edit_setting_password_reset = db.Column(db.Boolean, default=False)
    can_edit_setting_profile_pic = db.Column(db.Boolean, default=False)
    can_edit_setting_leaderboard_size = db.Column(db.Boolean, default=False)
    can_edit_setting_footer_text = db.Column(db.Boolean, default=False)
    
    @classmethod
    def seed_defaults(cls):
        """Create default rows for levels 3-6 if they don't exist."""
        for level in range(3, 7):
            if not cls.query.get(level):
                db.session.add(cls(level=level, name=f'Custom Level {level}'))
        db.session.commit()
    
    def __repr__(self):
        return f'<PermissionLevelConfig level={self.level} name={self.name}>'
