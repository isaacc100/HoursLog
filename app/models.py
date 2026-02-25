from datetime import datetime
import hashlib
from app import db, login_manager, bcrypt
from flask_login import UserMixin


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
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    email_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.utcnow())
    last_login = db.Column(db.DateTime)
    
    # Relationships
    log_entries = db.relationship('LogEntry', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
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
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.utcnow())
    updated_at = db.Column(db.DateTime, default=lambda: datetime.utcnow(), onupdate=lambda: datetime.utcnow())
    
    # Secondary roles (many-to-many)
    secondary_roles = db.relationship('Role', secondary=log_entry_secondary_roles,
                                       backref=db.backref('secondary_log_entries', lazy='dynamic'),
                                       lazy='select')
    
    @property
    def total_hours(self):
        """Return activity hours + travel hours."""
        return self.hours + (self.travel_hours or 0)
    
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
