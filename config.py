import os
from datetime import timedelta
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))


class BaseConfig:
    """Shared configuration for all environments."""

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Mail configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'localhost'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 25)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'false').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'noreply@hourslog.com'

    # Application settings
    LOGS_PER_PAGE = 20
    USERS_PER_PAGE = 20

    # Footer
    FOOTER_TEXT = os.environ.get('FOOTER_TEXT') or '© 2026 HoursLog. A volunteer hours tracking application.'

    # Google OAuth SSO
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')

    # Microsoft Azure AD SSO
    AZURE_CLIENT_ID = os.environ.get('AZURE_CLIENT_ID')
    AZURE_CLIENT_SECRET = os.environ.get('AZURE_CLIENT_SECRET')
    AZURE_TENANT_ID = os.environ.get('AZURE_TENANT_ID', 'common')

    # Upload settings
    UPLOAD_FOLDER = os.path.join(basedir, 'app', 'static', 'uploads', 'avatars')
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2MB max upload size
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}


class DevelopmentConfig(BaseConfig):
    """Development configuration — permissive defaults for local work."""

    DEBUG = True
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-for-development-only'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'hourslog.db')
    SESSION_COOKIE_SECURE = False


class ProductionConfig(BaseConfig):
    """Production configuration — strict, nothing optional.

    SECRET_KEY and DATABASE_URL are validated at app-creation time
    (see ``create_app`` in app/__init__.py) so that the check runs
    every time the application factory is called, not just at first import.
    """

    DEBUG = False
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')

    # Security — HTTPS expected
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    PREFERRED_URL_SCHEME = 'https'

    # CSRF token lifetime (seconds)
    WTF_CSRF_TIME_LIMIT = 3600


class TestingConfig(BaseConfig):
    """Testing configuration — fast, isolated."""

    TESTING = True
    SECRET_KEY = 'testing-secret-key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = False


# Legacy alias so existing imports of ``Config`` keep working.
Config = DevelopmentConfig

# Lookup dict used by the application factory.
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
}
