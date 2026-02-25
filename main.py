"""
HoursLog - Volunteer Hours Tracking Application
Main entry point for the Flask application
"""
from app import create_app, db
from app.models import User, Category, Role, LogEntry, AuditLog, AppSettings

app = create_app()


@app.shell_context_processor
def make_shell_context():
    """Make database models available in the Flask shell."""
    return {
        'db': db,
        'User': User,
        'Category': Category,
        'Role': Role,
        'LogEntry': LogEntry,
        'AuditLog': AuditLog,
        'AppSettings': AppSettings
    }


@app.cli.command()
def init_db():
    """Initialize the database with default data."""
    import secrets
    import string
    
    db.create_all()
    
    # Check if we already have data
    if Category.query.first() or Role.query.first():
        print("Database already initialized!")
        return
    
    # Create default categories
    categories = [
        Category(name='Tutoring', description='Educational tutoring activities', color='#007bff'),
        Category(name='Food Service', description='Food preparation and distribution', color='#28a745'),
        Category(name='Event Planning', description='Organizing and managing events', color='#ffc107'),
        Category(name='Administrative', description='Office and administrative work', color='#6c757d'),
        Category(name='Outreach', description='Community outreach programs', color='#17a2b8'),
        Category(name='Fundraising', description='Fundraising activities', color='#dc3545')
    ]
    
    for category in categories:
        db.session.add(category)
    
    # Create default roles
    roles = [
        Role(name='Volunteer', description='General volunteer role'),
        Role(name='Team Lead', description='Leading a team of volunteers'),
        Role(name='Coordinator', description='Coordinating activities'),
        Role(name='Trainer', description='Training other volunteers'),
        Role(name='Supervisor', description='Supervising activities')
    ]
    
    for role in roles:
        db.session.add(role)
    
    # Create default admin user with secure random password
    alphabet = string.ascii_letters + string.digits + string.punctuation
    admin_password = ''.join(secrets.choice(alphabet) for i in range(16))
    
    admin = User(
        username='admin',
        email='admin@hourslog.com',
        first_name='Admin',
        last_name='User',
        is_admin=True,
        email_verified=True
    )
    admin.set_password(admin_password)
    db.session.add(admin)
    
    # Create default app settings
    if not AppSettings.query.first():
        settings = AppSettings(
            allow_display_name_change=True,
            allow_password_reset=True,
            allow_profile_pic_change=True,
            leaderboard_size=50
        )
        db.session.add(settings)
    
    db.session.commit()
    print("Database initialized successfully!")
    print("=" * 60)
    print("IMPORTANT: Save these admin credentials securely!")
    print("=" * 60)
    print(f"Username: admin")
    print(f"Password: {admin_password}")
    print("=" * 60)
    print("This password will not be shown again. Please change it after first login!")


if __name__ == '__main__':
    import os
    # Only enable debug in development, never in production
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    app.run(debug=debug_mode, host='0.0.0.0', port=8080)
