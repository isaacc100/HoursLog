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
        # Service Delivery
        Category(
            name='Service Delivery',
            description='Providing service delivery such as first aid events, night-time economy, hospital volunteering, logistics and community advocacy',
            color='#007bff'
        ),

        # Community Service
        Category(
            name='Community Service',
            description='Participating in organised community activities such as visiting hospitals or care homes or supporting the elderly or disabled',
            color='#28a745'
        ),

        Category(
            name='Badger Support',
            description='Helping with Badgers as a Badger Helper',
            color='#28a745'
        ),

        # Event Planning & Support
        Category(
            name='Event Planning',
            description='Planning, delivering, or supporting internal competitions as an organiser, steward, or judge',
            color='#ffc107'
        ),

        Category(
            name='Cadet Events',
            description='Helping to organise events for other cadets and young people',
            color='#ffc107'
        ),

        # Training & Education
        Category(
            name='Training Delivery',
            description='Planning and delivering training inside or outside a unit, such as running courses or helping with Grand Prior subjects',
            color='#17a2b8'
        ),

        # Unit Support & Administration
        Category(
            name='Unit Support',
            description='Planning and delivering additional activities for a unit such as games, tuck-shops, or activity sessions',
            color='#6c757d'
        ),

        Category(
            name='Youth Representation',
            description='Representing young people through platforms such as Youth Forums or Regional Youth Team meetings',
            color='#6c757d'
        ),

        # Maintenance & Logistics
        Category(
            name='Maintenance & Cleaning',
            description='Involvement in cleaning or maintaining St John buildings or property',
            color='#795548'
        ),

        # Fundraising
        Category(
            name='Fundraising',
            description='Fundraising activities for St John Ambulance, the Order of St John, or St John Eye Hospital',
            color='#dc3545'
        ),

        # Ceremonial
        Category(
            name='Ceremonial Participation',
            description='Taking part in formal parades or acting as a lining (flag) party',
            color='#9c27b0'
        ),

        # Competitions
        Category(
            name='Competitions',
            description='Involvement or competition in external or inter-unit competitions',
            color='#3f51b5'
        ),

        # Event Representation
        Category(
            name='Public Representation',
            description='Involvement in external representation events outside of unit hours',
            color='#00bcd4'
        ),

        # Travel
        Category(
            name='Travel',
            description='Travel time to and from qualifying cadet volunteer activities',
            color='#8bc34a'
        )
    ]
    
    for category in categories:
        db.session.add(category)
    
    # Create default roles
    roles = [
        Role(name='Cadet Logistics Role', description='Any Cadet volunteering in logistics'),
        Role(name='Cadet Event Manager', description='Any Cadet volunteering in Event Management Roles such as Bronze Officer or Treatment Center Manager'),
        Role(name='Cadet Emergency Responder', description='Cadet Operational role for CER'),
        Role(name='Cadet Community First Aider', description='Cadet Operational role for CCFA'),
        Role(name='Cadet', description='Cadet Operational role for 10HrFA'),
        Role(name='Cadet of the Year Team', description='Any activities undertaken as a Cadet of the Year'),
        Role(name='Cadet Non-Commissioned Officer', description='Any activities undertaken as a Corporal, Sergeant, or Leading Cadet'),
        Role(name='Cadet Leadership Roles', description='Any other leadership roles, such as Youth Operations or St John Assembly Member')
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
        permission_level=7,
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


@app.cli.command('reset-db')
def reset_db():
    """Drop all tables and re-create them (works with SQLite and PostgreSQL)."""
    import click
    if not click.confirm(
        'This will DELETE all data in the database. Are you sure?',
        default=False,
    ):
        print('Aborted.')
        return

    db.drop_all()
    db.create_all()
    db.session.commit()
    print('All tables dropped and re-created.')
    print('Run "flask --app main init-db" to seed default data.')


if __name__ == '__main__':
    import os
    # Always use development config when running main.py directly
    os.environ.setdefault('FLASK_ENV', 'development')
    app.run(debug=True, host='0.0.0.0', port=8080)
