# HoursLog (CadetHours) — v0.2.0

A Flask web application for tracking volunteer hours with user authentication, dashboards, leaderboards, and an admin portal.

## Features

### User Features
- **User Authentication**: Secure login/signup with password hashing
- **Single Sign-On (SSO)**: Optional Google and Microsoft Azure AD login/signup buttons (configurable via environment variables; shows a friendly "unavailable" message when not configured)
- **Log Volunteer Hours**: Track activity hours and travel hours separately (total includes travel)
- **Notes**: Add notes to each log entry
- **Roles**: Primary role + optional secondary roles (multi-select) per entry
- **Dashboard**: View personal totals (including/excluding travel), charts, and recent entries
- **Leaderboard**: Top contributors list (size controlled by admin) with period filter (week/month/year/all-time) and your current rank
- **Data Visualization**: Interactive charts showing hours by category and role
- **Export (PDF & CSV)**: Download a PDF report (overview page with charts + full entry listing) or CSV file. Supports preset time periods (All Time, This Week, This Month, This Year) and custom date ranges. Admins can export any user's data.
- **Responsive Design**: Mobile-friendly interface with Bootstrap 5
- **Dark Mode Support**: CSS media queries for dark mode preference
- **Profile Management**: Change display name, upload/remove profile picture, and change password (if enabled by admin)

### Admin Features
- **Admin Dashboard**: Overview of all users and activities
- **User Management**: Activate/deactivate users, grant/revoke admin privileges
- **Admin Settings**: Globally allow/deny profile edits (name/picture/password), set leaderboard size, and customise footer text
- **Statistics**: View system-wide statistics and top contributors (includes travel-aware totals)
- **Audit Logs**: Track all user and admin actions
- **Activity Management**: Monitor all log entries across the system

## Technology Stack

- **Backend**: Flask 3.1.2, SQLAlchemy
- **Database**: SQLite (default, configurable)
- **Authentication**: Flask-Login, Flask-Bcrypt, Google & Azure AD OAuth (optional)
- **Forms**: Flask-WTF, WTForms
- **Frontend**: Bootstrap 5, Chart.js
- **PDF Export**: xhtml2pdf, matplotlib (server-side chart rendering)
- **Email**: Flask-Mail (configured for future use)

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd HoursLog
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   ```

   (If you already use `.venv` in your environment, that works too — just adjust paths accordingly.)

3. **Activate the virtual environment**
   - On Windows:
     ```bash
venv\Scripts\activate
     ```
   - On macOS/Linux:
     ```bash
source venv/bin/activate
     ```

4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **Initialize the database**
   ```bash
   flask --app main init-db
   ```
   
   This creates:
   - Default categories (Tutoring, Food Service, Event Planning, etc.)
   - Default roles (Volunteer, Team Lead, Coordinator, etc.)
   - Admin user with a secure random password (displayed once)
   - Default application settings (leaderboard size and profile permissions)
   
   **⚠️ Important**: Save the generated admin credentials securely! The password will only be displayed once.

6. **Run the application**
   ```bash
   python main.py
   ```
   
   Or using Flask CLI:
   ```bash
   flask --app main run --debug
   ```

7. **Access the application**
   - Open your browser and navigate to: `http://localhost:5000`
   - Login with the admin credentials shown during database initialization

## Usage

### For Regular Users

1. **Register**: Create a new account at `/auth/register`
2. **Login**: Sign in at `/auth/login`
3. **Create Log Entry**: Click "New Entry" to log volunteer hours
4. **View Dashboard**: See totals (including/excluding travel), charts, leaderboard, and recent entries
5. **Explore**: Browse categories and roles
6. **Profile**: Manage display name, profile picture, and password at `/profile` (if enabled by admin)

### For Administrators

1. **Access Admin Panel**: Click "Admin" in the navigation
2. **Manage Users**: View all users, activate/deactivate accounts, grant admin privileges
3. **View Statistics**: See system-wide statistics and top contributors
4. **Audit Logs**: Track all actions in the system
5. **Settings**: Configure global permissions and leaderboard size at `/admin/settings`

## Configuration

Create a `.env` file in the root directory for custom configuration:

```env
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///hourslog.db
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-email-password
MAIL_DEFAULT_SENDER=noreply@hourslog.com

# Footer (optional — can also be set in Admin Settings)
FOOTER_TEXT=© 2026 HoursLog. A volunteer hours tracking application.

# Google SSO (leave unset to disable)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Microsoft Azure AD SSO (leave unset to disable)
AZURE_CLIENT_ID=your-azure-client-id
AZURE_CLIENT_SECRET=your-azure-client-secret
AZURE_TENANT_ID=common
```

Additional settings are defined in `config.py`:

- `UPLOAD_FOLDER` (default: `app/static/uploads/avatars`) for profile pictures
- `MAX_CONTENT_LENGTH` (default: 2MB)
- `ALLOWED_EXTENSIONS` (default: png/jpg/jpeg/gif/webp)

## Project Structure

```
HoursLog/
├── app/
│   ├── __init__.py          # Application factory + context processors
│   ├── models.py            # Database models
│   ├── export.py            # PDF/CSV export helpers & chart generation
│   ├── static/
│   │   └── uploads/
│   │       └── avatars/      # Uploaded profile pictures
│   ├── auth/                # Authentication blueprint (incl. SSO)
│   │   ├── __init__.py
│   │   ├── routes.py
│   │   └── forms.py
│   ├── main/                # Main application blueprint
│   │   ├── __init__.py
│   │   ├── routes.py
│   │   └── forms.py
│   ├── admin/               # Admin blueprint
│   │   ├── __init__.py
│   │   └── routes.py
│   └── templates/           # HTML templates
│       ├── base.html
│       ├── auth/
│       ├── main/
│       │   └── export_pdf.html  # PDF report template
│       └── admin/
├── config.py                # Configuration
├── main.py                  # Application entry point
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Database Schema

### User
- User authentication and profile information
- Fields: username, email, password_hash, first_name, last_name, display_name, profile_pic, is_admin, is_active

### LogEntry
- Volunteer hours tracking
- Fields: title, description, notes, hours (activity), travel_hours, date, category, primary role
- Foreign keys: user_id, category_id, role_id
- Many-to-many: secondary roles (optional)

### AppSettings
- Global application settings (singleton row)
- Fields: leaderboard_size, allow_display_name_change, allow_password_reset, allow_profile_pic_change, footer_text

### Category
- Categorize volunteer activities
- Fields: name, description, color

### Role
- Volunteer roles
- Fields: name, description

### AuditLog
- Track all system actions
- Fields: user_id, action, details, ip_address, timestamp

## Security Features

- **Password Hashing**: Bcrypt for secure password storage
- **Session Management**: Secure cookie configuration
- **CSRF Protection**: Flask-WTF CSRF tokens on all forms
- **SQL Injection Protection**: SQLAlchemy ORM
- **Audit Logging**: Track all user and admin actions

## Development

### Run in Debug Mode
```bash
python main.py
```

### Access Flask Shell
```bash
flask --app main shell
```

### Database Commands
```bash
# Initialize database with default data
flask --app main init-db

# Access Python shell with database context
flask --app main shell
```

## Future Enhancements

- Email verification for new users
- Password reset functionality via email (Flask-Mail is configured but not wired up)
- PWA configuration for mobile app experience
- Database backup and restore functionality
- Advanced filtering and search
- Multi-language support
- API endpoints for mobile apps

## License

This project is for educational and volunteer organization use.

## Support

For issues, questions, or contributions, please open an issue on the repository.

