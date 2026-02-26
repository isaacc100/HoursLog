from flask import render_template, redirect, url_for, flash, request, current_app, session
from flask_login import login_user, logout_user, current_user
from app import db, bcrypt
from app.auth import bp
from app.auth.forms import LoginForm, RegistrationForm
from app.models import User, AuditLog
from datetime import datetime
import secrets
import requests


@bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash('Your account has been deactivated. Please contact an administrator.', 'danger')
                return redirect(url_for('auth.login'))
            
            login_user(user, remember=form.remember_me.data)
            user.last_login = datetime.utcnow()
            
            # Log the login action
            audit_log = AuditLog(
                user_id=user.id,
                action='login',
                details=f'User {user.username} logged in',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()
            
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('main.index')
            
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(next_page)
        else:
            flash('Invalid username or password. Please try again.', 'danger')
    
    return render_template('auth/login.html', title='Sign In', form=form)


@bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Require agreement acceptance
        if request.form.get('agreement_accepted') != 'true':
            flash('You must accept the data collection agreement to create an account.', 'danger')
            return render_template('auth/register.html', title='Register', form=form)

        user = User(
            username=form.username.data,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        # Log the registration
        audit_log = AuditLog(
            user_id=user.id,
            action='registration',
            details=f'New user registered: {user.username}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()
        
        flash('Congratulations! Your account has been created. You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html', title='Register', form=form)


@bp.route('/logout')
def logout():
    """User logout route."""
    if current_user.is_authenticated:
        # Log the logout action
        audit_log = AuditLog(
            user_id=current_user.id,
            action='logout',
            details=f'User {current_user.username} logged out',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()
        
        logout_user()
        flash('You have been logged out successfully.', 'info')
    
    return redirect(url_for('main.index'))


# ── Helper: find-or-create user from SSO profile ──────────────────────────
def _sso_login_or_register(email, first_name, last_name, provider):
    """Handle SSO callback: find existing user by email or auto-register."""
    user = User.query.filter_by(email=email).first()
    if user and not user.is_active:
        flash('Your account has been deactivated. Please contact an administrator.', 'danger')
        return redirect(url_for('auth.login'))

    if not user:
        # New SSO user – store data in session and redirect to agreement page
        session['pending_sso'] = {
            'email': email,
            'first_name': first_name or '',
            'last_name': last_name or '',
            'provider': provider,
        }
        return redirect(url_for('auth.sso_agreement'))

    login_user(user, remember=True)
    user.last_login = datetime.utcnow()

    audit_log = AuditLog(
        user_id=user.id,
        action='sso_login',
        details=f'User {user.username} logged in via {provider}',
        ip_address=request.remote_addr,
    )
    db.session.add(audit_log)
    db.session.commit()

    flash(f'Welcome, {user.get_display_name}!', 'success')
    return redirect(url_for('main.index'))


# ── SSO Data Agreement ─────────────────────────────────────────────────────
@bp.route('/agreement', methods=['GET', 'POST'])
def sso_agreement():
    """Show data collection agreement for new SSO users."""
    pending = session.get('pending_sso')
    if not pending:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'accept':
            email = pending['email']
            first_name = pending['first_name']
            last_name = pending['last_name']
            provider = pending['provider']
            session.pop('pending_sso', None)

            # Create the user account
            base_username = email.split('@')[0]
            username = base_username
            counter = 1
            while User.query.filter_by(username=username).first():
                username = f"{base_username}{counter}"
                counter += 1

            user = User(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                email_verified=True,
            )
            user.password_hash = bcrypt.generate_password_hash(secrets.token_hex(32)).decode('utf-8')
            db.session.add(user)
            db.session.commit()

            audit_log = AuditLog(
                user_id=user.id,
                action='sso_registration',
                details=f'New user registered via {provider} SSO: {user.username}',
                ip_address=request.remote_addr,
            )
            db.session.add(audit_log)
            db.session.commit()

            login_user(user, remember=True)
            user.last_login = datetime.utcnow()

            audit_log = AuditLog(
                user_id=user.id,
                action='sso_login',
                details=f'User {user.username} logged in via {provider}',
                ip_address=request.remote_addr,
            )
            db.session.add(audit_log)
            db.session.commit()

            flash(f'Welcome, {user.get_display_name}!', 'success')
            return redirect(url_for('main.index'))
        else:
            # Deny
            session.pop('pending_sso', None)
            flash('Account was not created. No data has been stored.', 'info')
            return redirect(url_for('auth.login'))

    return render_template('auth/agreement.html', title='Data Agreement')


# ── Google SSO ─────────────────────────────────────────────────────────────
GOOGLE_DISCOVERY_URL = 'https://accounts.google.com/.well-known/openid-configuration'


@bp.route('/login/google')
def google_login():
    """Redirect to Google OAuth consent screen."""
    cfg = current_app.config
    if not (cfg.get('GOOGLE_CLIENT_ID') and cfg.get('GOOGLE_CLIENT_SECRET')):
        flash('Sorry, Google sign-in is not available.', 'warning')
        return redirect(url_for('auth.login'))

    try:
        discovery = requests.get(GOOGLE_DISCOVERY_URL, timeout=5).json()
    except Exception:
        flash('Unable to reach Google. Please try again later.', 'danger')
        return redirect(url_for('auth.login'))

    authorization_endpoint = discovery['authorization_endpoint']

    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state

    redirect_uri = url_for('auth.google_callback', _external=True)
    params = {
        'client_id': cfg['GOOGLE_CLIENT_ID'],
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state,
    }
    query_string = '&'.join(f'{k}={requests.utils.quote(str(v))}' for k, v in params.items())
    return redirect(f'{authorization_endpoint}?{query_string}')


@bp.route('/callback/google')
def google_callback():
    """Handle Google OAuth callback."""
    cfg = current_app.config
    if request.args.get('state') != session.pop('oauth_state', None):
        flash('Invalid OAuth state. Please try again.', 'danger')
        return redirect(url_for('auth.login'))

    code = request.args.get('code')
    if not code:
        flash('Google sign-in was cancelled.', 'info')
        return redirect(url_for('auth.login'))

    try:
        discovery = requests.get(GOOGLE_DISCOVERY_URL, timeout=5).json()
        token_endpoint = discovery['token_endpoint']
        userinfo_endpoint = discovery['userinfo_endpoint']

        token_resp = requests.post(token_endpoint, data={
            'code': code,
            'client_id': cfg['GOOGLE_CLIENT_ID'],
            'client_secret': cfg['GOOGLE_CLIENT_SECRET'],
            'redirect_uri': url_for('auth.google_callback', _external=True),
            'grant_type': 'authorization_code',
        }, timeout=10)
        token_resp.raise_for_status()
        tokens = token_resp.json()

        userinfo_resp = requests.get(userinfo_endpoint, headers={
            'Authorization': f'Bearer {tokens["access_token"]}'
        }, timeout=10)
        userinfo_resp.raise_for_status()
        userinfo = userinfo_resp.json()
    except Exception:
        flash('Error communicating with Google. Please try again.', 'danger')
        return redirect(url_for('auth.login'))

    email = userinfo.get('email')
    if not email:
        flash('Could not retrieve your email from Google.', 'danger')
        return redirect(url_for('auth.login'))

    return _sso_login_or_register(
        email=email,
        first_name=userinfo.get('given_name', ''),
        last_name=userinfo.get('family_name', ''),
        provider='Google',
    )


# ── Microsoft Azure AD SSO ────────────────────────────────────────────────
@bp.route('/login/azure')
def azure_login():
    """Redirect to Microsoft Azure AD OAuth consent screen."""
    cfg = current_app.config
    if not (cfg.get('AZURE_CLIENT_ID') and cfg.get('AZURE_CLIENT_SECRET')):
        flash('Sorry, Microsoft sign-in is not available.', 'warning')
        return redirect(url_for('auth.login'))

    tenant = cfg.get('AZURE_TENANT_ID', 'common')
    authorization_endpoint = f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize'

    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state

    redirect_uri = url_for('auth.azure_callback', _external=True)
    params = {
        'client_id': cfg['AZURE_CLIENT_ID'],
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'openid email profile User.Read',
        'state': state,
        'response_mode': 'query',
    }
    query_string = '&'.join(f'{k}={requests.utils.quote(str(v))}' for k, v in params.items())
    return redirect(f'{authorization_endpoint}?{query_string}')


@bp.route('/callback/azure')
def azure_callback():
    """Handle Microsoft Azure AD OAuth callback."""
    cfg = current_app.config
    if request.args.get('state') != session.pop('oauth_state', None):
        flash('Invalid OAuth state. Please try again.', 'danger')
        return redirect(url_for('auth.login'))

    code = request.args.get('code')
    if not code:
        flash('Microsoft sign-in was cancelled.', 'info')
        return redirect(url_for('auth.login'))

    tenant = cfg.get('AZURE_TENANT_ID', 'common')
    token_endpoint = f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token'

    try:
        token_resp = requests.post(token_endpoint, data={
            'code': code,
            'client_id': cfg['AZURE_CLIENT_ID'],
            'client_secret': cfg['AZURE_CLIENT_SECRET'],
            'redirect_uri': url_for('auth.azure_callback', _external=True),
            'grant_type': 'authorization_code',
            'scope': 'openid email profile User.Read',
        }, timeout=10)
        token_resp.raise_for_status()
        tokens = token_resp.json()

        graph_resp = requests.get('https://graph.microsoft.com/v1.0/me', headers={
            'Authorization': f'Bearer {tokens["access_token"]}'
        }, timeout=10)
        graph_resp.raise_for_status()
        profile = graph_resp.json()
    except Exception:
        flash('Error communicating with Microsoft. Please try again.', 'danger')
        return redirect(url_for('auth.login'))

    email = profile.get('mail') or profile.get('userPrincipalName')
    if not email:
        flash('Could not retrieve your email from Microsoft.', 'danger')
        return redirect(url_for('auth.login'))

    return _sso_login_or_register(
        email=email,
        first_name=profile.get('givenName', ''),
        last_name=profile.get('surname', ''),
        provider='Microsoft',
    )
