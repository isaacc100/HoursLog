from flask import render_template, redirect, url_for, flash, request, jsonify, current_app, Response, make_response
from flask_login import login_required, current_user
from app import db, bcrypt
from app.main import bp
from app.main.forms import LogEntryForm, CategoryForm, RoleForm, ProfileForm, ChangePasswordForm
from app.models import LogEntry, Category, Role, AuditLog, User, AppSettings
from app.export import (
    resolve_date_range, query_entries, compute_summary,
    generate_category_chart_b64, generate_role_chart_b64,
    generate_csv, generate_pdf,
)
from sqlalchemy import func
from datetime import datetime, timedelta, date
from werkzeug.utils import secure_filename
import os
import time


def populate_log_form_choices(form):
    """Helper function to populate select field choices for log entry form."""
    active_roles = Role.query.filter_by(is_active=True).all()
    form.category_id.choices = [(c.id, c.name) for c in Category.query.filter_by(is_active=True).all()]
    form.role_id.choices = [(r.id, r.name) for r in active_roles]
    form.secondary_role_ids.choices = [(r.id, r.name) for r in active_roles]


@bp.route('/')
@bp.route('/index')
def index():
    """Home page route."""
    return render_template('main/index.html', title='Home')


@bp.route('/dashboard')
@login_required
def dashboard():
    """User dashboard with overview, statistics, and leaderboard."""
    # Get user's log entries
    page = request.args.get('page', 1, type=int)
    entries = LogEntry.query.filter_by(user_id=current_user.id)\
        .order_by(LogEntry.date.desc())\
        .paginate(page=page, per_page=10, error_out=False)
    
    # Calculate statistics - activity hours only
    total_activity_hours = db.session.query(func.sum(LogEntry.hours))\
        .filter_by(user_id=current_user.id).scalar() or 0
    
    # Travel hours
    total_travel_hours = db.session.query(func.sum(LogEntry.travel_hours))\
        .filter_by(user_id=current_user.id).scalar() or 0
    
    # Total = activity + travel
    total_hours = total_activity_hours + total_travel_hours
    
    total_entries = LogEntry.query.filter_by(user_id=current_user.id).count()
    
    # Hours by category (total = activity + travel)
    hours_by_category = db.session.query(
        Category.name,
        func.sum(LogEntry.hours + LogEntry.travel_hours).label('total')
    ).join(LogEntry).filter(LogEntry.user_id == current_user.id)\
        .group_by(Category.name).all()
    
    # Hours by role (total = activity + travel)
    hours_by_role = db.session.query(
        Role.name,
        func.sum(LogEntry.hours + LogEntry.travel_hours).label('total')
    ).join(LogEntry).filter(LogEntry.user_id == current_user.id)\
        .group_by(Role.name).all()
    
    # === Leaderboard ===
    settings = AppSettings.get_settings()
    leaderboard_period = request.args.get('leaderboard_period', 'all')
    
    # Build date filter for leaderboard
    date_filter = None
    today = date.today()
    if leaderboard_period == 'week':
        date_filter = today - timedelta(days=today.weekday())  # Monday of this week
    elif leaderboard_period == 'month':
        date_filter = today.replace(day=1)
    elif leaderboard_period == 'year':
        date_filter = today.replace(month=1, day=1)
    
    # Query leaderboard data
    leaderboard_query = db.session.query(
        User.id,
        User.username,
        User.display_name,
        User.first_name,
        User.last_name,
        func.sum(LogEntry.hours + LogEntry.travel_hours).label('total_hours')
    ).join(LogEntry, User.id == LogEntry.user_id)\
        .filter(User.is_active == True)
    
    if date_filter:
        leaderboard_query = leaderboard_query.filter(LogEntry.date >= date_filter)
    
    leaderboard_query = leaderboard_query.group_by(User.id, User.username, User.display_name, User.first_name, User.last_name)\
        .order_by(func.sum(LogEntry.hours + LogEntry.travel_hours).desc())
    
    # Get full list for rank calculation, then limit for display
    all_ranked = leaderboard_query.all()
    
    # Find current user's rank
    user_rank = None
    for idx, row in enumerate(all_ranked, 1):
        if row.id == current_user.id:
            user_rank = idx
            break
    
    leaderboard = all_ranked[:settings.leaderboard_size]
    
    # For admin: list of all users for export user-picker
    all_users = []
    if current_user.is_admin:
        all_users = User.query.filter(User.id != current_user.id, User.is_active == True)\
            .order_by(User.username).all()
    
    return render_template('main/dashboard.html',
                         title='Dashboard',
                         entries=entries,
                         total_hours=total_hours,
                         total_activity_hours=total_activity_hours,
                         total_travel_hours=total_travel_hours,
                         total_entries=total_entries,
                         hours_by_category=hours_by_category,
                         hours_by_role=hours_by_role,
                         leaderboard=leaderboard,
                         user_rank=user_rank,
                         leaderboard_period=leaderboard_period,
                         all_users=all_users)


@bp.route('/log/new', methods=['GET', 'POST'])
@login_required
def new_log():
    """Create a new log entry."""
    form = LogEntryForm()
    
    # Populate choices for select fields
    populate_log_form_choices(form)
    
    if form.validate_on_submit():
        entry = LogEntry(
            user_id=current_user.id,
            title=form.title.data,
            description=form.description.data,
            notes=form.notes.data,
            hours=form.hours.data,
            travel_hours=form.travel_hours.data or 0.0,
            date=form.date.data,
            category_id=form.category_id.data,
            role_id=form.role_id.data
        )
        
        # Set secondary roles
        if form.secondary_role_ids.data:
            secondary = Role.query.filter(Role.id.in_(form.secondary_role_ids.data)).all()
            entry.secondary_roles = secondary
        
        db.session.add(entry)
        
        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            action='log_entry_created',
            details=f'Created log entry: {entry.title} ({entry.hours}h activity + {entry.travel_hours}h travel)',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()
        
        flash('Log entry created successfully!', 'success')
        return redirect(url_for('main.dashboard'))
    
    return render_template('main/log_form.html', title='New Log Entry', form=form)


@bp.route('/log/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_log(id):
    """Edit an existing log entry."""
    entry = LogEntry.query.get_or_404(id)
    
    # Check if user owns this entry
    if entry.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to edit this entry.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    form = LogEntryForm(obj=entry)
    
    # Populate choices for select fields
    populate_log_form_choices(form)
    
    if form.validate_on_submit():
        entry.title = form.title.data
        entry.description = form.description.data
        entry.notes = form.notes.data
        entry.hours = form.hours.data
        entry.travel_hours = form.travel_hours.data or 0.0
        entry.date = form.date.data
        entry.category_id = form.category_id.data
        entry.role_id = form.role_id.data
        
        # Update secondary roles
        if form.secondary_role_ids.data:
            secondary = Role.query.filter(Role.id.in_(form.secondary_role_ids.data)).all()
            entry.secondary_roles = secondary
        else:
            entry.secondary_roles = []
        
        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            action='log_entry_updated',
            details=f'Updated log entry: {entry.title}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()
        
        flash('Log entry updated successfully!', 'success')
        return redirect(url_for('main.dashboard'))
    elif request.method == 'GET':
        # Pre-select secondary roles
        form.secondary_role_ids.data = [r.id for r in entry.secondary_roles]
    
    return render_template('main/log_form.html', title='Edit Log Entry', form=form, entry=entry)


@bp.route('/log/<int:id>/delete', methods=['POST'])
@login_required
def delete_log(id):
    """Delete a log entry."""
    entry = LogEntry.query.get_or_404(id)
    
    # Check if user owns this entry
    if entry.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to delete this entry.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    title = entry.title
    db.session.delete(entry)
    
    # Log the action
    audit_log = AuditLog(
        user_id=current_user.id,
        action='log_entry_deleted',
        details=f'Deleted log entry: {title}',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()
    
    flash('Log entry deleted successfully!', 'success')
    return redirect(url_for('main.dashboard'))


@bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile management page."""
    settings = AppSettings.get_settings()
    profile_form = ProfileForm()
    password_form = ChangePasswordForm()
    
    if request.method == 'POST':
        # Determine which form was submitted
        if 'submit_password' in request.form:
            # Password change form
            if not settings.allow_password_reset:
                flash('Password changes are currently disabled by an administrator.', 'warning')
                return redirect(url_for('main.profile'))
            
            if password_form.validate_on_submit():
                if not current_user.check_password(password_form.current_password.data):
                    flash('Current password is incorrect.', 'danger')
                    return redirect(url_for('main.profile'))
                
                current_user.set_password(password_form.new_password.data)
                
                audit_log = AuditLog(
                    user_id=current_user.id,
                    action='password_changed',
                    details=f'User {current_user.username} changed their password',
                    ip_address=request.remote_addr
                )
                db.session.add(audit_log)
                db.session.commit()
                flash('Password changed successfully!', 'success')
                return redirect(url_for('main.profile'))
        else:
            # Profile update form
            if profile_form.validate_on_submit():
                changes = []
                
                # Display name
                if settings.allow_display_name_change:
                    new_name = profile_form.display_name.data
                    if new_name != current_user.display_name:
                        current_user.display_name = new_name
                        changes.append('display name')
                
                # Profile picture
                if settings.allow_profile_pic_change and profile_form.profile_pic.data:
                    file = profile_form.profile_pic.data
                    if file.filename:
                        filename = secure_filename(file.filename)
                        ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'png'
                        new_filename = f"{current_user.id}_{int(time.time())}.{ext}"
                        upload_folder = current_app.config['UPLOAD_FOLDER']
                        filepath = os.path.join(upload_folder, new_filename)
                        
                        # Delete old profile pic if exists
                        if current_user.profile_pic:
                            old_path = os.path.join(upload_folder, current_user.profile_pic)
                            if os.path.exists(old_path):
                                os.remove(old_path)
                        
                        file.save(filepath)
                        current_user.profile_pic = new_filename
                        changes.append('profile picture')
                
                if changes:
                    audit_log = AuditLog(
                        user_id=current_user.id,
                        action='profile_updated',
                        details=f'User {current_user.username} updated: {", ".join(changes)}',
                        ip_address=request.remote_addr
                    )
                    db.session.add(audit_log)
                    db.session.commit()
                    flash('Profile updated successfully!', 'success')
                else:
                    flash('No changes were made.', 'info')
                return redirect(url_for('main.profile'))
    
    # Pre-fill form with current data
    if request.method == 'GET':
        profile_form.display_name.data = current_user.display_name
    
    return render_template('main/profile.html',
                         title='Profile',
                         profile_form=profile_form,
                         password_form=password_form,
                         settings=settings)


@bp.route('/profile/remove-pic', methods=['POST'])
@login_required
def remove_profile_pic():
    """Remove user's profile picture."""
    settings = AppSettings.get_settings()
    if not settings.allow_profile_pic_change:
        flash('Profile picture changes are currently disabled.', 'warning')
        return redirect(url_for('main.profile'))
    
    if current_user.profile_pic:
        upload_folder = current_app.config['UPLOAD_FOLDER']
        old_path = os.path.join(upload_folder, current_user.profile_pic)
        if os.path.exists(old_path):
            os.remove(old_path)
        current_user.profile_pic = None
        
        audit_log = AuditLog(
            user_id=current_user.id,
            action='profile_pic_removed',
            details=f'User {current_user.username} removed their profile picture',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()
        flash('Profile picture removed.', 'success')
    
    return redirect(url_for('main.profile'))


@bp.route('/categories')
@login_required
def categories():
    """View all categories."""
    categories = Category.query.filter_by(is_active=True).order_by(Category.name).all()
    return render_template('main/categories.html', title='Categories', categories=categories)


@bp.route('/roles')
@login_required
def roles():
    """View all roles."""
    roles = Role.query.filter_by(is_active=True).order_by(Role.name).all()
    return render_template('main/roles.html', title='Roles', roles=roles)


# ── Export routes ──────────────────────────────────────────────────────────

def _export_target_user():
    """Return the User whose data should be exported.

    Admins may pass ?user_id=<id>; everyone else always gets their own.
    """
    user_id = request.args.get('user_id', type=int)
    if user_id and current_user.is_admin and user_id != current_user.id:
        target = User.query.get(user_id)
        if target:
            return target
    return current_user


PERIOD_LABELS = {
    'all': 'All Time',
    'week': 'This Week',
    'month': 'This Month',
    'year': 'This Year',
    'custom': 'Custom Range',
}


@bp.route('/export/pdf')
@login_required
def export_pdf():
    """Generate and download a PDF report."""
    target = _export_target_user()
    period = request.args.get('period', 'all')
    start_str = request.args.get('start')
    end_str = request.args.get('end')

    start_date, end_date = resolve_date_range(period, start_str, end_str)
    entries = query_entries(target.id, start_date, end_date)
    summary = compute_summary(entries)

    category_chart = generate_category_chart_b64(summary)
    role_chart = generate_role_chart_b64(summary)

    html = render_template(
        'main/export_pdf.html',
        user_name=target.get_display_name,
        period_label=PERIOD_LABELS.get(period, period),
        start_date=start_date,
        end_date=end_date,
        summary=summary,
        entries=entries,
        category_chart=category_chart,
        role_chart=role_chart,
    )

    pdf_bytes = generate_pdf(html)
    if pdf_bytes is None:
        flash('PDF generation is unavailable — WeasyPrint is not installed.', 'danger')
        return redirect(url_for('main.dashboard'))

    filename = f"hourslog_{target.username}_{period}.pdf"
    response = make_response(pdf_bytes)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


@bp.route('/export/csv')
@login_required
def export_csv():
    """Generate and download a CSV report."""
    target = _export_target_user()
    period = request.args.get('period', 'all')
    start_str = request.args.get('start')
    end_str = request.args.get('end')

    start_date, end_date = resolve_date_range(period, start_str, end_str)
    entries = query_entries(target.id, start_date, end_date)
    csv_content = generate_csv(entries, target.get_display_name)

    filename = f"hourslog_{target.username}_{period}.csv"
    response = make_response(csv_content)
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response
