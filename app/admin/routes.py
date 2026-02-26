from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from functools import wraps
from app import db
from app.admin import bp
from app.models import User, LogEntry, Category, Role, AuditLog, AppSettings
from sqlalchemy import func
from datetime import datetime, timedelta


def admin_required(f):
    """Decorator to require admin privileges."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You need administrator privileges to access this page.', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function


@bp.route('/')
@login_required
@admin_required
def index():
    """Admin dashboard."""
    # Get statistics
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_logs = LogEntry.query.count()
    total_hours = db.session.query(func.sum(LogEntry.hours + LogEntry.travel_hours)).scalar() or 0
    total_activity_hours = db.session.query(func.sum(LogEntry.hours)).scalar() or 0
    total_travel_hours = db.session.query(func.sum(LogEntry.travel_hours)).scalar() or 0
    
    # Recent activity
    recent_logs = LogEntry.query.order_by(LogEntry.created_at.desc()).limit(10).all()
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    
    return render_template('admin/index.html',
                         title='Admin Dashboard',
                         total_users=total_users,
                         active_users=active_users,
                         total_logs=total_logs,
                         total_hours=total_hours,
                         total_activity_hours=total_activity_hours,
                         total_travel_hours=total_travel_hours,
                         recent_logs=recent_logs,
                         recent_users=recent_users)


@bp.route('/users')
@login_required
@admin_required
def users():
    """Manage users."""
    page = request.args.get('page', 1, type=int)
    users = User.query.order_by(User.created_at.desc())\
        .paginate(page=page, per_page=20, error_out=False)
    return render_template('admin/users.html', title='Manage Users', users=users)


@bp.route('/user/<int:id>/toggle_active', methods=['POST'])
@login_required
@admin_required
def toggle_user_active(id):
    """Toggle user active status."""
    user = User.query.get_or_404(id)
    
    if user.id == current_user.id:
        flash('You cannot deactivate your own account.', 'warning')
        return redirect(url_for('admin.users'))
    
    user.is_active = not user.is_active
    status = 'activated' if user.is_active else 'deactivated'
    
    # Log the action
    audit_log = AuditLog(
        user_id=current_user.id,
        action=f'user_{status}',
        details=f'User {user.username} was {status}',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()
    
    flash(f'User {user.username} has been {status}.', 'success')
    return redirect(url_for('admin.users'))


@bp.route('/user/<int:id>/toggle_admin', methods=['POST'])
@login_required
@admin_required
def toggle_user_admin(id):
    """Toggle user admin status."""
    user = User.query.get_or_404(id)
    
    if user.id == current_user.id:
        flash('You cannot modify your own admin status.', 'warning')
        return redirect(url_for('admin.users'))
    
    user.is_admin = not user.is_admin
    status = 'granted' if user.is_admin else 'revoked'
    
    # Log the action
    audit_log = AuditLog(
        user_id=current_user.id,
        action=f'admin_privileges_{status}',
        details=f'Admin privileges {status} for user {user.username}',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()
    
    flash(f'Admin privileges {status} for {user.username}.', 'success')
    return redirect(url_for('admin.users'))


@bp.route('/audit_logs')
@login_required
@admin_required
def audit_logs():
    """View audit logs."""
    page = request.args.get('page', 1, type=int)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc())\
        .paginate(page=page, per_page=50, error_out=False)
    return render_template('admin/audit_logs.html', title='Audit Logs', logs=logs)


@bp.route('/statistics')
@login_required
@admin_required
def statistics():
    """View detailed statistics."""
    # Hours by user (total = activity + travel)
    hours_by_user = db.session.query(
        User.username,
        func.sum(LogEntry.hours + LogEntry.travel_hours).label('total'),
        func.sum(LogEntry.hours).label('activity_only')
    ).join(LogEntry).group_by(User.username)\
        .order_by(func.sum(LogEntry.hours + LogEntry.travel_hours).desc()).limit(10).all()
    
    # Hours by category
    hours_by_category = db.session.query(
        Category.name,
        func.sum(LogEntry.hours + LogEntry.travel_hours).label('total')
    ).join(LogEntry).group_by(Category.name).all()
    
    # Hours by role
    hours_by_role = db.session.query(
        Role.name,
        func.sum(LogEntry.hours + LogEntry.travel_hours).label('total')
    ).join(LogEntry).group_by(Role.name).all()
    
    return render_template('admin/statistics.html',
                         title='Statistics',
                         hours_by_user=hours_by_user,
                         hours_by_category=hours_by_category,
                         hours_by_role=hours_by_role)


@bp.route('/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def settings():
    """Admin settings page for global application configuration."""
    app_settings = AppSettings.get_settings()
    
    if request.method == 'POST':
        app_settings.allow_display_name_change = 'allow_display_name_change' in request.form
        app_settings.allow_password_reset = 'allow_password_reset' in request.form
        app_settings.allow_profile_pic_change = 'allow_profile_pic_change' in request.form
        
        leaderboard_size = request.form.get('leaderboard_size', 50, type=int)
        app_settings.leaderboard_size = max(10, min(500, leaderboard_size))
        
        app_settings.footer_text = request.form.get('footer_text', '').strip()
        
        audit_log = AuditLog(
            user_id=current_user.id,
            action='settings_updated',
            details=f'Admin {current_user.username} updated application settings',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()
        
        flash('Settings updated successfully!', 'success')
        return redirect(url_for('admin.settings'))
    
    return render_template('admin/settings.html',
                         title='Admin Settings',
                         settings=app_settings)


# ── Category Management ───────────────────────────────────────────────────

@bp.route('/categories')
@login_required
@admin_required
def categories():
    """List all categories for admin management."""
    categories = Category.query.order_by(Category.name).all()
    return render_template('admin/categories.html',
                         title='Manage Categories',
                         categories=categories)


@bp.route('/categories/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_category():
    """Add a new category."""
    from app.main.forms import CategoryForm
    form = CategoryForm()

    if form.validate_on_submit():
        # Check for duplicate name (case-insensitive)
        existing = Category.query.filter(
            func.lower(Category.name) == func.lower(form.name.data)
        ).first()
        if existing:
            flash(f'A category named "{existing.name}" already exists.', 'warning')
            return render_template('admin/category_form.html',
                                 title='Add Category', form=form)

        category = Category(
            name=form.name.data.strip(),
            description=form.description.data.strip() if form.description.data else '',
            color=form.color.data
        )
        db.session.add(category)

        audit_log = AuditLog(
            user_id=current_user.id,
            action='category_created',
            details=f'Created category: {category.name}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()

        flash(f'Category "{category.name}" created successfully!', 'success')
        return redirect(url_for('admin.categories'))

    return render_template('admin/category_form.html',
                         title='Add Category', form=form)


@bp.route('/categories/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_category(id):
    """Edit an existing category."""
    from app.main.forms import CategoryForm
    category = Category.query.get_or_404(id)
    form = CategoryForm(obj=category)

    if form.validate_on_submit():
        # Check for duplicate name (case-insensitive), excluding self
        existing = Category.query.filter(
            func.lower(Category.name) == func.lower(form.name.data),
            Category.id != id
        ).first()
        if existing:
            flash(f'A category named "{existing.name}" already exists.', 'warning')
            return render_template('admin/category_form.html',
                                 title='Edit Category', form=form,
                                 category=category)

        category.name = form.name.data.strip()
        category.description = form.description.data.strip() if form.description.data else ''
        category.color = form.color.data

        audit_log = AuditLog(
            user_id=current_user.id,
            action='category_updated',
            details=f'Updated category: {category.name}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()

        flash(f'Category "{category.name}" updated successfully!', 'success')
        return redirect(url_for('admin.categories'))

    return render_template('admin/category_form.html',
                         title='Edit Category', form=form,
                         category=category)


@bp.route('/categories/<int:id>/toggle_active', methods=['POST'])
@login_required
@admin_required
def toggle_category_active(id):
    """Toggle category active status."""
    category = Category.query.get_or_404(id)
    category.is_active = not category.is_active
    status = 'activated' if category.is_active else 'deactivated'

    audit_log = AuditLog(
        user_id=current_user.id,
        action=f'category_{status}',
        details=f'Category "{category.name}" was {status}',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()

    flash(f'Category "{category.name}" has been {status}.', 'success')
    return redirect(url_for('admin.categories'))


# ── Role Management ───────────────────────────────────────────────────────

@bp.route('/roles')
@login_required
@admin_required
def roles():
    """List all roles for admin management."""
    roles = Role.query.order_by(Role.name).all()
    return render_template('admin/roles.html',
                         title='Manage Roles',
                         roles=roles)


@bp.route('/roles/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_role():
    """Add a new role."""
    from app.main.forms import RoleForm
    form = RoleForm()

    if form.validate_on_submit():
        # Check for duplicate name (case-insensitive)
        existing = Role.query.filter(
            func.lower(Role.name) == func.lower(form.name.data)
        ).first()
        if existing:
            flash(f'A role named "{existing.name}" already exists.', 'warning')
            return render_template('admin/role_form.html',
                                 title='Add Role', form=form)

        role = Role(
            name=form.name.data.strip(),
            description=form.description.data.strip() if form.description.data else ''
        )
        db.session.add(role)

        audit_log = AuditLog(
            user_id=current_user.id,
            action='role_created',
            details=f'Created role: {role.name}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()

        flash(f'Role "{role.name}" created successfully!', 'success')
        return redirect(url_for('admin.roles'))

    return render_template('admin/role_form.html',
                         title='Add Role', form=form)


@bp.route('/roles/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_role(id):
    """Edit an existing role."""
    from app.main.forms import RoleForm
    role = Role.query.get_or_404(id)
    form = RoleForm(obj=role)

    if form.validate_on_submit():
        # Check for duplicate name (case-insensitive), excluding self
        existing = Role.query.filter(
            func.lower(Role.name) == func.lower(form.name.data),
            Role.id != id
        ).first()
        if existing:
            flash(f'A role named "{existing.name}" already exists.', 'warning')
            return render_template('admin/role_form.html',
                                 title='Edit Role', form=form,
                                 role=role)

        role.name = form.name.data.strip()
        role.description = form.description.data.strip() if form.description.data else ''

        audit_log = AuditLog(
            user_id=current_user.id,
            action='role_updated',
            details=f'Updated role: {role.name}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()

        flash(f'Role "{role.name}" updated successfully!', 'success')
        return redirect(url_for('admin.roles'))

    return render_template('admin/role_form.html',
                         title='Edit Role', form=form,
                         role=role)


@bp.route('/user/<int:id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(id):
    """Permanently delete a user and all associated data."""
    user = User.query.get_or_404(id)

    # Prevent self-deletion through admin panel (use profile page instead)
    if user.id == current_user.id:
        flash('To delete your own account, use the option on your Profile page.', 'warning')
        return redirect(url_for('admin.users'))

    # Prevent deleting the last admin
    if user.is_admin:
        admin_count = User.query.filter_by(is_admin=True, is_active=True).count()
        if admin_count <= 1:
            flash('Cannot delete the only remaining administrator.', 'danger')
            return redirect(url_for('admin.users'))

    confirmation = request.form.get('confirmation', '').strip()
    if confirmation != 'I want to delete my data':
        flash('Deletion failed. The confirmation phrase was not entered correctly.', 'danger')
        return redirect(url_for('admin.users'))

    username = user.username

    # Remove avatar file if present
    import os
    from flask import current_app
    if user.profile_pic:
        upload_folder = current_app.config['UPLOAD_FOLDER']
        pic_path = os.path.join(upload_folder, user.profile_pic)
        if os.path.exists(pic_path):
            os.remove(pic_path)

    # Clear secondary-role associations for this user's log entries
    from app.models import log_entry_secondary_roles
    entry_ids = [e.id for e in user.log_entries.all()]
    if entry_ids:
        db.session.execute(
            log_entry_secondary_roles.delete().where(
                log_entry_secondary_roles.c.log_entry_id.in_(entry_ids)
            )
        )

    # Audit log (record before deleting so we keep a trace)
    audit_log = AuditLog(
        user_id=current_user.id,
        action='user_deleted',
        details=f'Admin {current_user.username} permanently deleted user "{username}" (id={id})',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)

    db.session.delete(user)
    db.session.commit()

    flash(f'User "{username}" and all associated data have been permanently deleted.', 'success')
    return redirect(url_for('admin.users'))


@bp.route('/roles/<int:id>/toggle_active', methods=['POST'])
@login_required
@admin_required
def toggle_role_active(id):
    """Toggle role active status."""
    role = Role.query.get_or_404(id)
    role.is_active = not role.is_active
    status = 'activated' if role.is_active else 'deactivated'

    audit_log = AuditLog(
        user_id=current_user.id,
        action=f'role_{status}',
        details=f'Role "{role.name}" was {status}',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()

    flash(f'Role "{role.name}" has been {status}.', 'success')
    return redirect(url_for('admin.roles'))
