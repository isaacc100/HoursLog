from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from functools import wraps
from app import db
from app.admin import bp
from app.models import (
    User, LogEntry, Category, Role, AuditLog, AppSettings,
    PermissionLevelConfig, ALL_PERMISSIONS, PERMISSION_LEVEL_NAMES,
)
from sqlalchemy import func
from datetime import datetime, timedelta


# ── Permission decorators ─────────────────────────────────────────────────

def permission_required(permission):
    """Decorator: require that current_user.can(permission) is True."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or not current_user.can(permission):
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('main.index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def any_admin_required(f):
    """Decorator: require that user has at least one admin permission."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.has_any_admin_permission():
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function


def level7_required(f):
    """Decorator: require full admin (level 7)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.permission_level != 7:
            flash('You need full administrator privileges to access this page.', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function


# Keep backward compat alias
admin_required = level7_required


# ── Admin Dashboard ───────────────────────────────────────────────────────

@bp.route('/')
@login_required
@any_admin_required
def index():
    """Admin dashboard."""
    total_users = User.query.count()
    active_users = User.query.filter(User.permission_level > 0).count()
    total_logs = LogEntry.query.count()
    total_hours = db.session.query(func.sum(LogEntry.hours + LogEntry.travel_hours)).scalar() or 0
    total_activity_hours = db.session.query(func.sum(LogEntry.hours)).scalar() or 0
    total_travel_hours = db.session.query(func.sum(LogEntry.travel_hours)).scalar() or 0

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


# ── User Management ──────────────────────────────────────────────────────

@bp.route('/users')
@login_required
@permission_required('can_manage_users')
def users():
    """Manage users."""
    page = request.args.get('page', 1, type=int)
    users = User.query.order_by(User.created_at.desc())\
        .paginate(page=page, per_page=20, error_out=False)
    return render_template('admin/users.html', title='Manage Users', users=users)


@bp.route('/user/<int:id>/toggle_active', methods=['POST'])
@login_required
@permission_required('can_deactivate_users')
def toggle_user_active(id):
    """Toggle user active status (set level to 0 or back to 1)."""
    user = User.query.get_or_404(id)

    if user.id == current_user.id:
        flash('You cannot deactivate your own account.', 'warning')
        return redirect(url_for('admin.users'))

    # Cannot deactivate users at or above your own level
    if user.permission_level >= current_user.permission_level:
        flash('You cannot deactivate a user at or above your permission level.', 'danger')
        return redirect(url_for('admin.users'))

    if user.permission_level == 0:
        user.permission_level = 1
        status = 'activated'
    else:
        user.permission_level = 0
        status = 'deactivated'

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


@bp.route('/user/<int:id>/set_level', methods=['POST'])
@login_required
@permission_required('can_change_user_level')
def set_user_level(id):
    """Set a user's permission level."""
    user = User.query.get_or_404(id)

    if user.id == current_user.id:
        flash('You cannot modify your own permission level.', 'warning')
        return redirect(url_for('admin.users'))

    new_level = request.form.get('permission_level', type=int)
    if new_level is None or new_level < 0 or new_level > 7:
        flash('Invalid permission level.', 'danger')
        return redirect(url_for('admin.users'))

    # Cannot set level higher than your own
    if new_level > current_user.permission_level:
        flash('You cannot set a permission level higher than your own.', 'danger')
        return redirect(url_for('admin.users'))

    # Cannot change users at or above your own level
    if user.permission_level >= current_user.permission_level:
        flash('You cannot modify a user at or above your permission level.', 'danger')
        return redirect(url_for('admin.users'))

    old_level = user.permission_level
    old_name = user.level_name
    user.permission_level = new_level
    new_name = user.level_name

    audit_log = AuditLog(
        user_id=current_user.id,
        action='permission_level_changed',
        details=f'Changed {user.username} from level {old_level} ({old_name}) to level {new_level} ({new_name})',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()

    flash(f'Permission level for {user.username} changed to {new_name} (Level {new_level}).', 'success')
    return redirect(url_for('admin.users'))


@bp.route('/user/<int:id>/delete', methods=['POST'])
@login_required
@permission_required('can_delete_users')
def delete_user(id):
    """Permanently delete a user and all associated data."""
    user = User.query.get_or_404(id)

    if user.id == current_user.id:
        flash('To delete your own account, use the option on your Profile page.', 'warning')
        return redirect(url_for('admin.users'))

    # Cannot delete users at or above your own level
    if user.permission_level >= current_user.permission_level:
        flash('You cannot delete a user at or above your permission level.', 'danger')
        return redirect(url_for('admin.users'))

    # Prevent deleting the last level-7 admin
    if user.permission_level == 7:
        admin_count = User.query.filter(User.permission_level == 7).count()
        if admin_count <= 1:
            flash('Cannot delete the only remaining full administrator.', 'danger')
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

    audit_log = AuditLog(
        user_id=current_user.id,
        action='user_deleted',
        details=f'{current_user.username} permanently deleted user "{username}" (id={id})',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)

    db.session.delete(user)
    db.session.commit()

    flash(f'User "{username}" and all associated data have been permanently deleted.', 'success')
    return redirect(url_for('admin.users'))


# ── Audit Logs ────────────────────────────────────────────────────────────

@bp.route('/audit_logs')
@login_required
@permission_required('can_view_audit_log')
def audit_logs():
    """View audit logs."""
    page = request.args.get('page', 1, type=int)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc())\
        .paginate(page=page, per_page=50, error_out=False)
    return render_template('admin/audit_logs.html', title='Audit Logs', logs=logs)


# ── Statistics ────────────────────────────────────────────────────────────

@bp.route('/statistics')
@login_required
@permission_required('can_view_statistics')
def statistics():
    """View detailed statistics."""
    hours_by_user = db.session.query(
        User.username,
        func.sum(LogEntry.hours + LogEntry.travel_hours).label('total'),
        func.sum(LogEntry.hours).label('activity_only')
    ).join(LogEntry, LogEntry.user_id == User.id).group_by(User.username)\
        .order_by(func.sum(LogEntry.hours + LogEntry.travel_hours).desc()).limit(10).all()

    hours_by_category = db.session.query(
        Category.name,
        func.sum(LogEntry.hours + LogEntry.travel_hours).label('total')
    ).join(LogEntry, LogEntry.category_id == Category.id).group_by(Category.name).all()

    hours_by_role = db.session.query(
        Role.name,
        func.sum(LogEntry.hours + LogEntry.travel_hours).label('total')
    ).join(LogEntry, LogEntry.role_id == Role.id).group_by(Role.name).all()

    return render_template('admin/statistics.html',
                         title='Statistics',
                         hours_by_user=hours_by_user,
                         hours_by_category=hours_by_category,
                         hours_by_role=hours_by_role)


# ── Settings ──────────────────────────────────────────────────────────────

@bp.route('/settings', methods=['GET', 'POST'])
@login_required
@any_admin_required
def settings():
    """Admin settings page — only shows fields the user has permission for."""
    app_settings = AppSettings.get_settings()

    # Map each setting field to its permission
    setting_permissions = {
        'allow_display_name_change': 'can_edit_setting_display_name',
        'allow_password_reset': 'can_edit_setting_password_reset',
        'allow_profile_pic_change': 'can_edit_setting_profile_pic',
        'leaderboard_size': 'can_edit_setting_leaderboard_size',
        'footer_text': 'can_edit_setting_footer_text',
    }

    # Check if user can edit any setting
    can_edit_any = current_user.has_any_settings_permission()
    if not can_edit_any:
        flash('You do not have permission to edit any settings.', 'danger')
        return redirect(url_for('admin.index'))

    if request.method == 'POST':
        changes = []

        if current_user.can('can_edit_setting_display_name'):
            app_settings.allow_display_name_change = 'allow_display_name_change' in request.form
            changes.append('display_name_change')

        if current_user.can('can_edit_setting_password_reset'):
            app_settings.allow_password_reset = 'allow_password_reset' in request.form
            changes.append('password_reset')

        if current_user.can('can_edit_setting_profile_pic'):
            app_settings.allow_profile_pic_change = 'allow_profile_pic_change' in request.form
            changes.append('profile_pic_change')

        if current_user.can('can_edit_setting_leaderboard_size'):
            leaderboard_size = request.form.get('leaderboard_size', 50, type=int)
            app_settings.leaderboard_size = max(10, min(500, leaderboard_size))
            changes.append('leaderboard_size')

        if current_user.can('can_edit_setting_footer_text'):
            app_settings.footer_text = request.form.get('footer_text', '').strip()
            changes.append('footer_text')

        audit_log = AuditLog(
            user_id=current_user.id,
            action='settings_updated',
            details=f'{current_user.username} updated settings: {", ".join(changes)}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()

        flash('Settings updated successfully!', 'success')
        return redirect(url_for('admin.settings'))

    return render_template('admin/settings.html',
                         title='Admin Settings',
                         settings=app_settings,
                         setting_permissions=setting_permissions)


# ── Category Management ───────────────────────────────────────────────────

@bp.route('/categories')
@login_required
@permission_required('can_manage_categories')
def categories():
    """List all categories for admin management."""
    categories = Category.query.order_by(Category.name).all()
    return render_template('admin/categories.html',
                         title='Manage Categories',
                         categories=categories)


@bp.route('/categories/add', methods=['GET', 'POST'])
@login_required
@permission_required('can_manage_categories')
def add_category():
    """Add a new category."""
    from app.main.forms import CategoryForm
    form = CategoryForm()

    if form.validate_on_submit():
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
@permission_required('can_manage_categories')
def edit_category(id):
    """Edit an existing category."""
    from app.main.forms import CategoryForm
    category = Category.query.get_or_404(id)
    form = CategoryForm(obj=category)

    if form.validate_on_submit():
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
@permission_required('can_manage_categories')
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
@permission_required('can_manage_roles')
def roles():
    """List all roles for admin management."""
    roles = Role.query.order_by(Role.name).all()
    return render_template('admin/roles.html',
                         title='Manage Roles',
                         roles=roles)


@bp.route('/roles/add', methods=['GET', 'POST'])
@login_required
@permission_required('can_manage_roles')
def add_role():
    """Add a new role."""
    from app.main.forms import RoleForm
    form = RoleForm()

    if form.validate_on_submit():
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
@permission_required('can_manage_roles')
def edit_role(id):
    """Edit an existing role."""
    from app.main.forms import RoleForm
    role = Role.query.get_or_404(id)
    form = RoleForm(obj=role)

    if form.validate_on_submit():
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


@bp.route('/roles/<int:id>/toggle_active', methods=['POST'])
@login_required
@permission_required('can_manage_roles')
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


# ── Entry Review (Level 2+) ──────────────────────────────────────────────

@bp.route('/entries')
@login_required
@permission_required('can_view_all_entries')
def review_entries():
    """View all users' entries for review."""
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', 'all')
    user_filter = request.args.get('user_id', type=int)

    query = LogEntry.query.join(User, LogEntry.user_id == User.id)

    if status_filter and status_filter != 'all':
        query = query.filter(LogEntry.review_status == status_filter)

    if user_filter:
        query = query.filter(LogEntry.user_id == user_filter)

    entries = query.order_by(LogEntry.date.desc())\
        .paginate(page=page, per_page=25, error_out=False)

    all_users = User.query.filter(User.permission_level > 0).order_by(User.username).all()

    return render_template('admin/entries.html',
                         title='Review Entries',
                         entries=entries,
                         all_users=all_users,
                         status_filter=status_filter,
                         user_filter=user_filter)


@bp.route('/entry/<int:id>/action', methods=['POST'])
@login_required
@permission_required('can_action_entries')
def action_entry(id):
    """Mark an entry as actioned."""
    entry = LogEntry.query.get_or_404(id)

    entry.review_status = 'actioned'
    entry.reviewed_by_id = current_user.id
    entry.reviewed_at = datetime.utcnow()
    entry.denial_reason = None

    audit_log = AuditLog(
        user_id=current_user.id,
        action='entry_actioned',
        details=f'Marked entry "{entry.title}" (id={entry.id}) by {entry.user.username} as actioned',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()

    flash(f'Entry "{entry.title}" marked as actioned.', 'success')
    return redirect(request.referrer or url_for('admin.review_entries'))


@bp.route('/entry/<int:id>/deny', methods=['POST'])
@login_required
@permission_required('can_deny_entries')
def deny_entry(id):
    """Deny (soft-delete) an entry with optional reason."""
    entry = LogEntry.query.get_or_404(id)

    reason = request.form.get('denial_reason', '').strip()

    entry.review_status = 'denied'
    entry.reviewed_by_id = current_user.id
    entry.reviewed_at = datetime.utcnow()
    entry.denial_reason = reason or None

    audit_log = AuditLog(
        user_id=current_user.id,
        action='entry_denied',
        details=f'Denied entry "{entry.title}" (id={entry.id}) by {entry.user.username}. Reason: {reason or "No reason given"}',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()

    flash(f'Entry "{entry.title}" has been denied.', 'success')
    return redirect(request.referrer or url_for('admin.review_entries'))


@bp.route('/entry/<int:id>/restore', methods=['POST'])
@login_required
@permission_required('can_deny_entries')
def restore_entry(id):
    """Restore a denied entry back to active."""
    entry = LogEntry.query.get_or_404(id)

    if entry.review_status != 'denied':
        flash('This entry is not denied.', 'warning')
        return redirect(request.referrer or url_for('admin.review_entries'))

    entry.review_status = 'active'
    entry.reviewed_by_id = current_user.id
    entry.reviewed_at = datetime.utcnow()
    entry.denial_reason = None

    audit_log = AuditLog(
        user_id=current_user.id,
        action='entry_restored',
        details=f'Restored entry "{entry.title}" (id={entry.id}) by {entry.user.username} from denied to active',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()

    flash(f'Entry "{entry.title}" has been restored.', 'success')
    return redirect(request.referrer or url_for('admin.review_entries'))


# ── Permission Level Configuration (Level 7 only) ────────────────────────

@bp.route('/permission-levels', methods=['GET', 'POST'])
@login_required
@level7_required
def permission_levels():
    """Configure permission sets for levels 3-6."""
    configs = {c.level: c for c in PermissionLevelConfig.query.all()}

    # Ensure all levels exist
    for level in range(3, 7):
        if level not in configs:
            c = PermissionLevelConfig(level=level, name=f'Custom Level {level}')
            db.session.add(c)
            configs[level] = c
    db.session.commit()

    if request.method == 'POST':
        for level in range(3, 7):
            config = configs[level]
            config.name = request.form.get(f'name_{level}', '').strip() or f'Custom Level {level}'

            for perm in ALL_PERMISSIONS:
                setattr(config, perm, f'{perm}_{level}' in request.form)

        audit_log = AuditLog(
            user_id=current_user.id,
            action='permission_levels_updated',
            details=f'{current_user.username} updated permission level configuration',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()

        flash('Permission levels updated successfully!', 'success')
        return redirect(url_for('admin.permission_levels'))

    return render_template('admin/permission_levels.html',
                         title='Permission Levels',
                         configs=configs,
                         all_permissions=ALL_PERMISSIONS,
                         level_names=PERMISSION_LEVEL_NAMES)
