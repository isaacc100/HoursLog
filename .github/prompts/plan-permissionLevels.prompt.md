## Plan: Permission Levels System

**TL;DR** — Replace the binary `is_admin` flag with an 8-tier permission level system (0–7). Levels 0 (deactivated), 1 (standard user), 2 (entry reviewer), and 7 (full admin) are hardcoded. Levels 3–6 are configurable by Level 7 admins, each with a named tier and toggleable permissions. Level 2 introduces a new entry review workflow where entries are active by default but can be stamped "actioned" or "denied" (soft-delete with optional reason). All existing `is_admin` checks are replaced with granular permission lookups. Existing users are migrated based on their current `is_admin` and `is_active` flags.

---

**Steps**

### Step 1 — Database model changes in [app/models.py](app/models.py)

1. **User model:**
   - Add `permission_level` Integer column (default `1`, not nullable).
   - Keep `is_active` as a **hybrid property** that returns `self.permission_level > 0` (maintain backward compat for Flask-Login's `is_active` check).
   - Remove the `is_active` column after migration (replace with property).
   - Remove `is_admin` column after migration (replace with property `is_admin` → `self.permission_level == 7`).
   - Add convenience properties: `is_reviewer` → `permission_level >= 2`, `can(permission_name)` method for checking granular permissions.

2. **LogEntry model — add review fields:**
   - `review_status` — String(20), default `'active'`, values: `active`, `actioned`, `denied`.
   - `reviewed_by_id` — FK → `users.id`, nullable.
   - `reviewed_at` — DateTime, nullable.
   - `denial_reason` — Text, nullable.
   - Relationship: `reviewed_by` → `User`.

3. **New `PermissionLevelConfig` model** (table `permission_level_configs`):
   - `level` — Integer, PK (values 3–6 only).
   - `name` — String(50), e.g. "Supervisor", default empty.
   - **Permission booleans** (all default `False`):
     - `can_manage_users`
     - `can_change_user_level`
     - `can_deactivate_users`
     - `can_delete_users`
     - `can_manage_roles`
     - `can_manage_categories`
     - `can_view_audit_log`
     - `can_view_all_entries`
     - `can_action_entries`
     - `can_deny_entries`
     - `can_edit_setting_display_name`
     - `can_edit_setting_password_reset`
     - `can_edit_setting_profile_pic`
     - `can_edit_setting_leaderboard_size`
     - `can_edit_setting_footer_text`
   - Seed rows for levels 3–6 in `db.create_all()` or a migration.

4. **Add `User.can(permission)` method** — central permission resolution:
   - Level 0 → always `False`
   - Level 1 → always `False` (no admin permissions)
   - Level 2 → hardcoded `True` for `can_view_all_entries`, `can_action_entries`, `can_deny_entries`; `False` for everything else
   - Levels 3–6 → look up `PermissionLevelConfig` row, return the column value
   - Level 7 → always `True`

### Step 2 — Data migration

- Write a migration block (or inline logic at startup) to migrate existing users:
  - `is_admin=True` → `permission_level=7`
  - `is_admin=False, is_active=True` → `permission_level=1`
  - `is_admin=False, is_active=False` → `permission_level=0`
- Seed `PermissionLevelConfig` rows for levels 3, 4, 5, 6 with all permissions `False` and placeholder names.
- Set all existing `LogEntry.review_status` to `'active'`.

### Step 3 — Replace decorators and access control in [app/admin/routes.py](app/admin/routes.py)

1. Replace the `admin_required` decorator with a **`permission_required(permission_name)`** decorator factory:
   - Check `current_user.can(permission_name)`.
   - Return 403 on failure instead of redirecting (with flash + redirect fallback).
2. Update every admin route's decorator:
   - `/admin/` (dashboard) → `permission_required('can_manage_users')` (or any admin-level permission — show if user has *any* permission)
   - `/admin/users`, `toggle_active`, `delete` → `permission_required('can_manage_users')` with sub-checks for deactivate/delete
   - `/admin/user/<id>/toggle_admin` → replace with `set_permission_level` route, gated by `can_change_user_level`, enforcing "cannot set level higher than own"
   - `/admin/categories/*` → `permission_required('can_manage_categories')`
   - `/admin/roles/*` → `permission_required('can_manage_roles')`
   - `/admin/audit_logs` → `permission_required('can_view_audit_log')`
   - `/admin/settings` → custom logic: show only the settings the user has `can_edit_setting_*` for; Level 7 sees all
   - `/admin/statistics` → `permission_required('can_manage_users')` (or a new permission if desired)

### Step 4 — New routes for Level 2 entry review

Add to [app/admin/routes.py](app/admin/routes.py) (or a new `review` blueprint):

1. **`GET /admin/entries`** — `permission_required('can_view_all_entries')` — paginated list of all users' entries with filters (user, date range, status). Shows current `review_status` per entry.
2. **`POST /admin/entry/<id>/action`** — `permission_required('can_action_entries')` — sets `review_status='actioned'`, `reviewed_by_id`, `reviewed_at`.
3. **`POST /admin/entry/<id>/deny`** — `permission_required('can_deny_entries')` — sets `review_status='denied'`, `reviewed_by_id`, `reviewed_at`, `denial_reason` (from form). This is a **soft delete** — the entry persists but is excluded from totals.
4. **`POST /admin/entry/<id>/restore`** — `permission_required('can_deny_entries')` — restores a denied entry back to `active`.

### Step 5 — Update user-facing views

1. **Dashboard** ([app/main/routes.py](app/main/routes.py) + [dashboard.html](app/templates/main/dashboard.html)):
   - Show `review_status` badge on each entry (e.g., green "Actioned" ✓, red "Denied" ✗ with reason tooltip).
   - Exclude denied entries from hour totals (or show separately).
   - For Level 2+ users, show a "Review Queue" link or section.

2. **User management** ([app/templates/admin/users.html](app/templates/admin/users.html)):
   - Replace "Toggle Admin" button with a permission level dropdown (0–7, limited to ≤ current user's level).
   - Show the level name (e.g., "Standard User", "Reviewer", or the configured name for 3–6).
   - Replace "Toggle Active" with setting level to 0 (deactivate) or back to 1 (reactivate).

### Step 6 — Update navigation in [app/templates/base.html](app/templates/base.html)

- Replace `{% if current_user.is_admin %}` with individual permission checks.
- Build the admin dropdown dynamically:
  - "Dashboard" → shown if user has *any* admin permission
  - "Manage Users" → `current_user.can('can_manage_users')`
  - "Review Entries" → `current_user.can('can_view_all_entries')`
  - "Manage Categories" → `current_user.can('can_manage_categories')`
  - "Manage Roles" → `current_user.can('can_manage_roles')`
  - "Statistics" → `current_user.can('can_manage_users')`
  - "Audit Logs" → `current_user.can('can_view_audit_log')`
  - "Settings" → shown if user has *any* `can_edit_setting_*` permission
  - "Permission Levels" → `current_user.permission_level == 7` (Level 7 only config page)

### Step 7 — New admin page: Permission Level Configuration

1. **Template** `app/templates/admin/permission_levels.html` — accessible only to Level 7.
2. **Route** `GET/POST /admin/permission-levels` — shows a form for levels 3–6 with:
   - Name field for each level.
   - Checkbox grid: rows = levels 3–6, columns = each permission.
3. Saves to `PermissionLevelConfig` rows.

### Step 8 — Update settings page in [app/admin/routes.py](app/admin/routes.py) + [settings.html](app/templates/admin/settings.html)

- The settings route should only allow editing settings the user has permission for.
- Render each setting field as read-only or editable based on the user's `can_edit_setting_*` permissions.
- On POST, only process fields the user is authorized to change.

### Step 9 — Update remaining authorization checks

1. **[app/main/routes.py](app/main/routes.py)** — replace all `current_user.is_admin` checks:
   - Entry edit/delete ownership checks: `current_user.can('can_view_all_entries')` or keep admin-only for editing (Level 2 can't edit, but Level 7 can).
   - Export `_export_target_user()`: allow if `current_user.can('can_view_all_entries')`.
2. **[app/auth/routes.py](app/auth/routes.py)** — login check: replace `is_active` check with `permission_level > 0`.
3. **[app/export.py](app/export.py)** — update any admin checks if present.

### Step 10 — Update audit logging

- Log permission level changes (who changed whom, from what level to what level).
- Log entry review actions (actioned, denied, restored).

### Step 11 — Template for entry review

Create `app/templates/admin/entries.html`:
- Table of all entries with: user, date, title, category, hours, status, actions.
- Filter bar: user dropdown, date range, status filter.
- Action buttons per row: "Mark Actioned" (checkbox/button), "Deny" (opens modal with reason textarea), "Restore" (for denied entries).

---

**Verification**

1. **Migration test**: Run the app, verify existing users are correctly assigned levels (admin → 7, active → 1, inactive → 0).
2. **Level 0**: Confirm deactivated users cannot log in.
3. **Level 1**: Confirm standard users see no admin menu, can only manage their own entries.
4. **Level 2**: Log in as Level 2 user → verify "Review Entries" visible, can view all entries, can action/deny, CANNOT edit entry content, CANNOT access user management/categories/roles/settings.
5. **Levels 3–6**: Configure Level 4 with `can_manage_categories` only → verify that user sees only "Manage Categories" in admin menu.
6. **Level cap**: As a Level 4 user, attempt to set another user to Level 5 → verify it's blocked.
7. **Level 7**: Full admin retains all access. Can configure levels 3–6.
8. **Denied entries**: Deny an entry → verify it shows as "Declined" on user's dashboard with reason, excluded from hour totals.
9. **Audit trail**: Verify all permission changes and review actions appear in audit logs.

---

**Decisions**

- Entries are **active by default** — "actioned" is an optional review stamp, not a gate.
- Levels 3–6 are **per-level config** — all users at the same level share the same permission set.
- Level 2 can **view + action/deny only** — no editing of entry content.
- Existing `Role` model keeps its name — the new concept is called "Permission Level" throughout.
- `is_admin` and `is_active` become computed properties on the User model for backward compatibility during transition.
