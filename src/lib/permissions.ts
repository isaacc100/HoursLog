export const PERMISSION_LEVEL_NAMES: Record<number, string> = {
  0: 'Deactivated',
  1: 'Standard User',
  2: 'Entry Reviewer',
  7: 'Full Admin',
}

export const ALL_PERMISSIONS = [
  'can_manage_users', 'can_change_user_level', 'can_deactivate_users', 'can_delete_users',
  'can_manage_roles', 'can_manage_categories', 'can_view_audit_log', 'can_view_all_entries',
  'can_action_entries', 'can_deny_entries', 'can_edit_setting_display_name',
  'can_edit_setting_password_reset', 'can_edit_setting_profile_pic',
  'can_edit_setting_leaderboard_size', 'can_edit_setting_footer_text', 'can_view_statistics',
] as const

export type Permission = typeof ALL_PERMISSIONS[number]

export const LEVEL_2_PERMISSIONS: Set<Permission> = new Set([
  'can_view_all_entries', 'can_action_entries', 'can_deny_entries',
])

// Helper function to check if a user has a permission
// Takes the user's permission level and optionally the config row for levels 3-6
export function hasPermission(level: number, permission: Permission, config?: Record<string, boolean> | null): boolean {
  if (level <= 0) return false
  if (level === 1) return false
  if (level === 7) return true
  if (level === 2) return LEVEL_2_PERMISSIONS.has(permission)
  // Levels 3-6: check config
  if (!config) return false
  return config[permission] ?? false
}

export function hasAnyAdminPermission(level: number, config?: Record<string, boolean> | null): boolean {
  if (level >= 7) return true
  if (level === 2) return true
  if (level <= 1) return false
  if (!config) return false
  return ALL_PERMISSIONS.some(p => config[p] === true)
}

export function hasAnySettingsPermission(level: number, config?: Record<string, boolean> | null): boolean {
  if (level === 7) return true
  if (level <= 2) return false
  if (!config) return false
  return ALL_PERMISSIONS.filter(p => p.startsWith('can_edit_setting_')).some(p => config[p] === true)
}

// Map Prisma PermissionLevelConfig to a simple Record
export function configToRecord(config: any): Record<string, boolean> {
  const result: Record<string, boolean> = {}
  for (const p of ALL_PERMISSIONS) {
    // Convert camelCase prisma field back to snake_case permission name
    const camelKey = p.replace(/_([a-z])/g, (_, c) => c.toUpperCase())
    result[p] = config?.[camelKey] ?? false
  }
  return result
}
