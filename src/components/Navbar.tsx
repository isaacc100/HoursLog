'use client'

import Link from 'next/link'
import { signOut } from 'next-auth/react'
import { hasPermission, hasAnyAdminPermission, hasAnySettingsPermission } from '@/lib/permissions'
import { getDisplayName, getInitials, getAvatarColor } from '@/lib/helpers'

interface NavUser {
  id: number
  username: string
  permissionLevel: number
  displayName?: string | null
  firstName?: string | null
  lastName?: string | null
}

export default function Navbar({ user, permissions }: { user?: NavUser | null; permissions?: Record<string, boolean> | null }) {
  const isLoggedIn = !!user
  const level = user?.permissionLevel ?? 0
  const can = (p: string) => hasPermission(level, p as any, permissions)
  const isAdmin = hasAnyAdminPermission(level, permissions)
  const hasSetting = hasAnySettingsPermission(level, permissions)
  
  return (
    <nav className="navbar navbar-expand-lg navbar-dark bg-primary shadow-sm">
      <div className="container">
        <Link className="navbar-brand d-flex align-items-center gap-2" href="/">
          <i className="bi bi-clock-history fs-4"></i>
          <span className="fw-bold">HoursLog</span>
        </Link>
        <button className="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#mainNav">
          <span className="navbar-toggler-icon"></span>
        </button>
        <div className="collapse navbar-collapse" id="mainNav">
          <ul className="navbar-nav me-auto">
            {isLoggedIn && (
              <>
                <li className="nav-item">
                  <Link className="nav-link" href="/dashboard"><i className="bi bi-speedometer2 me-1"></i>Dashboard</Link>
                </li>
                <li className="nav-item">
                  <Link className="nav-link" href="/log/new"><i className="bi bi-plus-circle me-1"></i>Log Hours</Link>
                </li>
                <li className="nav-item">
                  <Link className="nav-link" href="/categories"><i className="bi bi-tags me-1"></i>Categories</Link>
                </li>
                <li className="nav-item">
                  <Link className="nav-link" href="/roles"><i className="bi bi-people me-1"></i>Roles</Link>
                </li>
              </>
            )}
          </ul>
          <ul className="navbar-nav">
            {isLoggedIn && isAdmin && (
              <li className="nav-item dropdown">
                <a className="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                  <i className="bi bi-shield-lock me-1"></i>Admin
                </a>
                <ul className="dropdown-menu dropdown-menu-end">
                  <li><Link className="dropdown-item" href="/admin"><i className="bi bi-speedometer2 me-1"></i>Dashboard</Link></li>
                  {can('can_manage_users') && <li><Link className="dropdown-item" href="/admin/users"><i className="bi bi-people me-1"></i>Users</Link></li>}
                  {can('can_manage_categories') && <li><Link className="dropdown-item" href="/admin/categories"><i className="bi bi-tags me-1"></i>Categories</Link></li>}
                  {can('can_manage_roles') && <li><Link className="dropdown-item" href="/admin/roles"><i className="bi bi-diagram-3 me-1"></i>Roles</Link></li>}
                  {(can('can_view_all_entries') || can('can_action_entries') || can('can_deny_entries')) && (
                    <li><Link className="dropdown-item" href="/admin/entries"><i className="bi bi-journal-check me-1"></i>Entries</Link></li>
                  )}
                  {can('can_view_audit_log') && <li><Link className="dropdown-item" href="/admin/audit"><i className="bi bi-clock-history me-1"></i>Audit Log</Link></li>}
                  {hasSetting && <li><Link className="dropdown-item" href="/admin/settings"><i className="bi bi-gear me-1"></i>Settings</Link></li>}
                  {level === 7 && <li><Link className="dropdown-item" href="/admin/permissions"><i className="bi bi-key me-1"></i>Permission Levels</Link></li>}
                </ul>
              </li>
            )}
            {isLoggedIn ? (
              <li className="nav-item dropdown">
                <a className="nav-link dropdown-toggle d-flex align-items-center gap-2" href="#" role="button" data-bs-toggle="dropdown">
                  <div className="avatar-circle" style={{ backgroundColor: getAvatarColor(user!.id), width: 30, height: 30, fontSize: '0.75rem' }}>
                    {getInitials(user!)}
                  </div>
                  <span>{getDisplayName(user!)}</span>
                </a>
                <ul className="dropdown-menu dropdown-menu-end">
                  <li><Link className="dropdown-item" href="/profile"><i className="bi bi-person me-1"></i>Profile</Link></li>
                  <li><hr className="dropdown-divider" /></li>
                  <li><button className="dropdown-item" onClick={() => signOut({ callbackUrl: '/' })}><i className="bi bi-box-arrow-right me-1"></i>Logout</button></li>
                </ul>
              </li>
            ) : (
              <>
                <li className="nav-item">
                  <Link className="nav-link" href="/auth/login"><i className="bi bi-box-arrow-in-right me-1"></i>Login</Link>
                </li>
                <li className="nav-item">
                  <Link className="nav-link" href="/auth/register"><i className="bi bi-person-plus me-1"></i>Register</Link>
                </li>
              </>
            )}
          </ul>
        </div>
      </div>
    </nav>
  )
}
