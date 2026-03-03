'use client'
import { useState, useEffect } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'

const PERMISSION_GROUPS = [
  { label: 'User Management', permissions: [
    { key: 'canManageUsers', label: 'Manage Users' },
    { key: 'canChangeUserLevel', label: 'Change User Level' },
    { key: 'canDeactivateUsers', label: 'Deactivate Users' },
    { key: 'canDeleteUsers', label: 'Delete Users' },
  ]},
  { label: 'Content', permissions: [
    { key: 'canManageRoles', label: 'Manage Roles' },
    { key: 'canManageCategories', label: 'Manage Categories' },
  ]},
  { label: 'Entry Review', permissions: [
    { key: 'canViewAllEntries', label: 'View All Entries' },
    { key: 'canActionEntries', label: 'Action Entries' },
    { key: 'canDenyEntries', label: 'Deny Entries' },
  ]},
  { label: 'Audit & Stats', permissions: [
    { key: 'canViewAuditLog', label: 'View Audit Log' },
    { key: 'canViewStatistics', label: 'View Statistics' },
  ]},
  { label: 'Settings', permissions: [
    { key: 'canEditSettingDisplayName', label: 'Edit Display Name Setting' },
    { key: 'canEditSettingPasswordReset', label: 'Edit Password Reset Setting' },
    { key: 'canEditSettingProfilePic', label: 'Edit Profile Pic Setting' },
    { key: 'canEditSettingLeaderboardSize', label: 'Edit Leaderboard Size' },
    { key: 'canEditSettingFooterText', label: 'Edit Footer Text' },
  ]},
]

interface LevelConfig {
  level: number
  name: string
  [key: string]: any
}

export default function PermissionLevelsPage() {
  const { data: session, status } = useSession()
  const router = useRouter()
  const [configs, setConfigs] = useState<LevelConfig[]>([])
  const [message, setMessage] = useState<{ type: string; text: string } | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (status === 'unauthenticated') router.push('/auth/login')
    if (session && (session.user as any).permissionLevel !== 7) router.push('/')
  }, [status, session, router])

  useEffect(() => {
    fetch('/api/admin/permissions').then(r => r.json()).then(setConfigs)
  }, [])

  const handleToggle = (level: number, key: string) => {
    setConfigs(prev => prev.map(c => c.level === level ? { ...c, [key]: !c[key] } : c))
  }

  const handleNameChange = (level: number, name: string) => {
    setConfigs(prev => prev.map(c => c.level === level ? { ...c, name } : c))
  }

  const handleSave = async () => {
    setLoading(true)
    const res = await fetch('/api/admin/permissions', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(configs),
    })
    const data = await res.json()
    setMessage({ type: res.ok ? 'success' : 'danger', text: data.message || data.error })
    setLoading(false)
  }

  if (!configs.length) return <div className="container py-5 text-center"><div className="spinner-border text-primary"></div></div>

  return (
    <div className="container py-4">
      <h2 className="mb-4"><i className="bi bi-key me-2"></i>Permission Levels</h2>

      {message && (
        <div className={`alert alert-${message.type} alert-dismissible fade show`}>
          {message.text}<button type="button" className="btn-close" onClick={() => setMessage(null)}></button>
        </div>
      )}

      <div className="card shadow-sm">
        <div className="table-responsive">
          <table className="table table-bordered mb-0">
            <thead className="table-light">
              <tr>
                <th>Permission</th>
                {configs.map(c => (
                  <th key={c.level} className="text-center" style={{ minWidth: 140 }}>
                    <input type="text" className="form-control form-control-sm text-center mb-1"
                      value={c.name} onChange={e => handleNameChange(c.level, e.target.value)}
                      placeholder={`Level ${c.level}`} />
                    <small className="text-muted">Level {c.level}</small>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {PERMISSION_GROUPS.map(group => (
                <>
                  <tr key={group.label} className="table-secondary">
                    <td colSpan={configs.length + 1}><strong>{group.label}</strong></td>
                  </tr>
                  {group.permissions.map(p => (
                    <tr key={p.key}>
                      <td>{p.label}</td>
                      {configs.map(c => (
                        <td key={c.level} className="text-center">
                          <input type="checkbox" className="form-check-input"
                            checked={c[p.key] || false}
                            onChange={() => handleToggle(c.level, p.key)} />
                        </td>
                      ))}
                    </tr>
                  ))}
                </>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card-footer">
          <button className="btn btn-primary" onClick={handleSave} disabled={loading}>
            {loading ? 'Saving...' : 'Save All'}
          </button>
        </div>
      </div>

      <div className="card mt-4 border-info">
        <div className="card-body">
          <h6 className="card-title"><i className="bi bi-info-circle me-1 text-info"></i>Fixed Levels</h6>
          <ul className="mb-0">
            <li><strong>Level 0</strong> — Deactivated (no access)</li>
            <li><strong>Level 1</strong> — Standard User (no admin permissions)</li>
            <li><strong>Level 2</strong> — Entry Reviewer (can view, action, and deny entries)</li>
            <li><strong>Levels 3-6</strong> — Configurable (above)</li>
            <li><strong>Level 7</strong> — Full Admin (all permissions)</li>
          </ul>
        </div>
      </div>
    </div>
  )
}
