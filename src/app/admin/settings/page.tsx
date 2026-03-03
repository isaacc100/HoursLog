'use client'
import { useState, useEffect } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'

interface Settings {
  id: number
  allowDisplayNameChange: boolean
  allowPasswordReset: boolean
  allowProfilePicChange: boolean
  leaderboardSize: number
  footerText: string
}

export default function AdminSettingsPage() {
  const { data: session, status } = useSession()
  const router = useRouter()
  const [settings, setSettings] = useState<Settings | null>(null)
  const [permissions, setPermissions] = useState<Record<string, boolean>>({})
  const [message, setMessage] = useState<{ type: string; text: string } | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (status === 'unauthenticated') router.push('/auth/login')
  }, [status, router])

  useEffect(() => {
    fetch('/api/settings').then(r => r.json()).then(setSettings)
    fetch('/api/admin/permissions/check').then(r => r.json()).then(setPermissions)
  }, [])

  const handleSave = async () => {
    if (!settings) return
    setLoading(true)
    const res = await fetch('/api/admin/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings),
    })
    const data = await res.json()
    setMessage({ type: res.ok ? 'success' : 'danger', text: data.message || data.error })
    setLoading(false)
  }

  if (!settings) return <div className="container py-5 text-center"><div className="spinner-border text-primary"></div></div>

  const canEdit = (key: string) => permissions[key] === true || (session?.user as any)?.permissionLevel === 7

  return (
    <div className="container py-4">
      <h2 className="mb-4"><i className="bi bi-gear me-2"></i>Application Settings</h2>

      {message && (
        <div className={`alert alert-${message.type} alert-dismissible fade show`}>
          {message.text}<button type="button" className="btn-close" onClick={() => setMessage(null)}></button>
        </div>
      )}

      <div className="card shadow-sm">
        <div className="card-body">
          <div className="mb-4">
            <h5 className="card-title">Feature Toggles</h5>
            <div className="form-check form-switch mb-3">
              <input className="form-check-input" type="checkbox" id="displayName"
                checked={settings.allowDisplayNameChange}
                disabled={!canEdit('can_edit_setting_display_name')}
                onChange={e => setSettings(s => s ? { ...s, allowDisplayNameChange: e.target.checked } : s)} />
              <label className="form-check-label" htmlFor="displayName">Allow Display Name Changes</label>
            </div>
            <div className="form-check form-switch mb-3">
              <input className="form-check-input" type="checkbox" id="passwordReset"
                checked={settings.allowPasswordReset}
                disabled={!canEdit('can_edit_setting_password_reset')}
                onChange={e => setSettings(s => s ? { ...s, allowPasswordReset: e.target.checked } : s)} />
              <label className="form-check-label" htmlFor="passwordReset">Allow Password Reset</label>
            </div>
            <div className="form-check form-switch mb-3">
              <input className="form-check-input" type="checkbox" id="profilePic"
                checked={settings.allowProfilePicChange}
                disabled={!canEdit('can_edit_setting_profile_pic')}
                onChange={e => setSettings(s => s ? { ...s, allowProfilePicChange: e.target.checked } : s)} />
              <label className="form-check-label" htmlFor="profilePic">Allow Profile Picture Changes</label>
            </div>
          </div>

          <div className="mb-4">
            <h5>Leaderboard</h5>
            <div className="row">
              <div className="col-md-4">
                <label className="form-label">Leaderboard Size</label>
                <input type="number" className="form-control" min={1} max={500}
                  value={settings.leaderboardSize}
                  disabled={!canEdit('can_edit_setting_leaderboard_size')}
                  onChange={e => setSettings(s => s ? { ...s, leaderboardSize: parseInt(e.target.value) || 50 } : s)} />
              </div>
            </div>
          </div>

          <div className="mb-4">
            <h5>Footer</h5>
            <input type="text" className="form-control" maxLength={500}
              value={settings.footerText}
              disabled={!canEdit('can_edit_setting_footer_text')}
              onChange={e => setSettings(s => s ? { ...s, footerText: e.target.value } : s)}
              placeholder="Custom footer text" />
          </div>

          <button className="btn btn-primary" onClick={handleSave} disabled={loading}>
            {loading ? <><span className="spinner-border spinner-border-sm me-1"></span>Saving...</> : <><i className="bi bi-check-lg me-1"></i>Save Settings</>}
          </button>
        </div>
      </div>
    </div>
  )
}
