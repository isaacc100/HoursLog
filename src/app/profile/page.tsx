'use client'

import { useState, useEffect } from 'react'
import { useSession, signOut } from 'next-auth/react'
import { useRouter } from 'next/navigation'

interface Settings {
  allowDisplayNameChange: boolean
  allowPasswordReset: boolean
  allowProfilePicChange: boolean
}

interface UserProfile {
  id: number
  username: string
  email: string
  displayName: string | null
  firstName: string | null
  lastName: string | null
  permissionLevel: number
  createdAt: string
}

export default function ProfilePage() {
  const { data: session, status } = useSession()
  const router = useRouter()
  const [profile, setProfile] = useState<UserProfile | null>(null)
  const [settings, setSettings] = useState<Settings | null>(null)
  const [displayName, setDisplayName] = useState('')
  const [pwForm, setPwForm] = useState({ current: '', newPw: '', confirm: '' })
  const [deleteConfirm, setDeleteConfirm] = useState('')
  const [message, setMessage] = useState<{ type: string; text: string } | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (status === 'unauthenticated') router.push('/auth/login')
  }, [status, router])

  useEffect(() => {
    fetch('/api/profile').then(r => r.json()).then(d => {
      setProfile(d)
      setDisplayName(d.displayName || '')
    })
    fetch('/api/settings').then(r => r.json()).then(d => setSettings(d))
  }, [])

  const handleDisplayName = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    const res = await fetch('/api/profile', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ displayName }),
    })
    const data = await res.json()
    setMessage({ type: res.ok ? 'success' : 'danger', text: data.message || data.error })
    setLoading(false)
  }

  const handlePassword = async (e: React.FormEvent) => {
    e.preventDefault()
    if (pwForm.newPw !== pwForm.confirm) {
      setMessage({ type: 'danger', text: 'Passwords do not match.' })
      return
    }
    setLoading(true)
    const res = await fetch('/api/profile/password', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentPassword: pwForm.current, newPassword: pwForm.newPw }),
    })
    const data = await res.json()
    setMessage({ type: res.ok ? 'success' : 'danger', text: data.message || data.error })
    if (res.ok) setPwForm({ current: '', newPw: '', confirm: '' })
    setLoading(false)
  }

  const handleDelete = async (e: React.FormEvent) => {
    e.preventDefault()
    if (deleteConfirm !== 'I want to delete my data') {
      setMessage({ type: 'danger', text: 'Please type the confirmation phrase exactly.' })
      return
    }
    setLoading(true)
    const res = await fetch('/api/profile', { method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ confirmation: deleteConfirm }),
    })
    if (res.ok) {
      signOut({ callbackUrl: '/' })
    } else {
      const data = await res.json()
      setMessage({ type: 'danger', text: data.error })
      setLoading(false)
    }
  }

  if (!profile || !settings) return <div className="container py-5 text-center"><div className="spinner-border text-primary"></div></div>

  const initials = profile.firstName && profile.lastName
    ? (profile.firstName[0] + profile.lastName[0]).toUpperCase()
    : profile.displayName
      ? profile.displayName.split(' ').length >= 2
        ? (profile.displayName.split(' ')[0][0] + profile.displayName.split(' ')[1][0]).toUpperCase()
        : profile.displayName[0].toUpperCase()
      : profile.username[0].toUpperCase()

  const levelNames: Record<number, string> = { 0: 'Deactivated', 1: 'Standard User', 2: 'Entry Reviewer', 7: 'Full Admin' }
  const levelName = levelNames[profile.permissionLevel] || `Level ${profile.permissionLevel}`

  return (
    <div className="container py-4">
      <h2 className="mb-4"><i className="bi bi-person-circle me-2"></i>Profile</h2>

      {message && (
        <div className={`alert alert-${message.type} alert-dismissible fade show`}>
          {message.text}
          <button type="button" className="btn-close" onClick={() => setMessage(null)}></button>
        </div>
      )}

      {/* User Info Card */}
      <div className="card shadow-sm mb-4">
        <div className="card-body d-flex align-items-center gap-4">
          <div className="avatar-circle avatar-circle-lg" style={{ backgroundColor: '#007bff' }}>
            {initials}
          </div>
          <div>
            <h4 className="mb-1">{profile.displayName || profile.username}</h4>
            <p className="text-muted mb-1">@{profile.username} &middot; {profile.email}</p>
            <span className="badge bg-primary">{levelName}</span>
            <span className="text-muted ms-2 small">Member since {new Date(profile.createdAt).toLocaleDateString()}</span>
          </div>
        </div>
      </div>

      <div className="row g-4">
        {/* Display Name */}
        {settings.allowDisplayNameChange && (
          <div className="col-md-6">
            <div className="card shadow-sm h-100">
              <div className="card-header bg-white"><h5 className="mb-0"><i className="bi bi-pencil me-2"></i>Display Name</h5></div>
              <div className="card-body">
                <form onSubmit={handleDisplayName}>
                  <div className="mb-3">
                    <input type="text" className="form-control" value={displayName} onChange={e => setDisplayName(e.target.value)} maxLength={100} placeholder="Enter display name" />
                  </div>
                  <button type="submit" className="btn btn-primary" disabled={loading}>Save</button>
                </form>
              </div>
            </div>
          </div>
        )}

        {/* Password Change */}
        {settings.allowPasswordReset && (
          <div className="col-md-6">
            <div className="card shadow-sm h-100">
              <div className="card-header bg-white"><h5 className="mb-0"><i className="bi bi-lock me-2"></i>Change Password</h5></div>
              <div className="card-body">
                <form onSubmit={handlePassword}>
                  <div className="mb-2">
                    <input type="password" className="form-control" placeholder="Current password" value={pwForm.current} onChange={e => setPwForm(f => ({ ...f, current: e.target.value }))} required />
                  </div>
                  <div className="mb-2">
                    <input type="password" className="form-control" placeholder="New password (min 6 chars)" value={pwForm.newPw} onChange={e => setPwForm(f => ({ ...f, newPw: e.target.value }))} required minLength={6} />
                  </div>
                  <div className="mb-3">
                    <input type="password" className="form-control" placeholder="Confirm new password" value={pwForm.confirm} onChange={e => setPwForm(f => ({ ...f, confirm: e.target.value }))} required />
                  </div>
                  <button type="submit" className="btn btn-primary" disabled={loading}>Change Password</button>
                </form>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Delete Account */}
      <div className="card border-danger shadow-sm mt-4">
        <div className="card-header bg-danger text-white"><h5 className="mb-0"><i className="bi bi-exclamation-triangle me-2"></i>Danger Zone</h5></div>
        <div className="card-body">
          <p>Deleting your account will permanently remove all your data including log entries, audit records, and profile information.</p>
          <form onSubmit={handleDelete}>
            <div className="mb-3">
              <label className="form-label">Type <strong>&quot;I want to delete my data&quot;</strong> to confirm:</label>
              <input type="text" className="form-control" value={deleteConfirm} onChange={e => setDeleteConfirm(e.target.value)} />
            </div>
            <button type="submit" className="btn btn-danger" disabled={loading || deleteConfirm !== 'I want to delete my data'}>
              <i className="bi bi-trash me-1"></i>Delete Account
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
