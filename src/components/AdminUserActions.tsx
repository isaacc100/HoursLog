'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'

export default function AdminUserActions({ userId, currentLevel, isCurrentUser, canChangeLevel, canDeactivate, canDelete }: {
  userId: number; currentLevel: number; isCurrentUser: boolean;
  canChangeLevel: boolean; canDeactivate: boolean; canDelete: boolean
}) {
  const router = useRouter()
  const [loading, setLoading] = useState(false)
  const [showLevelModal, setShowLevelModal] = useState(false)
  const [newLevel, setNewLevel] = useState(currentLevel)

  const handleToggle = async () => {
    if (!confirm(currentLevel > 0 ? 'Deactivate this user?' : 'Reactivate this user?')) return
    setLoading(true)
    await fetch(`/api/admin/users/${userId}/toggle`, { method: 'POST' })
    router.refresh()
    setLoading(false)
  }

  const handleChangeLevel = async () => {
    setLoading(true)
    await fetch(`/api/admin/users/${userId}/level`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ level: newLevel }),
    })
    setShowLevelModal(false)
    router.refresh()
    setLoading(false)
  }

  const handleDelete = async () => {
    if (!confirm('Are you sure you want to permanently delete this user and all their data?')) return
    setLoading(true)
    await fetch(`/api/admin/users/${userId}`, { method: 'DELETE' })
    router.refresh()
    setLoading(false)
  }

  if (isCurrentUser) return <span className="text-muted small">Current user</span>

  return (
    <>
      <div className="btn-group btn-group-sm">
        {canDeactivate && (
          <button className={`btn ${currentLevel > 0 ? 'btn-outline-warning' : 'btn-outline-success'}`} onClick={handleToggle} disabled={loading}>
            <i className={`bi ${currentLevel > 0 ? 'bi-pause-circle' : 'bi-play-circle'}`}></i>
          </button>
        )}
        {canChangeLevel && (
          <button className="btn btn-outline-info" onClick={() => setShowLevelModal(true)} disabled={loading}>
            <i className="bi bi-sliders"></i>
          </button>
        )}
        {canDelete && (
          <button className="btn btn-outline-danger" onClick={handleDelete} disabled={loading}>
            <i className="bi bi-trash"></i>
          </button>
        )}
      </div>

      {showLevelModal && (
        <div className="modal show d-block" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
          <div className="modal-dialog modal-dialog-centered">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">Change Permission Level</h5>
                <button type="button" className="btn-close" onClick={() => setShowLevelModal(false)}></button>
              </div>
              <div className="modal-body">
                <select className="form-select" value={newLevel} onChange={e => setNewLevel(parseInt(e.target.value))}>
                  <option value={0}>0 - Deactivated</option>
                  <option value={1}>1 - Standard User</option>
                  <option value={2}>2 - Entry Reviewer</option>
                  <option value={3}>3 - Custom Level 3</option>
                  <option value={4}>4 - Custom Level 4</option>
                  <option value={5}>5 - Custom Level 5</option>
                  <option value={6}>6 - Custom Level 6</option>
                  <option value={7}>7 - Full Admin</option>
                </select>
              </div>
              <div className="modal-footer">
                <button className="btn btn-secondary" onClick={() => setShowLevelModal(false)}>Cancel</button>
                <button className="btn btn-primary" onClick={handleChangeLevel} disabled={loading}>Save</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
