'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'

export default function EntryReviewActions({ entryId, currentStatus, canAction, canDeny }: {
  entryId: number; currentStatus: string; canAction: boolean; canDeny: boolean
}) {
  const router = useRouter()
  const [loading, setLoading] = useState(false)
  const [showDenyModal, setShowDenyModal] = useState(false)
  const [reason, setReason] = useState('')

  const handleAction = async (action: string, denialReason?: string) => {
    setLoading(true)
    await fetch(`/api/admin/entries/${entryId}/review`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, reason: denialReason }),
    })
    setShowDenyModal(false)
    router.refresh()
    setLoading(false)
  }

  return (
    <>
      <div className="btn-group btn-group-sm">
        {canAction && currentStatus !== 'actioned' && (
          <button className="btn btn-outline-success" onClick={() => handleAction('action')} disabled={loading} title="Mark as actioned">
            <i className="bi bi-check-lg"></i>
          </button>
        )}
        {canDeny && currentStatus !== 'denied' && (
          <button className="btn btn-outline-danger" onClick={() => setShowDenyModal(true)} disabled={loading} title="Deny">
            <i className="bi bi-x-lg"></i>
          </button>
        )}
        {(canAction || canDeny) && currentStatus !== 'active' && (
          <button className="btn btn-outline-secondary" onClick={() => handleAction('reset')} disabled={loading} title="Reset to active">
            <i className="bi bi-arrow-counterclockwise"></i>
          </button>
        )}
      </div>

      {showDenyModal && (
        <div className="modal show d-block" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
          <div className="modal-dialog modal-dialog-centered">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">Deny Entry</h5>
                <button type="button" className="btn-close" onClick={() => setShowDenyModal(false)}></button>
              </div>
              <div className="modal-body">
                <label className="form-label">Reason for denial:</label>
                <textarea className="form-control" rows={3} value={reason} onChange={e => setReason(e.target.value)}></textarea>
              </div>
              <div className="modal-footer">
                <button className="btn btn-secondary" onClick={() => setShowDenyModal(false)}>Cancel</button>
                <button className="btn btn-danger" onClick={() => handleAction('deny', reason)} disabled={loading}>Deny Entry</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
