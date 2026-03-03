'use client'

import { useState, useEffect } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter, useParams } from 'next/navigation'
import Link from 'next/link'

interface Option { id: number; name: string }

export default function EditLogPage() {
  const { data: session, status } = useSession()
  const router = useRouter()
  const params = useParams()
  const entryId = params.id as string
  const [categories, setCategories] = useState<Option[]>([])
  const [roles, setRoles] = useState<Option[]>([])
  const [form, setForm] = useState({
    title: '', description: '', notes: '', hours: '', travelHours: '0',
    date: '', categoryId: '', roleId: '', secondaryRoleIds: [] as number[],
  })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [fetching, setFetching] = useState(true)
  
  useEffect(() => {
    if (status === 'unauthenticated') router.push('/auth/login')
  }, [status, router])
  
  useEffect(() => {
    Promise.all([
      fetch('/api/categories').then(r => r.json()),
      fetch('/api/roles').then(r => r.json()),
      fetch(`/api/log/${entryId}`).then(r => r.json()),
    ]).then(([cats, rols, entry]) => {
      setCategories(cats)
      setRoles(rols)
      if (entry.error) { setError(entry.error); setFetching(false); return }
      setForm({
        title: entry.title, description: entry.description || '', notes: entry.notes || '',
        hours: String(entry.hours), travelHours: String(entry.travelHours || 0),
        date: entry.date?.split('T')[0] || '', categoryId: String(entry.categoryId),
        roleId: String(entry.roleId), secondaryRoleIds: entry.secondaryRoleIds || [],
      })
      setFetching(false)
    }).catch(() => { setError('Failed to load data.'); setFetching(false) })
  }, [entryId])
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const res = await fetch(`/api/log/${entryId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: form.title, description: form.description, notes: form.notes,
          hours: parseFloat(form.hours), travelHours: parseFloat(form.travelHours) || 0,
          date: form.date, categoryId: parseInt(form.categoryId),
          roleId: parseInt(form.roleId), secondaryRoleIds: form.secondaryRoleIds,
        }),
      })
      const data = await res.json()
      if (!res.ok) { setError(data.error || 'Failed to update entry.'); setLoading(false); return }
      router.push('/dashboard')
    } catch { setError('An error occurred.'); setLoading(false) }
  }
  
  const handleSecondaryChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const selected = Array.from(e.target.selectedOptions, o => parseInt(o.value))
    setForm(prev => ({ ...prev, secondaryRoleIds: selected }))
  }
  
  if (status === 'loading' || fetching) return <div className="container py-5 text-center"><div className="spinner-border text-primary"></div></div>
  
  return (
    <div className="container py-4">
      <div className="row justify-content-center">
        <div className="col-md-8">
          <div className="card shadow">
            <div className="card-header bg-white">
              <h4 className="mb-0"><i className="bi bi-pencil me-2 text-primary"></i>Edit Log Entry</h4>
            </div>
            <div className="card-body">
              {error && <div className="alert alert-danger">{error}</div>}
              <form onSubmit={handleSubmit}>
                <div className="mb-3">
                  <label className="form-label">Title <span className="text-danger">*</span></label>
                  <input type="text" className="form-control" value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))} required minLength={3} maxLength={200} />
                </div>
                <div className="mb-3">
                  <label className="form-label">Description</label>
                  <textarea className="form-control" rows={2} value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} maxLength={500}></textarea>
                </div>
                <div className="mb-3">
                  <label className="form-label">Notes</label>
                  <textarea className="form-control" rows={2} value={form.notes} onChange={e => setForm(f => ({ ...f, notes: e.target.value }))} maxLength={1000}></textarea>
                </div>
                <div className="row mb-3">
                  <div className="col-md-4">
                    <label className="form-label">Activity Hours <span className="text-danger">*</span></label>
                    <input type="number" className="form-control" step="0.25" min="0.1" max="24" value={form.hours} onChange={e => setForm(f => ({ ...f, hours: e.target.value }))} required />
                  </div>
                  <div className="col-md-4">
                    <label className="form-label">Travel Hours</label>
                    <input type="number" className="form-control" step="0.25" min="0" max="24" value={form.travelHours} onChange={e => setForm(f => ({ ...f, travelHours: e.target.value }))} required />
                  </div>
                  <div className="col-md-4">
                    <label className="form-label">Date <span className="text-danger">*</span></label>
                    <input type="date" className="form-control" value={form.date} onChange={e => setForm(f => ({ ...f, date: e.target.value }))} required />
                  </div>
                </div>
                <div className="row mb-3">
                  <div className="col-md-6">
                    <label className="form-label">Category <span className="text-danger">*</span></label>
                    <select className="form-select" value={form.categoryId} onChange={e => setForm(f => ({ ...f, categoryId: e.target.value }))} required>
                      <option value="">Select category...</option>
                      {categories.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                    </select>
                  </div>
                  <div className="col-md-6">
                    <label className="form-label">Primary Role <span className="text-danger">*</span></label>
                    <select className="form-select" value={form.roleId} onChange={e => setForm(f => ({ ...f, roleId: e.target.value }))} required>
                      <option value="">Select role...</option>
                      {roles.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
                    </select>
                  </div>
                </div>
                <div className="mb-3">
                  <label className="form-label">Secondary Roles (optional)</label>
                  <select className="form-select" multiple size={4} value={form.secondaryRoleIds.map(String)} onChange={handleSecondaryChange}>
                    {roles.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
                  </select>
                </div>
                <div className="d-flex gap-2">
                  <button type="submit" className="btn btn-primary" disabled={loading}>
                    {loading ? <><span className="spinner-border spinner-border-sm me-1"></span>Saving...</> : <><i className="bi bi-check-lg me-1"></i>Update Entry</>}
                  </button>
                  <Link href="/dashboard" className="btn btn-secondary">Cancel</Link>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
