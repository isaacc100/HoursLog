'use client'
import { useState, useEffect } from 'react'
import { useRouter, useParams } from 'next/navigation'
import Link from 'next/link'

export default function EditRolePage() {
  const router = useRouter()
  const params = useParams()
  const id = params.id as string
  const [form, setForm] = useState({ name: '', description: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    fetch(`/api/admin/roles/${id}`).then(r => r.json()).then(d => setForm({ name: d.name, description: d.description || '' }))
  }, [id])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    const res = await fetch(`/api/admin/roles/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) })
    const data = await res.json()
    if (!res.ok) { setError(data.error); setLoading(false); return }
    router.push('/admin/roles')
  }

  return (
    <div className="container py-4">
      <div className="row justify-content-center"><div className="col-md-6">
        <div className="card shadow">
          <div className="card-header bg-white"><h4 className="mb-0"><i className="bi bi-pencil me-2 text-primary"></i>Edit Role</h4></div>
          <div className="card-body">
            {error && <div className="alert alert-danger">{error}</div>}
            <form onSubmit={handleSubmit}>
              <div className="mb-3"><label className="form-label">Name *</label><input type="text" className="form-control" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} required /></div>
              <div className="mb-3"><label className="form-label">Description</label><input type="text" className="form-control" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} /></div>
              <div className="d-flex gap-2"><button type="submit" className="btn btn-primary" disabled={loading}>Update</button><Link href="/admin/roles" className="btn btn-secondary">Cancel</Link></div>
            </form>
          </div>
        </div>
      </div></div>
    </div>
  )
}
