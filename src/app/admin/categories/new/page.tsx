'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'

export default function NewCategoryPage() {
  const router = useRouter()
  const [form, setForm] = useState({ name: '', description: '', color: '#007bff' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    const res = await fetch('/api/admin/categories', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form),
    })
    const data = await res.json()
    if (!res.ok) { setError(data.error); setLoading(false); return }
    router.push('/admin/categories')
  }

  return (
    <div className="container py-4">
      <div className="row justify-content-center">
        <div className="col-md-6">
          <div className="card shadow">
            <div className="card-header bg-white"><h4 className="mb-0"><i className="bi bi-plus-circle me-2 text-primary"></i>New Category</h4></div>
            <div className="card-body">
              {error && <div className="alert alert-danger">{error}</div>}
              <form onSubmit={handleSubmit}>
                <div className="mb-3">
                  <label className="form-label">Name *</label>
                  <input type="text" className="form-control" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} required minLength={2} maxLength={50} />
                </div>
                <div className="mb-3">
                  <label className="form-label">Description</label>
                  <input type="text" className="form-control" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} maxLength={200} />
                </div>
                <div className="mb-3">
                  <label className="form-label">Color</label>
                  <input type="color" className="form-control form-control-color" value={form.color} onChange={e => setForm(f => ({ ...f, color: e.target.value }))} />
                </div>
                <div className="d-flex gap-2">
                  <button type="submit" className="btn btn-primary" disabled={loading}>Save</button>
                  <Link href="/admin/categories" className="btn btn-secondary">Cancel</Link>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
