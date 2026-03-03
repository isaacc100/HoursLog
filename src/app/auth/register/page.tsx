'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'

export default function RegisterPage() {
  const router = useRouter()
  const [form, setForm] = useState({ username: '', email: '', firstName: '', lastName: '', password: '', password2: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [showAgreement, setShowAgreement] = useState(false)
  
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm(prev => ({ ...prev, [e.target.name]: e.target.value }))
  }
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (form.password !== form.password2) {
      setError('Passwords do not match.')
      return
    }
    if (form.password.length < 6) {
      setError('Password must be at least 6 characters.')
      return
    }
    setShowAgreement(true)
  }
  
  const handleAccept = async () => {
    setShowAgreement(false)
    setLoading(true)
    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: form.username,
          email: form.email,
          password: form.password,
          firstName: form.firstName,
          lastName: form.lastName,
          agreementAccepted: true,
        }),
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error || 'Registration failed.')
        setLoading(false)
        return
      }
      router.push('/auth/login?registered=true')
    } catch {
      setError('An error occurred. Please try again.')
      setLoading(false)
    }
  }
  
  return (
    <div className="container py-5">
      <div className="row justify-content-center">
        <div className="col-md-6">
          <div className="card shadow">
            <div className="card-body p-4">
              <div className="text-center mb-4">
                <i className="bi bi-person-plus text-primary" style={{ fontSize: '3rem' }}></i>
                <h2 className="mt-2">Create Account</h2>
                <p className="text-muted">Join HoursLog to track your volunteer hours</p>
              </div>
              
              {error && (
                <div className="alert alert-danger alert-dismissible fade show">
                  {error}
                  <button type="button" className="btn-close" onClick={() => setError('')}></button>
                </div>
              )}
              
              <form onSubmit={handleSubmit}>
                <div className="row mb-3">
                  <div className="col-md-6">
                    <label className="form-label">First Name</label>
                    <input type="text" className="form-control" name="firstName" value={form.firstName} onChange={handleChange} maxLength={50} />
                  </div>
                  <div className="col-md-6">
                    <label className="form-label">Last Name</label>
                    <input type="text" className="form-control" name="lastName" value={form.lastName} onChange={handleChange} maxLength={50} />
                  </div>
                </div>
                
                <div className="mb-3">
                  <label className="form-label">Username <span className="text-danger">*</span></label>
                  <input type="text" className="form-control" name="username" value={form.username} onChange={handleChange} required minLength={3} maxLength={80} />
                </div>
                
                <div className="mb-3">
                  <label className="form-label">Email <span className="text-danger">*</span></label>
                  <input type="email" className="form-control" name="email" value={form.email} onChange={handleChange} required />
                </div>
                
                <div className="mb-3">
                  <label className="form-label">Password <span className="text-danger">*</span></label>
                  <input type="password" className="form-control" name="password" value={form.password} onChange={handleChange} required minLength={6} />
                </div>
                
                <div className="mb-3">
                  <label className="form-label">Confirm Password <span className="text-danger">*</span></label>
                  <input type="password" className="form-control" name="password2" value={form.password2} onChange={handleChange} required />
                </div>
                
                <button type="submit" className="btn btn-primary w-100" disabled={loading}>
                  {loading ? <><span className="spinner-border spinner-border-sm me-2"></span>Creating account...</> : 'Register'}
                </button>
              </form>
              
              <div className="text-center mt-3">
                <span className="text-muted">Already have an account? </span>
                <Link href="/auth/login">Sign In</Link>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      {/* Data Agreement Modal */}
      {showAgreement && (
        <div className="modal show d-block" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
          <div className="modal-dialog modal-dialog-centered">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title"><i className="bi bi-shield-check me-2"></i>Data Collection Agreement</h5>
              </div>
              <div className="modal-body">
                <p>By creating an account, you agree that HoursLog may collect and store:</p>
                <ul>
                  <li>Your name and email address</li>
                  <li>Volunteer activity data (hours, dates, categories, roles, and descriptions)</li>
                  <li>Login timestamps and browser information for security auditing</li>
                </ul>
                <p>This data is used solely to provide the HoursLog service and will not be shared with third parties. You may request deletion of your data at any time through your profile settings.</p>
              </div>
              <div className="modal-footer">
                <button className="btn btn-secondary" onClick={() => setShowAgreement(false)}>Decline</button>
                <button className="btn btn-primary" onClick={handleAccept}>Accept &amp; Register</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
