'use client'

import { useState } from 'react'
import { signIn } from 'next-auth/react'
import Link from 'next/link'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    
    const result = await signIn('credentials', {
      username,
      password,
      redirect: false,
    })
    
    if (result?.error) {
      setError('Invalid username or password. Please try again.')
      setLoading(false)
    } else {
      window.location.href = '/dashboard'
    }
  }
  
  return (
    <div className="container py-5">
      <div className="row justify-content-center">
        <div className="col-md-5">
          <div className="card shadow">
            <div className="card-body p-4">
              <div className="text-center mb-4">
                <i className="bi bi-clock-history text-primary" style={{ fontSize: '3rem' }}></i>
                <h2 className="mt-2">Sign In</h2>
                <p className="text-muted">Welcome back to HoursLog</p>
              </div>
              
              {error && (
                <div className="alert alert-danger alert-dismissible fade show" role="alert">
                  {error}
                  <button type="button" className="btn-close" onClick={() => setError('')}></button>
                </div>
              )}
              
              <form onSubmit={handleSubmit}>
                <div className="mb-3">
                  <label htmlFor="username" className="form-label">Username</label>
                  <div className="input-group">
                    <span className="input-group-text"><i className="bi bi-person"></i></span>
                    <input type="text" className="form-control" id="username" value={username}
                      onChange={e => setUsername(e.target.value)} required minLength={3} maxLength={80} />
                  </div>
                </div>
                
                <div className="mb-3">
                  <label htmlFor="password" className="form-label">Password</label>
                  <div className="input-group">
                    <span className="input-group-text"><i className="bi bi-lock"></i></span>
                    <input type="password" className="form-control" id="password" value={password}
                      onChange={e => setPassword(e.target.value)} required />
                  </div>
                </div>
                
                <button type="submit" className="btn btn-primary w-100" disabled={loading}>
                  {loading ? <><span className="spinner-border spinner-border-sm me-2"></span>Signing in...</> : 'Sign In'}
                </button>
              </form>
              
              <div className="text-center mt-3">
                <span className="text-muted">Don&apos;t have an account? </span>
                <Link href="/auth/register">Register</Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
