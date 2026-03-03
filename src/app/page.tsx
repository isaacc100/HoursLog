import PageShell from '@/components/PageShell'
import Link from 'next/link'

export default function HomePage() {
  return (
    <PageShell>
      {/* Hero */}
      <div className="text-center py-5">
        <i className="bi bi-clock-history text-primary" style={{ fontSize: '4rem' }}></i>
        <h1 className="display-4 fw-bold mt-3">HoursLog</h1>
        <p className="lead text-muted mb-4">Track, manage, and report your volunteer hours with ease.</p>
        <div className="d-flex justify-content-center gap-3">
          <Link href="/auth/register" className="btn btn-primary btn-lg">
            <i className="bi bi-person-plus me-2"></i>Get Started
          </Link>
          <Link href="/auth/login" className="btn btn-outline-primary btn-lg">
            <i className="bi bi-box-arrow-in-right me-2"></i>Sign In
          </Link>
        </div>
      </div>
      
      {/* Features */}
      <div className="row g-4 mt-4">
        <div className="col-md-4">
          <div className="card h-100 border-0 shadow-sm">
            <div className="card-body text-center p-4">
              <div className="rounded-circle bg-primary bg-opacity-10 d-inline-flex p-3 mb-3">
                <i className="bi bi-journal-plus text-primary fs-3"></i>
              </div>
              <h5>Log Hours</h5>
              <p className="text-muted">Easily track your volunteer activity and travel hours with detailed categories and roles.</p>
            </div>
          </div>
        </div>
        <div className="col-md-4">
          <div className="card h-100 border-0 shadow-sm">
            <div className="card-body text-center p-4">
              <div className="rounded-circle bg-success bg-opacity-10 d-inline-flex p-3 mb-3">
                <i className="bi bi-graph-up text-success fs-3"></i>
              </div>
              <h5>Track Progress</h5>
              <p className="text-muted">View statistics, charts, and leaderboards to see how your volunteering compares.</p>
            </div>
          </div>
        </div>
        <div className="col-md-4">
          <div className="card h-100 border-0 shadow-sm">
            <div className="card-body text-center p-4">
              <div className="rounded-circle bg-info bg-opacity-10 d-inline-flex p-3 mb-3">
                <i className="bi bi-file-earmark-pdf text-info fs-3"></i>
              </div>
              <h5>Export Reports</h5>
              <p className="text-muted">Generate PDF and CSV reports of your volunteer hours for any time period.</p>
            </div>
          </div>
        </div>
      </div>
      
      <div className="row g-4 mt-2">
        <div className="col-md-4">
          <div className="card h-100 border-0 shadow-sm">
            <div className="card-body text-center p-4">
              <div className="rounded-circle bg-warning bg-opacity-10 d-inline-flex p-3 mb-3">
                <i className="bi bi-trophy text-warning fs-3"></i>
              </div>
              <h5>Leaderboard</h5>
              <p className="text-muted">Compete with fellow volunteers and see where you rank on the leaderboard.</p>
            </div>
          </div>
        </div>
        <div className="col-md-4">
          <div className="card h-100 border-0 shadow-sm">
            <div className="card-body text-center p-4">
              <div className="rounded-circle bg-danger bg-opacity-10 d-inline-flex p-3 mb-3">
                <i className="bi bi-shield-check text-danger fs-3"></i>
              </div>
              <h5>Admin Tools</h5>
              <p className="text-muted">Manage users, review entries, configure settings, and view audit logs.</p>
            </div>
          </div>
        </div>
        <div className="col-md-4">
          <div className="card h-100 border-0 shadow-sm">
            <div className="card-body text-center p-4">
              <div className="rounded-circle bg-secondary bg-opacity-10 d-inline-flex p-3 mb-3">
                <i className="bi bi-people text-secondary fs-3"></i>
              </div>
              <h5>Role Management</h5>
              <p className="text-muted">Organize volunteers by roles and categories for better tracking and reporting.</p>
            </div>
          </div>
        </div>
      </div>
    </PageShell>
  )
}
