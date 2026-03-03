import { redirect } from 'next/navigation'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import PageShell from '@/components/PageShell'
import Link from 'next/link'
import { hasAnyAdminPermission, configToRecord } from '@/lib/permissions'
import { getDisplayName, formatDate } from '@/lib/helpers'

export default async function AdminDashboardPage() {
  const session = await auth()
  if (!session?.user) redirect('/auth/login')
  const level = (session.user as any).permissionLevel
  let perms: Record<string, boolean> | null = null
  if (level >= 3 && level <= 6) {
    const cfg = await prisma.permissionLevelConfig.findUnique({ where: { level } })
    if (cfg) perms = configToRecord(cfg)
  }
  if (!hasAnyAdminPermission(level, perms)) redirect('/')

  const [totalUsers, activeUsers, totalLogs, agg, recentLogs, recentUsers] = await Promise.all([
    prisma.user.count(),
    prisma.user.count({ where: { permissionLevel: { gt: 0 } } }),
    prisma.logEntry.count(),
    prisma.logEntry.aggregate({ _sum: { hours: true, travelHours: true } }),
    prisma.logEntry.findMany({ take: 10, orderBy: { createdAt: 'desc' }, include: { user: true, category: true } }),
    prisma.user.findMany({ take: 5, orderBy: { createdAt: 'desc' } }),
  ])

  const totalActivity = agg._sum.hours || 0
  const totalTravel = agg._sum.travelHours || 0
  const totalHours = totalActivity + totalTravel

  return (
    <PageShell>
      <h2 className="mb-4"><i className="bi bi-shield-lock me-2"></i>Admin Dashboard</h2>

      <div className="row g-3 mb-4">
        {[
          { icon: 'bi-people', color: 'primary', val: totalUsers, label: 'Total Users' },
          { icon: 'bi-person-check', color: 'success', val: activeUsers, label: 'Active Users' },
          { icon: 'bi-journal-text', color: 'info', val: totalLogs, label: 'Total Entries' },
          { icon: 'bi-clock', color: 'warning', val: totalHours.toFixed(1), label: 'Total Hours' },
          { icon: 'bi-activity', color: 'danger', val: totalActivity.toFixed(1), label: 'Activity Hours' },
          { icon: 'bi-car-front', color: 'secondary', val: totalTravel.toFixed(1), label: 'Travel Hours' },
        ].map((s, i) => (
          <div key={i} className="col-md-4 col-lg-2">
            <div className={`card border-${s.color} stat-card h-100`}>
              <div className="card-body text-center py-3">
                <i className={`bi ${s.icon} text-${s.color} fs-4`}></i>
                <h4 className="mt-1 mb-0">{s.val}</h4>
                <small className="text-muted">{s.label}</small>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="row g-4">
        <div className="col-lg-8">
          <div className="card shadow-sm">
            <div className="card-header bg-white"><h5 className="mb-0">Recent Entries</h5></div>
            <div className="table-responsive">
              <table className="table table-hover mb-0">
                <thead className="table-light"><tr><th>Date</th><th>User</th><th>Title</th><th>Category</th><th className="text-end">Hours</th></tr></thead>
                <tbody>
                  {recentLogs.map(e => (
                    <tr key={e.id}>
                      <td>{formatDate(e.date)}</td>
                      <td>{getDisplayName(e.user)}</td>
                      <td>{e.title}</td>
                      <td><span className="badge" style={{ backgroundColor: e.category.color }}>{e.category.name}</span></td>
                      <td className="text-end">{(e.hours + (e.travelHours || 0)).toFixed(1)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
        <div className="col-lg-4">
          <div className="card shadow-sm">
            <div className="card-header bg-white"><h5 className="mb-0">Recent Users</h5></div>
            <ul className="list-group list-group-flush">
              {recentUsers.map(u => (
                <li key={u.id} className="list-group-item d-flex justify-content-between align-items-center">
                  <div>
                    <strong>{getDisplayName(u)}</strong>
                    <br /><small className="text-muted">@{u.username}</small>
                  </div>
                  <span className={`badge ${u.permissionLevel > 0 ? 'bg-success' : 'bg-danger'}`}>
                    {u.permissionLevel > 0 ? 'Active' : 'Deactivated'}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </PageShell>
  )
}
