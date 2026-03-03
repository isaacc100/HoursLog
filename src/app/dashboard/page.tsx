import { redirect } from 'next/navigation'
import Link from 'next/link'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import PageShell from '@/components/PageShell'
import DashboardCharts from '@/components/DashboardCharts'
import { getDisplayName } from '@/lib/helpers'
import { hasPermission, configToRecord } from '@/lib/permissions'

interface LeaderboardRow {
  id: number
  username: string
  display_name: string | null
  first_name: string | null
  last_name: string | null
  total_hours: number
}

export default async function DashboardPage({ searchParams }: { searchParams: Promise<{ page?: string; leaderboard_period?: string }> }) {
  const session = await auth()
  if (!session?.user) redirect('/auth/login')
  
  const params = await searchParams
  const userId = session.user.id
  const level = session.user.permissionLevel
  const page = Math.max(1, parseInt(params.page || '1'))
  const leaderboardPeriod = params.leaderboard_period || 'all'
  const perPage = 10
  
  // Check permissions
  let permissions: Record<string, boolean> | null = null
  if (level >= 3 && level <= 6) {
    const config = await prisma.permissionLevelConfig.findUnique({ where: { level } })
    if (config) permissions = configToRecord(config)
  }
  const canViewAll = hasPermission(level, 'can_view_all_entries', permissions)
  
  // Fetch entries
  const [entries, totalEntryCount] = await Promise.all([
    prisma.logEntry.findMany({
      where: { userId },
      orderBy: { date: 'desc' },
      skip: (page - 1) * perPage,
      take: perPage,
      include: { category: true, role: true, secondaryRoles: true },
    }),
    prisma.logEntry.count({ where: { userId } }),
  ])
  
  const totalPages = Math.ceil(totalEntryCount / perPage)
  
  // Statistics (exclude denied)
  const stats = await prisma.logEntry.aggregate({
    where: { userId, NOT: { reviewStatus: 'denied' } },
    _sum: { hours: true, travelHours: true },
    _count: true,
  })
  
  const totalActivityHours = stats._sum.hours || 0
  const totalTravelHours = stats._sum.travelHours || 0
  const totalHours = totalActivityHours + totalTravelHours
  const totalEntries = stats._count
  
  // Hours by category
  const catData = await prisma.logEntry.groupBy({
    by: ['categoryId'],
    where: { userId, NOT: { reviewStatus: 'denied' } },
    _sum: { hours: true, travelHours: true },
  })
  const categoryIds = catData.map(c => c.categoryId)
  const categories = categoryIds.length > 0
    ? await prisma.category.findMany({ where: { id: { in: categoryIds } } })
    : []
  const catMap = new Map(categories.map(c => [c.id, c]))
  const hoursByCategory = catData.map(c => ({
    name: catMap.get(c.categoryId)?.name || 'Unknown',
    color: catMap.get(c.categoryId)?.color || '#007bff',
    hours: (c._sum.hours || 0) + (c._sum.travelHours || 0),
  }))
  
  // Hours by role
  const roleData = await prisma.logEntry.groupBy({
    by: ['roleId'],
    where: { userId, NOT: { reviewStatus: 'denied' } },
    _sum: { hours: true, travelHours: true },
  })
  const roleIds = roleData.map(r => r.roleId)
  const roles = roleIds.length > 0
    ? await prisma.role.findMany({ where: { id: { in: roleIds } } })
    : []
  const roleMap = new Map(roles.map(r => [r.id, r]))
  const hoursByRole = roleData.map(r => ({
    name: roleMap.get(r.roleId)?.name || 'Unknown',
    hours: (r._sum.hours || 0) + (r._sum.travelHours || 0),
  }))
  
  // Leaderboard
  const settings = await prisma.appSettings.findFirst()
  const leaderboardSize = settings?.leaderboardSize || 50
  
  let dateFilter: Date | undefined
  const today = new Date()
  if (leaderboardPeriod === 'week') {
    const d = new Date(today)
    d.setDate(d.getDate() - d.getDay() + 1) // Monday
    d.setHours(0, 0, 0, 0)
    dateFilter = d
  } else if (leaderboardPeriod === 'month') {
    dateFilter = new Date(today.getFullYear(), today.getMonth(), 1)
  } else if (leaderboardPeriod === 'year') {
    dateFilter = new Date(today.getFullYear(), 0, 1)
  }
  
  // Raw SQL for leaderboard (Prisma groupBy with joins is limited)
  const leaderboardQuery = dateFilter
    ? await prisma.$queryRaw<LeaderboardRow[]>`
        SELECT u.id, u.username, u.display_name, u.first_name, u.last_name,
               SUM(le.hours + le.travel_hours) as total_hours
        FROM users u JOIN log_entries le ON u.id = le.user_id
        WHERE u.permission_level > 0 AND le.date >= ${dateFilter}
        GROUP BY u.id, u.username, u.display_name, u.first_name, u.last_name
        ORDER BY total_hours DESC`
    : await prisma.$queryRaw<LeaderboardRow[]>`
        SELECT u.id, u.username, u.display_name, u.first_name, u.last_name,
               SUM(le.hours + le.travel_hours) as total_hours
        FROM users u JOIN log_entries le ON u.id = le.user_id
        WHERE u.permission_level > 0
        GROUP BY u.id, u.username, u.display_name, u.first_name, u.last_name
        ORDER BY total_hours DESC`
  
  const userRank = leaderboardQuery.findIndex(r => r.id === userId) + 1 || null
  const leaderboard = leaderboardQuery.slice(0, leaderboardSize)
  
  // Users for export picker (if can view all)
  const allUsers = canViewAll
    ? await prisma.user.findMany({
        where: { id: { not: userId }, permissionLevel: { gt: 0 } },
        orderBy: { username: 'asc' },
        select: { id: true, username: true, displayName: true, firstName: true, lastName: true },
      })
    : []
  
  const periodLabels: Record<string, string> = { all: 'All Time', week: 'This Week', month: 'This Month', year: 'This Year' }
  
  return (
    <PageShell>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2><i className="bi bi-speedometer2 me-2"></i>Dashboard</h2>
        <Link href="/log/new" className="btn btn-primary">
          <i className="bi bi-plus-circle me-1"></i>Log Hours
        </Link>
      </div>
      
      {/* Stats Cards */}
      <div className="row g-3 mb-4">
        <div className="col-md-3">
          <div className="card border-primary stat-card h-100">
            <div className="card-body text-center">
              <i className="bi bi-clock text-primary fs-3"></i>
              <h3 className="mt-2 mb-0">{totalHours.toFixed(1)}</h3>
              <small className="text-muted">Total Hours</small>
            </div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="card border-success stat-card h-100">
            <div className="card-body text-center">
              <i className="bi bi-activity text-success fs-3"></i>
              <h3 className="mt-2 mb-0">{totalActivityHours.toFixed(1)}</h3>
              <small className="text-muted">Activity Hours</small>
            </div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="card border-info stat-card h-100">
            <div className="card-body text-center">
              <i className="bi bi-car-front text-info fs-3"></i>
              <h3 className="mt-2 mb-0">{totalTravelHours.toFixed(1)}</h3>
              <small className="text-muted">Travel Hours</small>
            </div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="card border-warning stat-card h-100">
            <div className="card-body text-center">
              <i className="bi bi-journal-text text-warning fs-3"></i>
              <h3 className="mt-2 mb-0">{totalEntries}</h3>
              <small className="text-muted">Total Entries</small>
            </div>
          </div>
        </div>
      </div>
      
      {/* Charts */}
      {(hoursByCategory.length > 0 || hoursByRole.length > 0) && (
        <div className="row g-4 mb-4">
          <div className="col-md-6">
            <div className="card shadow-sm">
              <div className="card-header bg-white"><h5 className="mb-0">Hours by Category</h5></div>
              <div className="card-body">
                <DashboardCharts type="doughnut" data={hoursByCategory} />
              </div>
            </div>
          </div>
          <div className="col-md-6">
            <div className="card shadow-sm">
              <div className="card-header bg-white"><h5 className="mb-0">Hours by Role</h5></div>
              <div className="card-body">
                <DashboardCharts type="bar" data={hoursByRole} />
              </div>
            </div>
          </div>
        </div>
      )}
      
      {/* Leaderboard */}
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-white d-flex justify-content-between align-items-center">
          <h5 className="mb-0"><i className="bi bi-trophy me-2 text-warning"></i>Leaderboard</h5>
          <div className="btn-group btn-group-sm">
            {['all', 'week', 'month', 'year'].map(p => (
              <Link key={p} href={`/dashboard?leaderboard_period=${p}`}
                className={`btn ${leaderboardPeriod === p ? 'btn-primary' : 'btn-outline-primary'}`}>
                {periodLabels[p]}
              </Link>
            ))}
          </div>
        </div>
        <div className="card-body p-0">
          {leaderboard.length > 0 ? (
            <div className="table-responsive">
              <table className="table table-hover mb-0">
                <thead className="table-light">
                  <tr>
                    <th style={{ width: 60 }}>Rank</th>
                    <th>Volunteer</th>
                    <th className="text-end">Total Hours</th>
                  </tr>
                </thead>
                <tbody>
                  {leaderboard.map((row, i) => (
                    <tr key={row.id} className={row.id === userId ? 'table-primary' : ''}>
                      <td>
                        <span className={`leaderboard-rank ${i < 3 ? ['bg-warning text-dark', 'bg-secondary text-white', 'bg-danger text-white'][i] : 'bg-light'}`}>
                          {i + 1}
                        </span>
                      </td>
                      <td>{getDisplayName({ displayName: row.display_name, firstName: row.first_name, lastName: row.last_name, username: row.username })}</td>
                      <td className="text-end fw-bold">{Number(row.total_hours).toFixed(1)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-4 text-muted">No data for this period.</div>
          )}
          {userRank && (
            <div className="card-footer bg-light text-center">
              <strong>Your Rank: #{userRank}</strong> of {leaderboardQuery.length} volunteers
            </div>
          )}
        </div>
      </div>
      
      {/* Export */}
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-white">
          <h5 className="mb-0"><i className="bi bi-download me-2"></i>Export</h5>
        </div>
        <div className="card-body">
          <div className="d-flex gap-2 flex-wrap">
            <a href="/api/export/pdf?period=all" className="btn btn-outline-danger">
              <i className="bi bi-file-earmark-pdf me-1"></i>PDF (All Time)
            </a>
            <a href="/api/export/csv?period=all" className="btn btn-outline-success">
              <i className="bi bi-filetype-csv me-1"></i>CSV (All Time)
            </a>
            <a href="/api/export/pdf?period=month" className="btn btn-outline-danger">
              <i className="bi bi-file-earmark-pdf me-1"></i>PDF (This Month)
            </a>
            <a href="/api/export/csv?period=month" className="btn btn-outline-success">
              <i className="bi bi-filetype-csv me-1"></i>CSV (This Month)
            </a>
          </div>
          {canViewAll && allUsers.length > 0 && (
            <div className="mt-3">
              <label className="form-label fw-bold">Export another user&apos;s data:</label>
              <div className="input-group">
                <select className="form-select" id="exportUserId">
                  {allUsers.map(u => (
                    <option key={u.id} value={u.id}>
                      {getDisplayName(u)} ({u.username})
                    </option>
                  ))}
                </select>
              </div>
            </div>
          )}
        </div>
      </div>
      
      {/* Entries Table */}
      <div className="card shadow-sm">
        <div className="card-header bg-white d-flex justify-content-between align-items-center">
          <h5 className="mb-0"><i className="bi bi-journal-text me-2"></i>Recent Entries</h5>
          <span className="badge bg-primary">{totalEntryCount} total</span>
        </div>
        <div className="card-body p-0">
          {entries.length > 0 ? (
            <div className="table-responsive">
              <table className="table table-hover mb-0">
                <thead className="table-light">
                  <tr>
                    <th>Date</th>
                    <th>Title</th>
                    <th>Category</th>
                    <th>Role</th>
                    <th className="text-end">Hours</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map(entry => (
                    <tr key={entry.id}>
                      <td>{new Date(entry.date).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}</td>
                      <td>{entry.title}</td>
                      <td><span className="badge" style={{ backgroundColor: entry.category.color }}>{entry.category.name}</span></td>
                      <td>{entry.role.name}</td>
                      <td className="text-end">{(entry.hours + (entry.travelHours || 0)).toFixed(1)}</td>
                      <td>
                        {entry.reviewStatus === 'active' && <span className="badge bg-success">Active</span>}
                        {entry.reviewStatus === 'denied' && <span className="badge bg-danger">Denied</span>}
                        {entry.reviewStatus === 'actioned' && <span className="badge bg-info">Actioned</span>}
                      </td>
                      <td>
                        <Link href={`/log/${entry.id}/edit`} className="btn btn-outline-primary btn-sm">
                          <i className="bi bi-pencil"></i>
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-4 text-muted">
              No entries yet. <Link href="/log/new">Log your first hours!</Link>
            </div>
          )}
        </div>
        {totalPages > 1 && (
          <div className="card-footer bg-white">
            <nav>
              <ul className="pagination pagination-sm justify-content-center mb-0">
                {page > 1 && (
                  <li className="page-item"><Link className="page-link" href={`/dashboard?page=${page - 1}&leaderboard_period=${leaderboardPeriod}`}>Previous</Link></li>
                )}
                {Array.from({ length: totalPages }, (_, i) => (
                  <li key={i} className={`page-item ${page === i + 1 ? 'active' : ''}`}>
                    <Link className="page-link" href={`/dashboard?page=${i + 1}&leaderboard_period=${leaderboardPeriod}`}>{i + 1}</Link>
                  </li>
                ))}
                {page < totalPages && (
                  <li className="page-item"><Link className="page-link" href={`/dashboard?page=${page + 1}&leaderboard_period=${leaderboardPeriod}`}>Next</Link></li>
                )}
              </ul>
            </nav>
          </div>
        )}
      </div>
    </PageShell>
  )
}
