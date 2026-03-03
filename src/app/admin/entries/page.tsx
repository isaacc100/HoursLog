import { redirect } from 'next/navigation'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import PageShell from '@/components/PageShell'
import Link from 'next/link'
import { hasPermission, configToRecord } from '@/lib/permissions'
import { getDisplayName, formatDate } from '@/lib/helpers'
import EntryReviewActions from '@/components/EntryReviewActions'

export default async function AdminEntriesPage({ searchParams }: { searchParams: Promise<{ page?: string; status?: string }> }) {
  const session = await auth()
  if (!session?.user) redirect('/auth/login')
  const level = (session.user as any).permissionLevel
  let perms: Record<string, boolean> | null = null
  if (level >= 3 && level <= 6) {
    const cfg = await prisma.permissionLevelConfig.findUnique({ where: { level } })
    if (cfg) perms = configToRecord(cfg)
  }
  const canView = hasPermission(level, 'can_view_all_entries', perms)
  const canAction = hasPermission(level, 'can_action_entries', perms)
  const canDeny = hasPermission(level, 'can_deny_entries', perms)
  if (!canView && !canAction && !canDeny) redirect('/')

  const params = await searchParams
  const page = Math.max(1, parseInt(params.page || '1'))
  const statusFilter = params.status || 'all'
  const perPage = 20

  const where = statusFilter !== 'all' ? { reviewStatus: statusFilter } : {}
  const [entries, total] = await Promise.all([
    prisma.logEntry.findMany({
      where, orderBy: { date: 'desc' }, skip: (page - 1) * perPage, take: perPage,
      include: { user: true, category: true, role: true, reviewedBy: true },
    }),
    prisma.logEntry.count({ where }),
  ])
  const totalPages = Math.ceil(total / perPage)

  return (
    <PageShell>
      <h2 className="mb-4"><i className="bi bi-journal-check me-2"></i>Review Entries</h2>

      <div className="btn-group mb-3">
        {['all', 'active', 'denied', 'actioned'].map(s => (
          <Link key={s} href={`/admin/entries?status=${s}`} className={`btn ${statusFilter === s ? 'btn-primary' : 'btn-outline-primary'}`}>
            {s.charAt(0).toUpperCase() + s.slice(1)} {s === 'all' ? `(${total})` : ''}
          </Link>
        ))}
      </div>

      <div className="card shadow-sm">
        <div className="table-responsive">
          <table className="table table-hover mb-0">
            <thead className="table-light"><tr><th>Date</th><th>User</th><th>Title</th><th>Category</th><th className="text-end">Hours</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody>
              {entries.map(e => (
                <tr key={e.id} className={e.reviewStatus === 'denied' ? 'table-danger' : e.reviewStatus === 'actioned' ? 'table-info' : ''}>
                  <td>{formatDate(e.date)}</td>
                  <td>{getDisplayName(e.user)}</td>
                  <td>{e.title}</td>
                  <td><span className="badge" style={{ backgroundColor: e.category.color }}>{e.category.name}</span></td>
                  <td className="text-end">{(e.hours + (e.travelHours || 0)).toFixed(1)}</td>
                  <td>
                    <span className={`badge ${e.reviewStatus === 'active' ? 'bg-success' : e.reviewStatus === 'denied' ? 'bg-danger' : 'bg-info'}`}>
                      {e.reviewStatus}
                    </span>
                    {e.reviewedBy && <small className="d-block text-muted">by {getDisplayName(e.reviewedBy)}</small>}
                  </td>
                  <td>
                    <EntryReviewActions entryId={e.id} currentStatus={e.reviewStatus} canAction={canAction} canDeny={canDeny} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {totalPages > 1 && (
          <div className="card-footer bg-white">
            <nav><ul className="pagination pagination-sm justify-content-center mb-0">
              {Array.from({ length: totalPages }, (_, i) => (
                <li key={i} className={`page-item ${page === i + 1 ? 'active' : ''}`}>
                  <Link className="page-link" href={`/admin/entries?status=${statusFilter}&page=${i + 1}`}>{i + 1}</Link>
                </li>
              ))}
            </ul></nav>
          </div>
        )}
      </div>
    </PageShell>
  )
}
