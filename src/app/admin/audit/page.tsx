import { redirect } from 'next/navigation'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import PageShell from '@/components/PageShell'
import Link from 'next/link'
import { hasPermission, configToRecord } from '@/lib/permissions'
import { formatDateTime } from '@/lib/helpers'

export default async function AuditLogPage({ searchParams }: { searchParams: Promise<{ page?: string }> }) {
  const session = await auth()
  if (!session?.user) redirect('/auth/login')
  const level = (session.user as any).permissionLevel
  let perms: Record<string, boolean> | null = null
  if (level >= 3 && level <= 6) {
    const cfg = await prisma.permissionLevelConfig.findUnique({ where: { level } })
    if (cfg) perms = configToRecord(cfg)
  }
  if (!hasPermission(level, 'can_view_audit_log', perms)) redirect('/')

  const params = await searchParams
  const page = Math.max(1, parseInt(params.page || '1'))
  const perPage = 20
  const [logs, total] = await Promise.all([
    prisma.auditLog.findMany({
      orderBy: { timestamp: 'desc' }, skip: (page - 1) * perPage, take: perPage,
      include: { user: { select: { username: true } } },
    }),
    prisma.auditLog.count(),
  ])
  const totalPages = Math.ceil(total / perPage)

  return (
    <PageShell>
      <h2 className="mb-4"><i className="bi bi-clock-history me-2"></i>Audit Log</h2>
      <div className="card shadow-sm">
        <div className="table-responsive">
          <table className="table table-hover table-sm mb-0">
            <thead className="table-light"><tr><th>Timestamp</th><th>User</th><th>Action</th><th>Details</th><th>IP</th></tr></thead>
            <tbody>
              {logs.map(log => (
                <tr key={log.id}>
                  <td><small>{formatDateTime(log.timestamp)}</small></td>
                  <td>{log.user?.username || <span className="text-muted">System</span>}</td>
                  <td><span className="badge bg-secondary">{log.action}</span></td>
                  <td><small>{log.details}</small></td>
                  <td><small className="text-muted">{log.ipAddress || '—'}</small></td>
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
                  <Link className="page-link" href={`/admin/audit?page=${i + 1}`}>{i + 1}</Link>
                </li>
              ))}
            </ul></nav>
          </div>
        )}
      </div>
    </PageShell>
  )
}
