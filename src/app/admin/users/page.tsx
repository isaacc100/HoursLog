import { redirect } from 'next/navigation'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import PageShell from '@/components/PageShell'
import Link from 'next/link'
import { hasPermission, configToRecord, PERMISSION_LEVEL_NAMES } from '@/lib/permissions'
import { getDisplayName } from '@/lib/helpers'
import AdminUserActions from '@/components/AdminUserActions'

export default async function AdminUsersPage({ searchParams }: { searchParams: Promise<{ page?: string }> }) {
  const session = await auth()
  if (!session?.user) redirect('/auth/login')
  const level = (session.user as any).permissionLevel
  let perms: Record<string, boolean> | null = null
  if (level >= 3 && level <= 6) {
    const cfg = await prisma.permissionLevelConfig.findUnique({ where: { level } })
    if (cfg) perms = configToRecord(cfg)
  }
  if (!hasPermission(level, 'can_manage_users', perms)) redirect('/')
  
  const params = await searchParams
  const page = Math.max(1, parseInt(params.page || '1'))
  const perPage = 20
  const [users, total] = await Promise.all([
    prisma.user.findMany({ orderBy: { createdAt: 'desc' }, skip: (page - 1) * perPage, take: perPage }),
    prisma.user.count(),
  ])
  const totalPages = Math.ceil(total / perPage)
  
  const canChangeLevel = hasPermission(level, 'can_change_user_level', perms)
  const canDeactivate = hasPermission(level, 'can_deactivate_users', perms)
  const canDelete = hasPermission(level, 'can_delete_users', perms)
  const currentUserId = (session.user as any).id

  const levelNames: Record<number, string> = { ...PERMISSION_LEVEL_NAMES }

  return (
    <PageShell>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2><i className="bi bi-people me-2"></i>Manage Users</h2>
        <span className="badge bg-primary fs-6">{total} users</span>
      </div>

      <div className="card shadow-sm">
        <div className="table-responsive">
          <table className="table table-hover mb-0">
            <thead className="table-light">
              <tr><th>Username</th><th>Email</th><th>Name</th><th>Level</th><th>Joined</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id} className={u.permissionLevel === 0 ? 'table-secondary' : ''}>
                  <td><strong>@{u.username}</strong></td>
                  <td>{u.email}</td>
                  <td>{getDisplayName(u)}</td>
                  <td>
                    <span className={`badge ${u.permissionLevel === 7 ? 'bg-danger' : u.permissionLevel === 0 ? 'bg-secondary' : u.permissionLevel >= 2 ? 'bg-warning text-dark' : 'bg-primary'}`}>
                      {levelNames[u.permissionLevel] || `Level ${u.permissionLevel}`}
                    </span>
                  </td>
                  <td><small>{new Date(u.createdAt).toLocaleDateString()}</small></td>
                  <td>
                    <AdminUserActions
                      userId={u.id}
                      currentLevel={u.permissionLevel}
                      isCurrentUser={u.id === currentUserId}
                      canChangeLevel={canChangeLevel}
                      canDeactivate={canDeactivate}
                      canDelete={canDelete}
                    />
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
                  <Link className="page-link" href={`/admin/users?page=${i + 1}`}>{i + 1}</Link>
                </li>
              ))}
            </ul></nav>
          </div>
        )}
      </div>
    </PageShell>
  )
}
