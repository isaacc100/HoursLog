import { redirect } from 'next/navigation'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import PageShell from '@/components/PageShell'
import Link from 'next/link'
import { hasPermission, configToRecord } from '@/lib/permissions'
import ToggleButton from '@/components/ToggleButton'

export default async function AdminRolesPage() {
  const session = await auth()
  if (!session?.user) redirect('/auth/login')
  const level = (session.user as any).permissionLevel
  let perms: Record<string, boolean> | null = null
  if (level >= 3 && level <= 6) {
    const cfg = await prisma.permissionLevelConfig.findUnique({ where: { level } })
    if (cfg) perms = configToRecord(cfg)
  }
  if (!hasPermission(level, 'can_manage_roles', perms)) redirect('/')

  const roles = await prisma.role.findMany({ orderBy: { name: 'asc' } })

  return (
    <PageShell>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2><i className="bi bi-diagram-3 me-2"></i>Manage Roles</h2>
        <Link href="/admin/roles/new" className="btn btn-primary"><i className="bi bi-plus-circle me-1"></i>Add Role</Link>
      </div>
      <div className="card shadow-sm">
        <div className="table-responsive">
          <table className="table table-hover mb-0">
            <thead className="table-light"><tr><th>Name</th><th>Description</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody>
              {roles.map(r => (
                <tr key={r.id} className={r.isActive ? '' : 'table-secondary'}>
                  <td><strong>{r.name}</strong></td>
                  <td>{r.description || <span className="text-muted">—</span>}</td>
                  <td><span className={`badge ${r.isActive ? 'bg-success' : 'bg-secondary'}`}>{r.isActive ? 'Active' : 'Inactive'}</span></td>
                  <td>
                    <div className="btn-group btn-group-sm">
                      <Link href={`/admin/roles/${r.id}/edit`} className="btn btn-outline-primary"><i className="bi bi-pencil"></i></Link>
                      <ToggleButton id={r.id} type="role" isActive={r.isActive} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </PageShell>
  )
}
