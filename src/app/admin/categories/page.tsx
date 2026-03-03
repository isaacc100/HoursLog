import { redirect } from 'next/navigation'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import PageShell from '@/components/PageShell'
import Link from 'next/link'
import { hasPermission, configToRecord } from '@/lib/permissions'
import ToggleButton from '@/components/ToggleButton'

export default async function AdminCategoriesPage() {
  const session = await auth()
  if (!session?.user) redirect('/auth/login')
  const level = (session.user as any).permissionLevel
  let perms: Record<string, boolean> | null = null
  if (level >= 3 && level <= 6) {
    const cfg = await prisma.permissionLevelConfig.findUnique({ where: { level } })
    if (cfg) perms = configToRecord(cfg)
  }
  if (!hasPermission(level, 'can_manage_categories', perms)) redirect('/')

  const categories = await prisma.category.findMany({ orderBy: { name: 'asc' } })

  return (
    <PageShell>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2><i className="bi bi-tags me-2"></i>Manage Categories</h2>
        <Link href="/admin/categories/new" className="btn btn-primary"><i className="bi bi-plus-circle me-1"></i>Add Category</Link>
      </div>
      <div className="card shadow-sm">
        <div className="table-responsive">
          <table className="table table-hover mb-0">
            <thead className="table-light"><tr><th>Color</th><th>Name</th><th>Description</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody>
              {categories.map(c => (
                <tr key={c.id} className={c.isActive ? '' : 'table-secondary'}>
                  <td><span className="d-inline-block rounded-circle" style={{ width: 24, height: 24, backgroundColor: c.color }}></span></td>
                  <td><strong>{c.name}</strong></td>
                  <td>{c.description || <span className="text-muted">—</span>}</td>
                  <td><span className={`badge ${c.isActive ? 'bg-success' : 'bg-secondary'}`}>{c.isActive ? 'Active' : 'Inactive'}</span></td>
                  <td>
                    <div className="btn-group btn-group-sm">
                      <Link href={`/admin/categories/${c.id}/edit`} className="btn btn-outline-primary"><i className="bi bi-pencil"></i></Link>
                      <ToggleButton id={c.id} type="category" isActive={c.isActive} />
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
