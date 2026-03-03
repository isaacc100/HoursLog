import { redirect } from 'next/navigation'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import PageShell from '@/components/PageShell'

export default async function RolesPage() {
  const session = await auth()
  if (!session?.user) redirect('/auth/login')
  
  const roles = await prisma.role.findMany({
    where: { isActive: true },
    orderBy: { name: 'asc' },
  })
  
  return (
    <PageShell>
      <h2 className="mb-4"><i className="bi bi-people me-2"></i>Roles</h2>
      <div className="row g-3">
        {roles.map(role => (
          <div key={role.id} className="col-md-4 col-lg-3">
            <div className="card h-100 shadow-sm border-0">
              <div className="card-body">
                <h6 className="mb-1"><i className="bi bi-person-badge me-1 text-primary"></i>{role.name}</h6>
                {role.description && <p className="text-muted small mb-0">{role.description}</p>}
              </div>
            </div>
          </div>
        ))}
        {roles.length === 0 && (
          <div className="col-12 text-center py-4 text-muted">No active roles.</div>
        )}
      </div>
    </PageShell>
  )
}
