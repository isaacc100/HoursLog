import { redirect } from 'next/navigation'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import PageShell from '@/components/PageShell'

export default async function CategoriesPage() {
  const session = await auth()
  if (!session?.user) redirect('/auth/login')
  
  const categories = await prisma.category.findMany({
    where: { isActive: true },
    orderBy: { name: 'asc' },
  })
  
  return (
    <PageShell>
      <h2 className="mb-4"><i className="bi bi-tags me-2"></i>Categories</h2>
      <div className="row g-3">
        {categories.map(cat => (
          <div key={cat.id} className="col-md-4 col-lg-3">
            <div className="card h-100 shadow-sm border-0">
              <div className="card-body">
                <div className="d-flex align-items-center gap-2 mb-2">
                  <span className="rounded-circle d-inline-block" style={{ width: 16, height: 16, backgroundColor: cat.color }}></span>
                  <h6 className="mb-0">{cat.name}</h6>
                </div>
                {cat.description && <p className="text-muted small mb-0">{cat.description}</p>}
              </div>
            </div>
          </div>
        ))}
        {categories.length === 0 && (
          <div className="col-12 text-center py-4 text-muted">No active categories.</div>
        )}
      </div>
    </PageShell>
  )
}
