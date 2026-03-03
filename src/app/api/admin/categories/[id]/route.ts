import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import { hasPermission, configToRecord } from '@/lib/permissions'

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const cat = await prisma.category.findUnique({ where: { id: parseInt(id) } })
  if (!cat) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  return NextResponse.json(cat)
}

export async function PUT(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await auth()
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const level = (session.user as any).permissionLevel
  let perms: Record<string, boolean> | null = null
  if (level >= 3 && level <= 6) {
    const cfg = await prisma.permissionLevelConfig.findUnique({ where: { level } })
    if (cfg) perms = configToRecord(cfg)
  }
  if (!hasPermission(level, 'can_manage_categories', perms))
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })

  const { id } = await params
  const body = await request.json()
  await prisma.category.update({ where: { id: parseInt(id) }, data: { name: body.name, description: body.description || null, color: body.color } })
  await prisma.auditLog.create({ data: { userId: (session.user as any).id, action: 'category_updated', details: `Updated category: ${body.name}` } })
  return NextResponse.json({ message: 'Updated.' })
}
