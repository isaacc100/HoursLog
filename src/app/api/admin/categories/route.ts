import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import { hasPermission, configToRecord } from '@/lib/permissions'

export async function POST(request: Request) {
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

  const body = await request.json()
  const { name, description, color } = body
  if (!name) return NextResponse.json({ error: 'Name is required.' }, { status: 400 })

  try {
    const cat = await prisma.category.create({ data: { name, description: description || null, color: color || '#007bff' } })
    await prisma.auditLog.create({ data: { userId: (session.user as any).id, action: 'category_created', details: `Created category: ${name}` } })
    return NextResponse.json(cat, { status: 201 })
  } catch {
    return NextResponse.json({ error: 'Category name already exists.' }, { status: 409 })
  }
}
