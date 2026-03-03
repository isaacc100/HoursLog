import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import { hasPermission, configToRecord } from '@/lib/permissions'

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const role = await prisma.role.findUnique({ where: { id: parseInt(id) } })
  if (!role) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  return NextResponse.json(role)
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
  if (!hasPermission(level, 'can_manage_roles', perms)) return NextResponse.json({ error: 'Forbidden' }, { status: 403 })

  const { id } = await params
  const body = await request.json()
  await prisma.role.update({ where: { id: parseInt(id) }, data: { name: body.name, description: body.description || null } })
  await prisma.auditLog.create({ data: { userId: (session.user as any).id, action: 'role_updated', details: `Updated role: ${body.name}` } })
  return NextResponse.json({ message: 'Updated.' })
}
