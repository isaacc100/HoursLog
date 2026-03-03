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
  if (!hasPermission(level, 'can_manage_roles', perms)) return NextResponse.json({ error: 'Forbidden' }, { status: 403 })

  const body = await request.json()
  if (!body.name) return NextResponse.json({ error: 'Name required.' }, { status: 400 })

  try {
    const role = await prisma.role.create({ data: { name: body.name, description: body.description || null } })
    await prisma.auditLog.create({ data: { userId: (session.user as any).id, action: 'role_created', details: `Created role: ${body.name}` } })
    return NextResponse.json(role, { status: 201 })
  } catch { return NextResponse.json({ error: 'Role name already exists.' }, { status: 409 }) }
}
