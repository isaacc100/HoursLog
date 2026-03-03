import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import { hasPermission, configToRecord } from '@/lib/permissions'

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await auth()
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  
  const level = (session.user as any).permissionLevel
  let perms: Record<string, boolean> | null = null
  if (level >= 3 && level <= 6) {
    const cfg = await prisma.permissionLevelConfig.findUnique({ where: { level } })
    if (cfg) perms = configToRecord(cfg)
  }
  if (!hasPermission(level, 'can_deactivate_users', perms))
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  
  const { id } = await params
  const userId = parseInt(id)
  const user = await prisma.user.findUnique({ where: { id: userId } })
  if (!user) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  
  const newLevel = user.permissionLevel > 0 ? 0 : 1
  await prisma.user.update({ where: { id: userId }, data: { permissionLevel: newLevel } })
  
  await prisma.auditLog.create({
    data: {
      userId: (session.user as any).id,
      action: newLevel > 0 ? 'user_activated' : 'user_deactivated',
      details: `${newLevel > 0 ? 'Activated' : 'Deactivated'} user ${user.username}`,
    },
  })
  
  return NextResponse.json({ message: 'User updated.' })
}
