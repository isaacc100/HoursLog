import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import { hasPermission, configToRecord } from '@/lib/permissions'

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await auth()
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  
  const adminLevel = (session.user as any).permissionLevel
  let perms: Record<string, boolean> | null = null
  if (adminLevel >= 3 && adminLevel <= 6) {
    const cfg = await prisma.permissionLevelConfig.findUnique({ where: { level: adminLevel } })
    if (cfg) perms = configToRecord(cfg)
  }
  if (!hasPermission(adminLevel, 'can_change_user_level', perms))
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  
  const { id } = await params
  const userId = parseInt(id)
  const body = await request.json()
  const newLevel = parseInt(body.level)
  
  if (isNaN(newLevel) || newLevel < 0 || newLevel > 7) {
    return NextResponse.json({ error: 'Invalid level.' }, { status: 400 })
  }
  
  const user = await prisma.user.findUnique({ where: { id: userId } })
  if (!user) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  
  await prisma.user.update({ where: { id: userId }, data: { permissionLevel: newLevel } })
  
  await prisma.auditLog.create({
    data: {
      userId: (session.user as any).id,
      action: 'user_level_changed',
      details: `Changed ${user.username} level from ${user.permissionLevel} to ${newLevel}`,
    },
  })
  
  return NextResponse.json({ message: 'Level updated.' })
}
