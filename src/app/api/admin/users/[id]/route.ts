import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import { hasPermission, configToRecord } from '@/lib/permissions'

export async function DELETE(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await auth()
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  
  const level = (session.user as any).permissionLevel
  let perms: Record<string, boolean> | null = null
  if (level >= 3 && level <= 6) {
    const cfg = await prisma.permissionLevelConfig.findUnique({ where: { level } })
    if (cfg) perms = configToRecord(cfg)
  }
  if (!hasPermission(level, 'can_delete_users', perms))
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  
  const { id } = await params
  const userId = parseInt(id)
  const user = await prisma.user.findUnique({ where: { id: userId } })
  if (!user) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  
  if (user.permissionLevel === 7) {
    const adminCount = await prisma.user.count({ where: { permissionLevel: 7 } })
    if (adminCount <= 1) return NextResponse.json({ error: 'Cannot delete the only admin.' }, { status: 400 })
  }
  
  await prisma.user.delete({ where: { id: userId } })
  
  await prisma.auditLog.create({
    data: {
      userId: (session.user as any).id,
      action: 'user_deleted',
      details: `Deleted user ${user.username}`,
    },
  })
  
  return NextResponse.json({ message: 'User deleted.' })
}
