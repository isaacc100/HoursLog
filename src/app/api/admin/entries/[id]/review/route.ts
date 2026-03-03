import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import { hasPermission, configToRecord } from '@/lib/permissions'

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await auth()
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const userId = (session.user as any).id
  const level = (session.user as any).permissionLevel
  let perms: Record<string, boolean> | null = null
  if (level >= 3 && level <= 6) {
    const cfg = await prisma.permissionLevelConfig.findUnique({ where: { level } })
    if (cfg) perms = configToRecord(cfg)
  }

  const { id } = await params
  const body = await request.json()
  const { action, reason } = body

  if (action === 'action' && !hasPermission(level, 'can_action_entries', perms))
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  if (action === 'deny' && !hasPermission(level, 'can_deny_entries', perms))
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })

  const data: any = { reviewedById: userId, reviewedAt: new Date() }
  if (action === 'action') { data.reviewStatus = 'actioned'; data.denialReason = null }
  else if (action === 'deny') { data.reviewStatus = 'denied'; data.denialReason = reason || null }
  else if (action === 'reset') { data.reviewStatus = 'active'; data.denialReason = null; data.reviewedById = null; data.reviewedAt = null }

  await prisma.logEntry.update({ where: { id: parseInt(id) }, data })
  await prisma.auditLog.create({
    data: { userId, action: `entry_${action}`, details: `${action} entry #${id}${reason ? ': ' + reason : ''}` },
  })

  return NextResponse.json({ message: 'Updated.' })
}
