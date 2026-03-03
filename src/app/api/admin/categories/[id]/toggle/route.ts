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
  if (!hasPermission(level, 'can_manage_categories', perms))
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })

  const { id } = await params
  const cat = await prisma.category.findUnique({ where: { id: parseInt(id) } })
  if (!cat) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  await prisma.category.update({ where: { id: parseInt(id) }, data: { isActive: !cat.isActive } })
  return NextResponse.json({ message: 'Toggled.' })
}
