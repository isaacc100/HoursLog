import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import { hasPermission, configToRecord } from '@/lib/permissions'

function resolveDateRange(period: string, startStr?: string | null, endStr?: string | null) {
  const today = new Date()
  today.setHours(0, 0, 0, 0)
  
  if (period === 'week') {
    const d = new Date(today)
    d.setDate(d.getDate() - d.getDay() + 1)
    return { start: d, end: today }
  }
  if (period === 'month') {
    return { start: new Date(today.getFullYear(), today.getMonth(), 1), end: today }
  }
  if (period === 'year') {
    return { start: new Date(today.getFullYear(), 0, 1), end: today }
  }
  if (period === 'custom') {
    return {
      start: startStr ? new Date(startStr) : undefined,
      end: endStr ? new Date(endStr) : undefined,
    }
  }
  return { start: undefined, end: undefined }
}

export async function GET(request: Request) {
  const session = await auth()
  if (!session?.user) return new NextResponse('Unauthorized', { status: 401 })
  
  const userId = (session.user as any).id
  const level = (session.user as any).permissionLevel
  const url = new URL(request.url)
  const period = url.searchParams.get('period') || 'all'
  const targetUserId = url.searchParams.get('user_id')
  
  let targetId = userId
  if (targetUserId) {
    let perms: Record<string, boolean> | null = null
    if (level >= 3 && level <= 6) {
      const cfg = await prisma.permissionLevelConfig.findUnique({ where: { level } })
      if (cfg) perms = configToRecord(cfg)
    }
    if (hasPermission(level, 'can_view_all_entries', perms)) {
      targetId = parseInt(targetUserId)
    }
  }
  
  const { start, end } = resolveDateRange(period, url.searchParams.get('start'), url.searchParams.get('end'))
  
  const where: any = { userId: targetId }
  if (start) where.date = { ...where.date, gte: start }
  if (end) where.date = { ...where.date, lte: end }
  
  const entries = await prisma.logEntry.findMany({
    where,
    orderBy: { date: 'desc' },
    include: { category: true, role: true, secondaryRoles: true },
  })
  
  const user = await prisma.user.findUnique({ where: { id: targetId } })
  
  // Generate CSV
  const rows = [['Date', 'Title', 'Category', 'Primary Role', 'Secondary Roles', 'Activity Hours', 'Travel Hours', 'Total Hours', 'Description', 'Notes']]
  for (const e of entries) {
    const secondary = e.secondaryRoles.map(r => r.name).join(', ')
    rows.push([
      new Date(e.date).toISOString().split('T')[0],
      e.title,
      e.category.name,
      e.role.name,
      secondary,
      e.hours.toFixed(2),
      (e.travelHours || 0).toFixed(2),
      (e.hours + (e.travelHours || 0)).toFixed(2),
      e.description || '',
      e.notes || '',
    ])
  }
  
  const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n')
  const filename = `hourslog_${user?.username || 'export'}_${period}.csv`
  
  return new NextResponse(csv, {
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="${filename}"`,
    },
  })
}
