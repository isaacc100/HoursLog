import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import { hasPermission, configToRecord } from '@/lib/permissions'
import { getDisplayName } from '@/lib/helpers'

function resolveDateRange(period: string, startStr?: string | null, endStr?: string | null) {
  const today = new Date()
  today.setHours(0, 0, 0, 0)
  if (period === 'week') {
    const d = new Date(today); d.setDate(d.getDate() - d.getDay() + 1)
    return { start: d, end: today }
  }
  if (period === 'month') return { start: new Date(today.getFullYear(), today.getMonth(), 1), end: today }
  if (period === 'year') return { start: new Date(today.getFullYear(), 0, 1), end: today }
  if (period === 'custom') return { start: startStr ? new Date(startStr) : undefined, end: endStr ? new Date(endStr) : undefined }
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
    if (hasPermission(level, 'can_view_all_entries', perms)) targetId = parseInt(targetUserId)
  }
  
  const { start, end } = resolveDateRange(period, url.searchParams.get('start'), url.searchParams.get('end'))
  const where: any = { userId: targetId }
  if (start) where.date = { ...where.date, gte: start }
  if (end) where.date = { ...where.date, lte: end }
  
  const entries = await prisma.logEntry.findMany({
    where, orderBy: { date: 'desc' },
    include: { category: true, role: true, secondaryRoles: true },
  })
  
  const user = await prisma.user.findUnique({ where: { id: targetId } })
  const userName = user ? getDisplayName(user) : 'Unknown'
  
  // Calculate summary
  const totalActivity = entries.reduce((s, e) => s + e.hours, 0)
  const totalTravel = entries.reduce((s, e) => s + (e.travelHours || 0), 0)
  const totalHours = totalActivity + totalTravel
  
  const periodLabels: Record<string, string> = { all: 'All Time', week: 'This Week', month: 'This Month', year: 'This Year', custom: 'Custom Range' }
  
  // Use jsPDF to generate the PDF
  const { jsPDF } = await import('jspdf')
  const autoTable = (await import('jspdf-autotable')).default
  
  const doc = new jsPDF()
  
  // Header
  doc.setFontSize(20)
  doc.setTextColor(0, 123, 255)
  doc.text('HoursLog Report', 14, 22)
  doc.setFontSize(12)
  doc.setTextColor(100)
  doc.text(`${userName} — ${periodLabels[period] || period}`, 14, 30)
  if (start || end) {
    const range = `${start ? new Date(start).toLocaleDateString() : 'Start'} to ${end ? new Date(end).toLocaleDateString() : 'Present'}`
    doc.text(range, 14, 37)
  }
  
  // Summary
  doc.setFontSize(14)
  doc.setTextColor(0)
  doc.text('Summary', 14, 50)
  doc.setFontSize(11)
  doc.text(`Total Hours: ${totalHours.toFixed(1)}`, 14, 58)
  doc.text(`Activity Hours: ${totalActivity.toFixed(1)}`, 14, 65)
  doc.text(`Travel Hours: ${totalTravel.toFixed(1)}`, 14, 72)
  doc.text(`Total Entries: ${entries.length}`, 14, 79)
  
  // Entries table
  const tableData = entries.map(e => [
    new Date(e.date).toLocaleDateString('en-GB'),
    e.title.substring(0, 40),
    e.category.name,
    e.role.name,
    e.hours.toFixed(1),
    (e.travelHours || 0).toFixed(1),
    (e.hours + (e.travelHours || 0)).toFixed(1),
  ])
  
  autoTable(doc, {
    startY: 88,
    head: [['Date', 'Title', 'Category', 'Role', 'Activity', 'Travel', 'Total']],
    body: tableData,
    styles: { fontSize: 8 },
    headStyles: { fillColor: [0, 123, 255] },
  })
  
  const pdfBytes = doc.output('arraybuffer')
  const filename = `hourslog_${user?.username || 'export'}_${period}.pdf`
  
  return new NextResponse(Buffer.from(pdfBytes), {
    headers: {
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="${filename}"`,
    },
  })
}
