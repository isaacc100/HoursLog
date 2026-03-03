import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await auth()
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  
  const { id } = await params
  const entryId = parseInt(id)
  const userId = (session.user as any).id
  const level = (session.user as any).permissionLevel
  
  const entry = await prisma.logEntry.findUnique({
    where: { id: entryId },
    include: { category: true, role: true, secondaryRoles: true },
  })
  
  if (!entry) return NextResponse.json({ error: 'Entry not found.' }, { status: 404 })
  if (entry.userId !== userId && level !== 7) {
    return NextResponse.json({ error: 'Permission denied.' }, { status: 403 })
  }
  
  return NextResponse.json({
    ...entry,
    secondaryRoleIds: entry.secondaryRoles.map(r => r.id),
  })
}

export async function PUT(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await auth()
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  
  const { id } = await params
  const entryId = parseInt(id)
  const userId = (session.user as any).id
  const level = (session.user as any).permissionLevel
  const body = await request.json()
  
  const entry = await prisma.logEntry.findUnique({ where: { id: entryId } })
  if (!entry) return NextResponse.json({ error: 'Entry not found.' }, { status: 404 })
  if (entry.userId !== userId && level !== 7) {
    return NextResponse.json({ error: 'Permission denied.' }, { status: 403 })
  }
  
  const { title, description, notes, hours, travelHours, date, categoryId, roleId, secondaryRoleIds } = body
  
  await prisma.logEntry.update({
    where: { id: entryId },
    data: {
      title, description: description || null, notes: notes || null,
      hours: parseFloat(hours), travelHours: parseFloat(travelHours) || 0,
      date: new Date(date), categoryId: parseInt(categoryId), roleId: parseInt(roleId),
      secondaryRoles: { set: (secondaryRoleIds || []).map((rid: number) => ({ id: rid })) },
    },
  })
  
  await prisma.auditLog.create({
    data: { userId, action: 'log_entry_updated', details: `Updated log entry: ${title}` },
  })
  
  return NextResponse.json({ message: 'Entry updated.' })
}

export async function DELETE(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await auth()
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  
  const { id } = await params
  const entryId = parseInt(id)
  const userId = (session.user as any).id
  const level = (session.user as any).permissionLevel
  
  const entry = await prisma.logEntry.findUnique({ where: { id: entryId } })
  if (!entry) return NextResponse.json({ error: 'Entry not found.' }, { status: 404 })
  if (entry.userId !== userId && level !== 7) {
    return NextResponse.json({ error: 'Permission denied.' }, { status: 403 })
  }
  
  await prisma.logEntry.delete({ where: { id: entryId } })
  
  await prisma.auditLog.create({
    data: { userId, action: 'log_entry_deleted', details: `Deleted log entry: ${entry.title}` },
  })
  
  return NextResponse.json({ message: 'Entry deleted.' })
}
