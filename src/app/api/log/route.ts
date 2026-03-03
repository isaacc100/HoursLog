import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'

export async function POST(request: Request) {
  const session = await auth()
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  
  const userId = (session.user as any).id
  const body = await request.json()
  const { title, description, notes, hours, travelHours, date, categoryId, roleId, secondaryRoleIds } = body
  
  if (!title || !hours || !date || !categoryId || !roleId) {
    return NextResponse.json({ error: 'Missing required fields.' }, { status: 400 })
  }
  
  if (hours < 0.1 || hours > 24) {
    return NextResponse.json({ error: 'Activity hours must be between 0.1 and 24.' }, { status: 400 })
  }
  
  try {
    const entry = await prisma.logEntry.create({
      data: {
        userId,
        title,
        description: description || null,
        notes: notes || null,
        hours: parseFloat(hours),
        travelHours: parseFloat(travelHours) || 0,
        date: new Date(date),
        categoryId: parseInt(categoryId),
        roleId: parseInt(roleId),
        secondaryRoles: secondaryRoleIds?.length ? { connect: secondaryRoleIds.map((id: number) => ({ id })) } : undefined,
      },
    })
    
    await prisma.auditLog.create({
      data: {
        userId,
        action: 'log_entry_created',
        details: `Created log entry: ${title} (${hours}h activity + ${travelHours || 0}h travel)`,
      },
    })
    
    return NextResponse.json({ id: entry.id, message: 'Entry created.' }, { status: 201 })
  } catch (error) {
    console.error('Create entry error:', error)
    return NextResponse.json({ error: 'Failed to create entry.' }, { status: 500 })
  }
}
