import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await auth()
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  
  const { id } = await params
  const entryId = parseInt(id)
  const userId = (session.user as any).id
  const level = (session.user as any).permissionLevel
  
  const entry = await prisma.logEntry.findUnique({ where: { id: entryId } })
  if (!entry) return NextResponse.redirect(new URL('/dashboard', request.url))
  if (entry.userId !== userId && level !== 7) {
    return NextResponse.redirect(new URL('/dashboard', request.url))
  }
  
  await prisma.logEntry.delete({ where: { id: entryId } })
  
  await prisma.auditLog.create({
    data: { userId, action: 'log_entry_deleted', details: `Deleted log entry: ${entry.title}` },
  })
  
  return NextResponse.redirect(new URL('/dashboard', request.url))
}
