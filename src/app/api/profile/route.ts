import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'

export async function GET() {
  const session = await auth()
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  
  const user = await prisma.user.findUnique({
    where: { id: (session.user as any).id },
    select: {
      id: true, username: true, email: true, displayName: true, firstName: true,
      lastName: true, permissionLevel: true, createdAt: true, profilePic: true,
    },
  })
  return NextResponse.json(user)
}

export async function PUT(request: Request) {
  const session = await auth()
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  
  const userId = (session.user as any).id
  const body = await request.json()
  
  if (body.displayName !== undefined) {
    await prisma.user.update({
      where: { id: userId },
      data: { displayName: body.displayName || null },
    })
    await prisma.auditLog.create({
      data: { userId, action: 'profile_updated', details: `Updated display name` },
    })
    return NextResponse.json({ message: 'Display name updated.' })
  }
  
  return NextResponse.json({ error: 'No changes.' }, { status: 400 })
}

export async function DELETE(request: Request) {
  const session = await auth()
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  
  const userId = (session.user as any).id
  const body = await request.json()
  
  if (body.confirmation !== 'I want to delete my data') {
    return NextResponse.json({ error: 'Invalid confirmation.' }, { status: 400 })
  }
  
  const user = await prisma.user.findUnique({ where: { id: userId } })
  if (!user) return NextResponse.json({ error: 'User not found.' }, { status: 404 })
  
  // Prevent last admin from deleting
  if (user.permissionLevel === 7) {
    const adminCount = await prisma.user.count({ where: { permissionLevel: 7 } })
    if (adminCount <= 1) {
      return NextResponse.json({ error: 'You are the only administrator. Appoint another admin first.' }, { status: 400 })
    }
  }
  
  await prisma.user.delete({ where: { id: userId } })
  return NextResponse.json({ message: 'Account deleted.' })
}
