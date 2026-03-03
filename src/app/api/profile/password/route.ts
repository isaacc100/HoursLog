import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import { compare } from 'bcryptjs'
import { hashPassword } from '@/lib/helpers'

export async function PUT(request: Request) {
  const session = await auth()
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  
  const userId = (session.user as any).id
  const body = await request.json()
  const { currentPassword, newPassword } = body
  
  if (!currentPassword || !newPassword) {
    return NextResponse.json({ error: 'Both passwords are required.' }, { status: 400 })
  }
  if (newPassword.length < 6) {
    return NextResponse.json({ error: 'New password must be at least 6 characters.' }, { status: 400 })
  }
  
  const user = await prisma.user.findUnique({ where: { id: userId } })
  if (!user) return NextResponse.json({ error: 'User not found.' }, { status: 404 })
  
  const valid = await compare(currentPassword, user.passwordHash)
  if (!valid) return NextResponse.json({ error: 'Current password is incorrect.' }, { status: 400 })
  
  const newHash = await hashPassword(newPassword)
  await prisma.user.update({ where: { id: userId }, data: { passwordHash: newHash } })
  
  await prisma.auditLog.create({
    data: { userId, action: 'password_changed', details: `User changed their password` },
  })
  
  return NextResponse.json({ message: 'Password changed successfully.' })
}
