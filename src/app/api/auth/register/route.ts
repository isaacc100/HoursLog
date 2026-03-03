import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { hashPassword } from '@/lib/helpers'

export async function POST(request: Request) {
  try {
    const body = await request.json()
    const { username, email, password, firstName, lastName, agreementAccepted } = body
    
    if (!username || !email || !password) {
      return NextResponse.json({ error: 'Username, email, and password are required.' }, { status: 400 })
    }
    
    if (username.length < 3 || username.length > 80) {
      return NextResponse.json({ error: 'Username must be between 3 and 80 characters.' }, { status: 400 })
    }
    
    if (password.length < 6) {
      return NextResponse.json({ error: 'Password must be at least 6 characters.' }, { status: 400 })
    }
    
    if (agreementAccepted !== true) {
      return NextResponse.json({ error: 'You must accept the data collection agreement.' }, { status: 400 })
    }
    
    // Check uniqueness
    const existingUser = await prisma.user.findFirst({
      where: { OR: [{ username }, { email }] },
    })
    if (existingUser) {
      if (existingUser.username === username) {
        return NextResponse.json({ error: 'Username already exists.' }, { status: 409 })
      }
      return NextResponse.json({ error: 'Email already registered.' }, { status: 409 })
    }
    
    const passwordHash = await hashPassword(password)
    
    const user = await prisma.user.create({
      data: { username, email, passwordHash, firstName: firstName || null, lastName: lastName || null },
    })
    
    await prisma.auditLog.create({
      data: { userId: user.id, action: 'registration', details: `New user registered: ${user.username}` },
    })
    
    return NextResponse.json({ message: 'Account created successfully.' }, { status: 201 })
  } catch (error) {
    console.error('Registration error:', error)
    return NextResponse.json({ error: 'An error occurred during registration.' }, { status: 500 })
  }
}
