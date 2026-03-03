import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

export async function GET() {
  const roles = await prisma.role.findMany({
    where: { isActive: true },
    orderBy: { name: 'asc' },
    select: { id: true, name: true, description: true },
  })
  return NextResponse.json(roles)
}
