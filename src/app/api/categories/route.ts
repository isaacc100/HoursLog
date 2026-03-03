import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

export async function GET() {
  const categories = await prisma.category.findMany({
    where: { isActive: true },
    orderBy: { name: 'asc' },
    select: { id: true, name: true, description: true, color: true },
  })
  return NextResponse.json(categories)
}
