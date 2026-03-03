import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'

export async function GET() {
  const session = await auth()
  if (!session?.user || (session.user as any).permissionLevel !== 7) {
    return NextResponse.json([], { status: 403 })
  }

  let configs = await prisma.permissionLevelConfig.findMany({
    where: { level: { in: [3, 4, 5, 6] } },
    orderBy: { level: 'asc' },
  })

  // Seed if empty
  if (configs.length < 4) {
    for (let level = 3; level <= 6; level++) {
      const exists = configs.find(c => c.level === level)
      if (!exists) {
        await prisma.permissionLevelConfig.create({ data: { level, name: `Custom Level ${level}` } })
      }
    }
    configs = await prisma.permissionLevelConfig.findMany({
      where: { level: { in: [3, 4, 5, 6] } },
      orderBy: { level: 'asc' },
    })
  }

  return NextResponse.json(configs)
}

export async function PUT(request: Request) {
  const session = await auth()
  if (!session?.user || (session.user as any).permissionLevel !== 7) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }

  const configs = await request.json()
  for (const cfg of configs) {
    if (cfg.level < 3 || cfg.level > 6) continue
    await prisma.permissionLevelConfig.upsert({
      where: { level: cfg.level },
      create: cfg,
      update: cfg,
    })
  }

  await prisma.auditLog.create({
    data: { userId: (session.user as any).id, action: 'permissions_updated', details: 'Updated permission level configurations' },
  })

  return NextResponse.json({ message: 'Permissions saved.' })
}
