import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import { ALL_PERMISSIONS, hasPermission, configToRecord } from '@/lib/permissions'

export async function GET() {
  const session = await auth()
  if (!session?.user) return NextResponse.json({})

  const level = (session.user as any).permissionLevel
  let perms: Record<string, boolean> | null = null
  if (level >= 3 && level <= 6) {
    const cfg = await prisma.permissionLevelConfig.findUnique({ where: { level } })
    if (cfg) perms = configToRecord(cfg)
  }

  const result: Record<string, boolean> = {}
  for (const p of ALL_PERMISSIONS) {
    result[p] = hasPermission(level, p, perms)
  }
  return NextResponse.json(result)
}
