import { NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import { hasPermission, hasAnySettingsPermission, configToRecord } from '@/lib/permissions'

export async function PUT(request: Request) {
  const session = await auth()
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const level = (session.user as any).permissionLevel
  let perms: Record<string, boolean> | null = null
  if (level >= 3 && level <= 6) {
    const cfg = await prisma.permissionLevelConfig.findUnique({ where: { level } })
    if (cfg) perms = configToRecord(cfg)
  }
  if (!hasAnySettingsPermission(level, perms)) return NextResponse.json({ error: 'Forbidden' }, { status: 403 })

  const body = await request.json()
  const data: any = {}

  if (hasPermission(level, 'can_edit_setting_display_name', perms) && body.allowDisplayNameChange !== undefined)
    data.allowDisplayNameChange = body.allowDisplayNameChange
  if (hasPermission(level, 'can_edit_setting_password_reset', perms) && body.allowPasswordReset !== undefined)
    data.allowPasswordReset = body.allowPasswordReset
  if (hasPermission(level, 'can_edit_setting_profile_pic', perms) && body.allowProfilePicChange !== undefined)
    data.allowProfilePicChange = body.allowProfilePicChange
  if (hasPermission(level, 'can_edit_setting_leaderboard_size', perms) && body.leaderboardSize !== undefined)
    data.leaderboardSize = parseInt(body.leaderboardSize)
  if (hasPermission(level, 'can_edit_setting_footer_text', perms) && body.footerText !== undefined)
    data.footerText = body.footerText

  let settings = await prisma.appSettings.findFirst()
  if (!settings) {
    settings = await prisma.appSettings.create({ data: { ...data } })
  } else {
    settings = await prisma.appSettings.update({ where: { id: settings.id }, data })
  }

  await prisma.auditLog.create({
    data: { userId: (session.user as any).id, action: 'settings_updated', details: `Updated settings: ${Object.keys(data).join(', ')}` },
  })

  return NextResponse.json({ message: 'Settings saved.' })
}
