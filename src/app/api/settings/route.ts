import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

export async function GET() {
  let settings = await prisma.appSettings.findFirst()
  if (!settings) {
    settings = await prisma.appSettings.create({
      data: { allowDisplayNameChange: true, allowPasswordReset: true, allowProfilePicChange: true, leaderboardSize: 50 },
    })
  }
  return NextResponse.json(settings)
}
