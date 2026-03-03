import { auth } from '@/lib/auth'
import prisma from '@/lib/prisma'
import Navbar from './Navbar'
import Footer from './Footer'
import { configToRecord } from '@/lib/permissions'

export default async function PageShell({ children }: { children: React.ReactNode }) {
  const session = await auth()
  let navUser = null
  let permissions = null
  let footerText = ''
  
  try {
    const settings = await prisma.appSettings.findFirst()
    footerText = settings?.footerText || ''
  } catch {
    // Settings may not exist yet; use defaults
  }
  
  if (session?.user) {
    const user = await prisma.user.findUnique({
      where: { id: (session.user as any).id },
      select: { id: true, username: true, permissionLevel: true, displayName: true, firstName: true, lastName: true },
    })
    if (user) {
      navUser = user
      if (user.permissionLevel >= 3 && user.permissionLevel <= 6) {
        const config = await prisma.permissionLevelConfig.findUnique({ where: { level: user.permissionLevel } })
        if (config) permissions = configToRecord(config)
      }
    }
  }
  
  return (
    <>
      <Navbar user={navUser} permissions={permissions} />
      <main className="container py-4">
        {children}
      </main>
      <Footer footerText={footerText} />
    </>
  )
}
