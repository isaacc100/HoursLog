import NextAuth from "next-auth"
import CredentialsProvider from "next-auth/providers/credentials"
import { compare } from "bcryptjs"
import prisma from "./prisma"

export const { handlers, signIn, signOut, auth } = NextAuth({
  session: { strategy: "jwt" },
  pages: {
    signIn: "/auth/login",
  },
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id
        token.username = (user as any).username
        token.permissionLevel = (user as any).permissionLevel
      }
      return token
    },
    async session({ session, token }) {
      if (session.user) {
        (session.user as any).id = token.id as number
        (session.user as any).username = token.username as string
        (session.user as any).permissionLevel = token.permissionLevel as number
      }
      return session
    },
  },
  providers: [
    CredentialsProvider({
      name: "credentials",
      credentials: {
        username: { label: "Username", type: "text" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.username || !credentials?.password) return null

        const user = await prisma.user.findUnique({
          where: { username: credentials.username as string },
        })

        if (!user) return null
        if (user.permissionLevel <= 0) return null

        const isValid = await compare(credentials.password as string, user.passwordHash)
        if (!isValid) return null

        // Update last login
        await prisma.user.update({
          where: { id: user.id },
          data: { lastLogin: new Date() },
        })

        // Create audit log
        await prisma.auditLog.create({
          data: {
            userId: user.id,
            action: 'login',
            details: `User ${user.username} logged in`,
          },
        })

        return {
          id: String(user.id),
          name: user.displayName || user.username,
          email: user.email,
          username: user.username,
          permissionLevel: user.permissionLevel,
        } as any
      },
    }),
  ],
})
