import "next-auth"

declare module "next-auth" {
  interface Session {
    user: {
      id: number
      username: string
      permissionLevel: number
      name?: string | null
      email?: string | null
      image?: string | null
    }
  }

  interface User {
    username: string
    permissionLevel: number
  }
}
