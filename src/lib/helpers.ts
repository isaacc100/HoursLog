import { hash } from "bcryptjs"
import crypto from "crypto"

export function getDisplayName(user: {
  displayName?: string | null
  firstName?: string | null
  lastName?: string | null
  username: string
}): string {
  if (user.displayName) return user.displayName
  if (user.firstName || user.lastName) {
    return `${user.firstName || ''} ${user.lastName || ''}`.trim()
  }
  return user.username
}

export function getInitials(user: {
  firstName?: string | null
  lastName?: string | null
  displayName?: string | null
  username: string
}): string {
  if (user.firstName && user.lastName) {
    return (user.firstName[0] + user.lastName[0]).toUpperCase()
  }
  if (user.displayName) {
    const parts = user.displayName.split(' ')
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase()
    return user.displayName[0].toUpperCase()
  }
  return user.username[0].toUpperCase()
}

export function getAvatarColor(userId: number): string {
  const colors = [
    '#007bff', '#28a745', '#dc3545', '#ffc107', '#17a2b8',
    '#6610f2', '#e83e8c', '#fd7e14', '#20c997', '#6f42c1',
  ]
  const hashVal = parseInt(crypto.createHash('md5').update(String(userId)).digest('hex'), 16)
  return colors[hashVal % colors.length]
}

export async function hashPassword(password: string): Promise<string> {
  return hash(password, 12)
}

export function formatDate(date: Date | string): string {
  const d = typeof date === 'string' ? new Date(date) : date
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
}

export function formatDateTime(date: Date | string): string {
  const d = typeof date === 'string' ? new Date(date) : date
  return d.toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}
