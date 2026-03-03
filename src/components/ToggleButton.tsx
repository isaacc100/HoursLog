'use client'
import { useRouter } from 'next/navigation'
import { useState } from 'react'

export default function ToggleButton({ id, type, isActive }: { id: number; type: 'category' | 'role'; isActive: boolean }) {
  const router = useRouter()
  const [loading, setLoading] = useState(false)

  const handleToggle = async () => {
    setLoading(true)
    await fetch(`/api/admin/${type === 'category' ? 'categories' : 'roles'}/${id}/toggle`, { method: 'POST' })
    router.refresh()
    setLoading(false)
  }

  return (
    <button className={`btn btn-sm ${isActive ? 'btn-outline-warning' : 'btn-outline-success'}`} onClick={handleToggle} disabled={loading}>
      <i className={`bi ${isActive ? 'bi-pause-circle' : 'bi-play-circle'}`}></i>
    </button>
  )
}
