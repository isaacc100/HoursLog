'use client'
import { useState } from 'react'

export default function FlashMessage({ messages }: { messages: { type: string; text: string }[] }) {
  const [visible, setVisible] = useState(messages.map(() => true))
  
  return (
    <>
      {messages.map((msg, i) => visible[i] && (
        <div key={i} className={`alert alert-${msg.type} alert-dismissible fade show`} role="alert">
          {msg.text}
          <button type="button" className="btn-close" aria-label="Close" onClick={() => setVisible(v => v.map((x, j) => j === i ? false : x))}></button>
        </div>
      ))}
    </>
  )
}
