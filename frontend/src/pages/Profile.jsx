import { useState } from 'react'
import { api } from '../services/api'
import { useAuth } from '../context/AuthContext'
import { Badge, ErrorBox, Field, Notice, PageHeader, Section, fmt } from '../components/ui'

export default function Profile() {
  const { user, refresh, logout } = useAuth()
  const [name, setName] = useState(user.full_name)
  const [pw, setPw] = useState('')
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  const save = async (e) => {
    e.preventDefault(); setError(''); setMsg('')
    if (name.trim().length < 2) return setError('Name must be at least 2 characters')
    if (pw && (pw.length < 10 || !/[A-Za-z]/.test(pw) || !/\d/.test(pw))) return setError('Password must be 10+ characters with letters and digits')
    try {
      await api.updateMe({ full_name: name.trim(), ...(pw ? { password: pw } : {}) })
      if (pw) { await logout(); return }   // changing the password revokes existing tokens
      await refresh(); setMsg('Profile updated')
    } catch (err) { setError(err.message) }
  }
  return (
    <>
      <PageHeader title="My Profile" />
      <div className="max-w-xl"><Section title="Account">
        <div className="mb-4 space-y-1 text-sm text-slate-300"><p>{user.email}</p><p>Role: <Badge value={user.role === 'admin' ? 'open' : 'unknown'}>{user.role}</Badge></p><p className="text-xs text-slate-500">Member since {fmt(user.created_at)}</p></div>
        <form onSubmit={save} className="space-y-4"><ErrorBox message={error} />{msg && <Notice tone="ok">{msg}</Notice>}
          <Field label="Full name" id="n"><input id="n" className="input" value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <Field label="New password" id="p" hint="Leave blank to keep your current password. Changing it signs you out everywhere."><input id="p" type="password" autoComplete="new-password" className="input" value={pw} onChange={(e) => setPw(e.target.value)} /></Field>
          <button className="btn-primary">Save changes</button></form>
      </Section></div>
    </>
  )
}
