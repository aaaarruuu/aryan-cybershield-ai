import { useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { Badge } from '../components/ui'

const NAV = [
  ['/', 'Dashboard', false], ['/intel', 'Threat Intelligence', false], ['/phishing', 'Phishing Analysis', false],
  ['/logs', 'Log Analyzer', false], ['/investigate', 'AI Investigation Center', false], ['/incidents', 'Incidents', false],
  ['/knowledge', 'Knowledge Base', false], ['/approvals', 'Response Approvals', false], ['/reports', 'Analytics & Reports', false],
  ['/profile', 'My Profile', false], ['/admin', 'Admin Settings', true], ['/about', 'About Project', false],
]

export default function AppLayout() {
  const { user, isAdmin, logout } = useAuth()
  const nav = useNavigate()
  const [open, setOpen] = useState(false)
  const links = NAV.filter(([, , adminOnly]) => !adminOnly || isAdmin)
  return (
    <div className="flex h-full">
      <aside className={`${open ? 'fixed inset-0 z-40 flex' : 'hidden'} w-64 shrink-0 flex-col border-r border-navy-600/60 bg-navy-900 md:static md:flex`}>
        <div className="border-b border-navy-600/60 p-5">
          <div className="flex items-center gap-2">
            <span aria-hidden className="grid h-8 w-8 place-items-center rounded-lg bg-cyan-500 font-bold text-navy-950">A</span>
            <div><p className="text-sm font-bold tracking-wide text-white">ARYAN CYBERSHIELD AI</p><p className="text-[11px] text-cyan-400">Developed by Aryan</p></div>
          </div>
        </div>
        <nav aria-label="Main" className="flex-1 space-y-0.5 overflow-y-auto p-3">
          {links.map(([to, text]) => (
            <NavLink key={to} to={to} end={to === '/'} onClick={() => setOpen(false)}
              className={({ isActive }) => `block rounded-lg px-3 py-2 text-sm ${isActive ? 'bg-cyan-500/15 font-medium text-cyan-300' : 'text-slate-400 hover:bg-navy-700 hover:text-slate-100'}`}>{text}</NavLink>
          ))}
        </nav>
        <div className="border-t border-navy-600/60 p-4 text-sm">
          <p className="truncate font-medium text-slate-200">{user.full_name}</p>
          <div className="mt-1 flex items-center justify-between"><Badge value={user.role === 'admin' ? 'open' : 'unknown'} className="!capitalize">{user.role}</Badge>
            <button className="text-xs text-slate-400 underline hover:text-white" onClick={async () => { await logout(); nav('/login') }}>Sign out</button></div>
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center gap-3 border-b border-navy-600/60 bg-navy-900/60 px-4 py-3 md:hidden">
          <button aria-label="Toggle menu" className="btn-ghost !px-3" onClick={() => setOpen(!open)}>☰</button>
          <span className="text-sm font-semibold text-white">ARYAN CYBERSHIELD AI</span>
        </header>
        <main className="flex-1 overflow-y-auto p-4 md:p-8"><Outlet /></main>
      </div>
    </div>
  )
}
