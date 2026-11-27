import { useState } from 'react'
import { api } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { useAuth } from '../context/AuthContext'
import { Async, Badge, ErrorBox, PageHeader, Section, Tabs, fmt, label } from '../components/ui'

export default function Admin() {
  const { user } = useAuth()
  const [tab, setTab] = useState('Settings')
  const [error, setError] = useState('')
  const settings = useAsync(() => api.adminSettings(), [])
  const users = useAsync(() => api.users(), [])
  const audit = useAsync(() => api.audit(), [])
  const update = async (u, patch) => { setError(''); try { await api.updateUser(u.id, { role: u.role, is_active: u.is_active, ...patch }); users.reload() } catch (e) { setError(e.message) } }
  return (
    <>
      <PageHeader title="Admin Settings" subtitle="Platform configuration (read-only; secrets are never displayed), user management and the audit trail." />
      <Tabs tabs={['Settings', 'Users', 'Audit log']} value={tab} onChange={setTab} />
      {tab === 'Settings' && <Async state={settings}>{(s) => <Section title="Configuration"><dl className="grid gap-3 text-sm sm:grid-cols-2">
        {[['Environment', s.environment], ['Demo mode', s.demo_mode ? 'On (sample intelligence, no paid APIs)' : 'Off (live services)'], ['VirusTotal key configured', s.virustotal_configured ? 'Yes' : 'No'], ['Analysis engine', s.analysis_engine], ['Response execution', s.response_execution_mode], ['Upload limit', `${s.upload_max_mb} MB`], ['Token lifetime', `${s.access_token_minutes} min`], ['Users', s.users], ['Knowledge documents', s.knowledge_documents], ['CORS origins', s.cors_origins.join(', ')]].map(([k, v]) => <div key={k} className="rounded-lg bg-navy-900 p-3"><dt className="text-xs text-slate-500">{k}</dt><dd className="text-slate-100">{String(v)}</dd></div>)}</dl>
        <p className="mt-3 text-xs text-slate-500">Change settings through environment variables (see .env.example) and restart the backend.</p></Section>}</Async>}
      {tab === 'Users' && <Section title="Users"><ErrorBox message={error} /><Async state={users}>{(rows) => <div className="overflow-x-auto"><table className="w-full"><thead><tr><th className="th">Name</th><th className="th">Email</th><th className="th">Role</th><th className="th">Active</th></tr></thead><tbody>
        {rows.map((u) => <tr key={u.id} className="border-t border-navy-700"><td className="td">{u.full_name}</td><td className="td">{u.email}</td>
          <td className="td"><select aria-label={`Role for ${u.email}`} className="input !w-auto" value={u.role} disabled={u.id === user.id} onChange={(e) => update(u, { role: e.target.value })}><option value="analyst">analyst</option><option value="admin">admin</option></select></td>
          <td className="td"><label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={u.is_active} disabled={u.id === user.id} onChange={(e) => update(u, { is_active: e.target.checked })} />{u.is_active ? 'Active' : 'Disabled'}</label></td></tr>)}</tbody></table></div>}</Async></Section>}
      {tab === 'Audit log' && <Section title="Audit log (latest 100)" right={<button className="btn-ghost !py-1" onClick={audit.reload}>Refresh</button>}><Async state={audit}>{(rows) => <div className="max-h-[32rem] overflow-auto"><table className="w-full"><thead><tr><th className="th">Time</th><th className="th">Actor</th><th className="th">Action</th><th className="th">Entity</th><th className="th">IP</th></tr></thead><tbody>
        {rows.map((a) => <tr key={a.id} className="border-t border-navy-700"><td className="td whitespace-nowrap text-xs">{fmt(a.at)}</td><td className="td text-xs">{a.actor || 'anonymous'}</td><td className="td"><Badge value={a.action.includes('failed') || a.action.includes('rejected') ? 'rejected' : 'open'}>{a.action}</Badge></td><td className="td text-xs">{label(a.entity)} {a.entity_id}</td><td className="td font-mono text-xs">{a.ip}</td></tr>)}</tbody></table></div>}</Async></Section>}
    </>
  )
}
