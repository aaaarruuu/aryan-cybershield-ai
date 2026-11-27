import { useState } from 'react'
import { api } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { useAuth } from '../context/AuthContext'
import { Async, Badge, Empty, ErrorBox, Field, PageHeader, Section, fmt, label } from '../components/ui'

const STATUSES = ['open', 'under_investigation', 'awaiting_approval', 'resolved', 'closed']
const SEVS = ['low', 'medium', 'high', 'critical']

function Detail({ id, onChanged }) {
  const { user } = useAuth()
  const inc = useAsync(() => api.incident(id), [id])
  const [note, setNote] = useState('')
  const [resolution, setResolution] = useState('')
  const [error, setError] = useState('')
  const act = async (fn) => { setError(''); try { await fn(); await inc.reload(); onChanged() } catch (e) { setError(e.message) } }
  return (
    <Async state={inc}>{(i) => (
      <Section title={`${i.incident_uid} — ${i.title}`} right={<Badge value={i.status} />}>
        <div className="space-y-4 text-sm">
          <ErrorBox message={error} />
          <p className="text-slate-300">{i.description || 'No description.'}</p>
          <div className="grid grid-cols-2 gap-3"><div><span className="label">Severity</span><select aria-label="Severity" className="input" value={i.severity} onChange={(e) => act(() => api.updateIncident(i.id, { severity: e.target.value }))}>{SEVS.map((s) => <option key={s}>{s}</option>)}</select></div>
            <div><span className="label">Status</span><select aria-label="Status" className="input" value={i.status} onChange={(e) => act(() => api.updateIncident(i.id, { status: e.target.value, resolution_notes: resolution || undefined }))}>{STATUSES.map((s) => <option key={s} value={s}>{label(s)}</option>)}</select></div></div>
          <p className="text-xs text-slate-500">Source {i.source} · category {label(i.category)} · detected {fmt(i.detected_at)} · assigned {i.assigned_to_id === user.id ? 'to you' : i.assigned_to_id ? `to user #${i.assigned_to_id}` : 'nobody'}{!i.assigned_to_id || i.assigned_to_id !== user.id ? '' : ''}</p>
          {i.assigned_to_id !== user.id && <button className="btn-ghost" onClick={() => act(() => api.updateIncident(i.id, { assigned_to_id: user.id }))}>Assign to me</button>}
          {i.related_indicators.length > 0 && <p className="font-mono text-xs text-slate-400">Indicators: {i.related_indicators.join(', ')}</p>}
          {i.recommended_response && <p className="text-xs text-slate-400">Recommended: {i.recommended_response}</p>}
          {i.investigation_id && <p className="text-xs text-cyan-300">From AI investigation #{i.investigation_id}</p>}
          <Field label="Resolution notes (required to resolve or close)" id="res"><textarea id="res" rows={2} className="input" defaultValue={i.resolution_notes} onChange={(e) => setResolution(e.target.value)} />
            <button className="btn-ghost mt-2" onClick={() => act(() => api.updateIncident(i.id, { resolution_notes: resolution }))}>Save notes</button></Field>
          <div><h3 className="label">Investigation history</h3><ul className="space-y-1">{i.history.map((h) => <li key={h.id} className="text-slate-300"><span className="font-mono text-xs text-slate-500">{fmt(h.created_at)}</span> <strong className="text-cyan-300">{label(h.action)}</strong> {h.note}</li>)}</ul>
            <form className="mt-2 flex gap-2" onSubmit={(e) => { e.preventDefault(); if (note.trim()) act(async () => { await api.addNote(i.id, note.trim()); setNote('') }) }}><input aria-label="Add note" className="input" placeholder="Record an investigation activity…" value={note} onChange={(e) => setNote(e.target.value)} /><button className="btn-primary">Add</button></form></div>
        </div>
      </Section>)}</Async>
  )
}

export default function Incidents() {
  const [filters, setFilters] = useState({ status: '', severity: '', q: '' })
  const [sel, setSel] = useState(null)
  const [show, setShow] = useState(false)
  const [form, setForm] = useState({ title: '', description: '', severity: 'medium', category: 'uncategorized', indicators: '' })
  const [error, setError] = useState('')
  const list = useAsync(() => api.incidents({ ...filters, limit: 200 }), [filters.status, filters.severity, filters.q])
  const create = async (e) => {
    e.preventDefault()
    if (form.title.trim().length < 3) return setError('Title must be at least 3 characters')
    try { const i = await api.createIncident({ title: form.title.trim(), description: form.description, severity: form.severity, category: form.category, related_indicators: form.indicators.split(/[\s,]+/).filter(Boolean) }); setShow(false); setError(''); setForm({ ...form, title: '', description: '', indicators: '' }); list.reload(); setSel(i.id) } catch (err) { setError(err.message) }
  }
  return (
    <>
      <PageHeader title="Incident Management" subtitle="Track incidents from detection to closure with a full investigation history.">
        <button className="btn-primary" onClick={() => setShow(!show)}>{show ? 'Cancel' : 'New incident'}</button><button className="btn-ghost" onClick={() => api.downloadIncidentsCsv()}>Export CSV</button>
      </PageHeader>
      {show && <form onSubmit={create} className="card mb-6 grid gap-3 md:grid-cols-2" aria-label="New incident"><div className="md:col-span-2"><ErrorBox message={error} /></div>
        <Field label="Title" id="t"><input id="t" className="input" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} /></Field>
        <Field label="Severity" id="s"><select id="s" className="input" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>{SEVS.map((s) => <option key={s}>{s}</option>)}</select></Field>
        <Field label="Description" id="d"><textarea id="d" rows={2} className="input" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
        <Field label="Related indicators" id="i"><textarea id="i" rows={2} className="input font-mono" value={form.indicators} onChange={(e) => setForm({ ...form, indicators: e.target.value })} /></Field>
        <div><button className="btn-primary">Create incident</button></div></form>}
      <div className="mb-4 flex flex-wrap gap-2">
        <input aria-label="Search incidents" className="input !w-64" placeholder="Search title, ID, description" value={filters.q} onChange={(e) => setFilters({ ...filters, q: e.target.value })} />
        <select aria-label="Filter status" className="input !w-auto" value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}><option value="">All statuses</option>{STATUSES.map((s) => <option key={s} value={s}>{label(s)}</option>)}</select>
        <select aria-label="Filter severity" className="input !w-auto" value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}><option value="">All severities</option>{SEVS.map((s) => <option key={s}>{s}</option>)}</select>
      </div>
      <div className="grid gap-6 xl:grid-cols-2">
        <Async state={list}>{(rows) => rows.length === 0 ? <Empty title="No incidents match" hint="Create one, or run an AI investigation." /> :
          <div className="card !p-0 overflow-x-auto"><table className="w-full"><thead><tr><th className="th">ID</th><th className="th">Title</th><th className="th">Severity</th><th className="th">Status</th></tr></thead><tbody>
            {rows.map((r) => <tr key={r.id} onClick={() => setSel(r.id)} className={`cursor-pointer border-t border-navy-700 hover:bg-navy-700/50 ${sel === r.id ? 'bg-navy-700/60' : ''}`}><td className="td font-mono text-xs">{r.incident_uid}</td><td className="td"><button className="text-left" onClick={() => setSel(r.id)}>{r.title}</button></td><td className="td"><Badge value={r.severity} /></td><td className="td"><Badge value={r.status} /></td></tr>)}</tbody></table></div>}</Async>
        {sel ? <Detail key={sel} id={sel} onChanged={list.reload} /> : <Empty title="Select an incident" hint="Details, notes and history appear here." />}
      </div>
    </>
  )
}
