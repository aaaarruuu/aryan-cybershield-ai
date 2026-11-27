import { useState } from 'react'
import { api } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { useAuth } from '../context/AuthContext'
import { Async, Badge, Empty, ErrorBox, Field, Notice, PageHeader, Tabs, fmt, label } from '../components/ui'

const ACTIONS = ['block_indicator', 'reset_password', 'revoke_sessions', 'isolate_endpoint', 'investigate_access', 'escalate_incident']

function Card({ a, onDone }) {
  const { user } = useAuth()
  const [note, setNote] = useState('')
  const [error, setError] = useState('')
  const can = a.approver_roles.includes(user.role)
  const run = async (fn, next) => { setError(''); try { await fn(); onDone(next) } catch (e) { setError(e.message) } }
  return (
    <div className="card space-y-2 text-sm">
      <div className="flex flex-wrap items-center justify-between gap-2"><div><span className="font-semibold text-white">{label(a.action_type)}</span> → <span className="font-mono text-cyan-300">{a.target}</span></div><Badge value={a.status} /></div>
      <p className="text-slate-400">{a.rationale || 'No rationale given.'}</p>
      <p className="text-xs text-slate-500">Requested by {a.requested_by} · {fmt(a.created_at)}{a.incident_id ? ` · incident #${a.incident_id}` : ''} · can be decided by: {a.approver_roles.join(', ')}</p>
      <ErrorBox message={error} />
      {a.status === 'pending' && (can ? <div className="flex flex-wrap gap-2"><input aria-label="Decision note" className="input !w-64" placeholder="Decision note (optional)" value={note} onChange={(e) => setNote(e.target.value)} /><button className="btn-primary" onClick={() => run(() => api.approve(a.id, note), 'Approved')}>Approve (simulated)</button><button className="btn-danger" onClick={() => run(() => api.reject(a.id, note), 'Rejected')}>Reject</button></div> : <p className="text-xs text-yellow-300">Your role cannot decide this action.</p>)}
      {a.execution && <div className="rounded-lg bg-navy-900 p-3"><div className="flex items-center gap-2"><Badge value={a.execution.status === 'executed_simulated' ? 'success' : a.execution.status === 'failed' ? 'failed' : 'skipped'}>{label(a.execution.status)}</Badge><span className="text-xs text-slate-400">{a.execution.result?.message || a.execution.result?.error}</span></div>
        {a.execution.verification?.verified && <p className="mt-1 text-xs text-emerald-300">Verified: {a.execution.verification.detail}</p>}
        {a.execution.rollback?.available && a.execution.status === 'executed_simulated' && <button className="btn-ghost mt-2 !py-1" onClick={() => run(() => api.rollback(a.id))}>Roll back: {a.execution.rollback.plan}</button>}</div>}
      {a.decision_note && <p className="text-xs text-slate-500">Note: {a.decision_note}</p>}
    </div>
  )
}

export default function Approvals() {
  const [tab, setTab] = useState('Pending')
  const [show, setShow] = useState(false)
  const [f, setF] = useState({ action_type: 'block_indicator', target: '', rationale: '', incident_id: '' })
  const [error, setError] = useState('')
  const status = { Pending: 'pending', Approved: 'approved', Rejected: 'rejected', All: undefined }[tab]
  const list = useAsync(() => api.approvals(status), [status])
  const create = async (e) => {
    e.preventDefault()
    if (!f.target.trim()) return setError('Target is required')
    try { await api.createApproval({ ...f, incident_id: f.incident_id ? Number(f.incident_id) : null }); setShow(false); setError(''); setF({ ...f, target: '', rationale: '' }); list.reload() } catch (err) { setError(err.message) }
  }
  return (
    <>
      <PageHeader title="Response Approval Center" subtitle="Every response action needs explicit human approval. Execution is simulated: nothing outside this application is ever changed.">
        <button className="btn-primary" onClick={() => setShow(!show)}>{show ? 'Cancel' : 'Request action'}</button>
      </PageHeader>
      <div className="mb-4"><Notice tone="warn">Simulation mode: approving an action records and simulates it, verifies the simulated state, and writes to the audit log. No firewall, directory or endpoint is contacted.</Notice></div>
      {show && <form onSubmit={create} className="card mb-6 grid gap-3 md:grid-cols-2" aria-label="Request action"><div className="md:col-span-2"><ErrorBox message={error} /></div>
        <Field label="Action" id="a"><select id="a" className="input" value={f.action_type} onChange={(e) => setF({ ...f, action_type: e.target.value })}>{ACTIONS.map((a) => <option key={a} value={a}>{label(a)}</option>)}</select></Field>
        <Field label="Target" id="tg" hint="IP/domain/hash, username, hostname or team"><input id="tg" className="input font-mono" value={f.target} onChange={(e) => setF({ ...f, target: e.target.value })} /></Field>
        <Field label="Incident ID (optional)" id="inc"><input id="inc" type="number" className="input" value={f.incident_id} onChange={(e) => setF({ ...f, incident_id: e.target.value })} /></Field>
        <Field label="Rationale" id="r"><input id="r" className="input" value={f.rationale} onChange={(e) => setF({ ...f, rationale: e.target.value })} /></Field>
        <div><button className="btn-primary">Submit request</button></div></form>}
      <Tabs tabs={['Pending', 'Approved', 'Rejected', 'All']} value={tab} onChange={setTab} />
      <Async state={list}>{(rows) => rows.length === 0 ? <Empty title={`No ${tab.toLowerCase()} requests`} hint="Run an AI investigation to generate recommended actions." /> : <div className="grid gap-4 xl:grid-cols-2">{rows.map((a) => <Card key={a.id} a={a} onDone={(next) => (next && next !== tab ? setTab(next) : list.reload())} />)}</div>}</Async>
    </>
  )
}
