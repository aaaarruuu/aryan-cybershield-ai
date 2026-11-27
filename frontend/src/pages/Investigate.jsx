import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { Async, Badge, Empty, ErrorBox, Facts, Field, Notice, PageHeader, Section, fmt, label } from '../components/ui'

export function ReportView({ inv }) {
  const r = inv.report
  if (!r || inv.status === 'failed') return <ErrorBox message={`Investigation failed${r?.error ? `: ${r.error}` : ''}.`} />
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <Badge value={r.risk_level || 'unknown'} className="!text-sm" /><span className="text-slate-300">{r.risk_score != null ? `${r.risk_score}/100` : 'Not scored'}</span>
        {r.incident_id && <span className="font-mono text-xs text-cyan-300">{r.incident_id}</span>}
      </div>
      <p className="text-sm text-slate-200">{r.incident_summary}</p>
      <p className="text-sm text-slate-400">{r.risk_explanation}</p>
      <div className="grid gap-4 md:grid-cols-2"><Facts title="Verified findings (observed)" items={r.verified_findings} /><Facts title="AI-generated hypotheses (unconfirmed)" items={r.ai_hypotheses} tone="warn" /></div>
      <div><h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">Timeline</h3>
        {r.related_events_timeline.length === 0 ? <p className="text-sm text-slate-500">No events.</p> : <ul className="space-y-1 text-sm">{r.related_events_timeline.map((t, i) => <li key={i} className="text-slate-300"><span className="font-mono text-xs text-slate-500">{t.time ? fmt(t.time) : 'n/a'}</span> {t.description}{!t.verified && <span className="ml-1 text-xs text-yellow-300">[unverified]</span>}</li>)}</ul>}</div>
      {r.correlations.length > 0 && <Facts title="Correlations across sources" items={r.correlations.map((c) => c.statement)} />}
      {r.possible_attack_techniques.length > 0 && <Facts title="Possible ATT&CK techniques (mapped, not verified)" items={r.possible_attack_techniques.map((t) => `${t.id} ${t.name}`)} tone="warn" />}
      <div><h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">Recommended actions (require human approval)</h3>
        {r.recommended_actions.length === 0 ? <p className="text-sm text-slate-500">None.</p> : <ul className="space-y-1 text-sm">{r.recommended_actions.map((a, i) => <li key={i} className="text-slate-300"><Badge value="pending" className="mr-2" />{label(a.action_type)} → <span className="font-mono">{a.target}</span><span className="block text-xs text-slate-500">{a.rationale}{a.citations?.length ? ` Sources: ${a.citations.join('; ')}` : ''}</span></li>)}</ul>}
        <p className="mt-2 text-xs text-slate-500">{r.knowledge_note}</p></div>
      <div><h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">Agent activity</h3>
        <div className="flex flex-wrap gap-2">{r.agent_execution.map((a) => <span key={a.agent} title={a.error || a.note || ''} className="rounded-lg bg-navy-900 px-2 py-1 text-xs text-slate-300">{label(a.agent)} <Badge value={a.status} /> {a.attempts > 1 && `×${a.attempts}`} <span className="text-slate-500">{a.duration_ms}ms</span></span>)}</div></div>
      <div className="flex gap-2"><button className="btn-ghost" onClick={() => api.downloadInvestigation(inv.id, 'pdf')}>Download PDF</button><button className="btn-ghost" onClick={() => api.downloadInvestigation(inv.id, 'csv')}>Download CSV</button></div>
    </div>
  )
}

export default function Investigate() {
  const [params] = useSearchParams()
  const [f, setF] = useState({ title: '', email: false, sender: '', subject: '', body: '', urls: '', indicators: '', batch: params.get('batch') || '', incident: true })
  const [active, setActive] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const batches = useAsync(() => api.batches(), [])
  const list = useAsync(() => api.investigations(), [])
  const timer = useRef()
  const set = (k) => (e) => setF({ ...f, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })

  const poll = (id) => {
    clearTimeout(timer.current)
    api.investigation(id).then((inv) => {
      setActive(inv)
      if (inv.status === 'queued' || inv.status === 'running') timer.current = setTimeout(() => poll(id), 1200)
      else list.reload()
    }).catch((e) => setError(e.message))
  }
  useEffect(() => () => clearTimeout(timer.current), [])

  const submit = async (e) => {
    e.preventDefault()
    const indicators = f.indicators.split(/[\s,]+/).filter(Boolean)
    if (!f.email && !indicators.length && !f.batch) return setError('Add an email, indicators, or select a log batch to investigate')
    const body = { title: f.title || 'Investigation', indicators, log_batch_id: f.batch || null, create_incident: f.incident }
    if (f.email) body.phishing = { sender: f.sender, subject: f.subject, body: f.body, urls: f.urls.split(/\s+/).filter(Boolean) }
    setBusy(true); setError('')
    try { const s = await api.startInvestigation(body); setActive({ ...s, report: null }); poll(s.id) } catch (err) { setError(err.message) } finally { setBusy(false) }
  }
  const running = active && (active.status === 'queued' || active.status === 'running')

  return (
    <>
      <PageHeader title="AI Investigation Center" subtitle="A controlled multi-agent workflow: only the agents needed for your inputs run. Severity is computed from evidence, and every response action waits for human approval." />
      <div className="grid gap-6 lg:grid-cols-5">
        <div className="space-y-6 lg:col-span-2">
          <form onSubmit={submit} className="card space-y-4" aria-label="New investigation">
            <ErrorBox message={error} />
            <Field label="Title" id="title"><input id="title" className="input" value={f.title} onChange={set('title')} placeholder="e.g. Suspected brute force on admin" /></Field>
            <Field label="Indicators (IPs, domains, URLs, hashes)" id="ind"><textarea id="ind" rows={2} className="input font-mono" value={f.indicators} onChange={set('indicators')} /></Field>
            <Field label="Log batch" id="batch"><select id="batch" className="input" value={f.batch} onChange={set('batch')}><option value="">None</option>{batches.data?.map((b) => <option key={b.batch_id} value={b.batch_id}>{b.source} ({b.events} events)</option>)}</select></Field>
            <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={f.email} onChange={set('email')} /> Include a suspicious email</label>
            {f.email && <div className="space-y-3 rounded-lg bg-navy-900 p-3"><input aria-label="Sender" className="input" placeholder="Sender" value={f.sender} onChange={set('sender')} /><input aria-label="Subject" className="input" placeholder="Subject" value={f.subject} onChange={set('subject')} /><textarea aria-label="Body" rows={4} className="input" placeholder="Body" value={f.body} onChange={set('body')} /><textarea aria-label="URLs" rows={2} className="input font-mono" placeholder="URLs" value={f.urls} onChange={set('urls')} /></div>}
            <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={f.incident} onChange={set('incident')} /> Create an incident if risk is above low</label>
            <button className="btn-primary w-full" disabled={busy || running}>{running ? 'Agents working…' : 'Start investigation'}</button>
          </form>
          <Section title="Past investigations"><Async state={list}>{(rows) => rows.length === 0 ? <Empty title="No investigations yet" /> :
            <ul className="space-y-2">{rows.map((i) => <li key={i.id}><button className="flex w-full items-center justify-between rounded-lg bg-navy-900 p-2 text-left text-sm hover:bg-navy-700" onClick={() => poll(i.id)}><span className="truncate text-slate-200">#{i.id} {i.title}</span>{i.risk_level ? <Badge value={i.risk_level} /> : <Badge value={i.status} />}</button></li>)}</ul>}</Async></Section>
        </div>
        <div className="lg:col-span-3">
          {!active ? <Empty title="No investigation selected" hint="Start a new investigation or open a past one to see the evidence-based report." /> :
            <Section title={`Investigation #${active.id} — ${active.title}`} right={<Badge value={active.status} />}>
              {running ? <div role="status" className="p-6 text-sm text-slate-400">Agents are running. This page updates automatically…</div> : <ReportView inv={active} />}
            </Section>}
          <div className="mt-4"><Notice>Hypotheses are AI/heuristic inferences. Confirm them before acting. Nothing has been executed against real systems.</Notice></div>
        </div>
      </div>
    </>
  )
}
