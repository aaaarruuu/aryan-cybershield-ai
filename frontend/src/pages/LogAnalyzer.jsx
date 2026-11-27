import { useRef, useState } from 'react'
import { api } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { Async, Badge, Empty, ErrorBox, Notice, PageHeader, Section, fmt } from '../components/ui'
import { Link } from 'react-router-dom'

export default function LogAnalyzer() {
  const batches = useAsync(() => api.batches(), [])
  const [current, setCurrent] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [suspOnly, setSuspOnly] = useState(true)
  const file = useRef()
  const events = useAsync(() => (current ? api.events({ batch_id: current.batch_id, suspicious: suspOnly ? true : undefined, limit: 100 }) : Promise.resolve([])), [current?.batch_id, suspOnly])

  const done = (r) => { setCurrent(r); batches.reload() }
  const upload = async (e) => {
    e.preventDefault()
    const f = file.current?.files?.[0]
    if (!f) return setError('Choose a .csv, .json, .txt or .log file first')
    setBusy(true); setError('')
    try { done(await api.uploadLogs(f)) } catch (err) { setError(err.message) } finally { setBusy(false) }
  }
  const sample = async () => { setBusy(true); setError(''); try { done(await api.loadSampleLogs()) } catch (err) { setError(err.message) } finally { setBusy(false) } }
  const open = async (id) => { setError(''); try { const a = await api.batchAnalysis(id); setCurrent({ ...a, warnings: [], skipped_rows: 0 }) } catch (err) { setError(err.message) } }

  return (
    <>
      <PageHeader title="Security Log Analyzer" subtitle="Upload CSV, JSON or text logs. Rule-based detections drive alerts; an Isolation Forest adds an unsupervised anomaly signal that is shown separately and never treated as confirmed." />
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6">
          <Section title="Upload">
            <form onSubmit={upload} className="space-y-3"><input ref={file} type="file" aria-label="Log file" accept=".csv,.json,.txt,.log" className="block w-full text-sm text-slate-300 file:mr-3 file:rounded-lg file:border-0 file:bg-navy-600 file:px-3 file:py-2 file:text-slate-100" />
              <div className="flex gap-2"><button className="btn-primary" disabled={busy}>{busy ? 'Analysing…' : 'Upload & analyse'}</button><button type="button" className="btn-ghost" onClick={sample} disabled={busy}>Load sample log</button></div></form>
            <p className="mt-2 text-xs text-slate-500">Needs a timestamp plus a source IP or username. Max 10 MB, 100,000 rows. Sample data is synthetic.</p>
            <div className="mt-3"><ErrorBox message={error} /></div>
          </Section>
          <Section title="Previous batches"><Async state={batches}>{(rows) => rows.length === 0 ? <Empty title="No logs analysed yet" /> :
            <ul className="space-y-2">{rows.map((b) => <li key={b.batch_id}><button onClick={() => open(b.batch_id)} className="w-full rounded-lg bg-navy-900 p-2 text-left text-sm hover:bg-navy-700"><span className="block truncate text-slate-200">{b.source}</span><span className="text-xs text-slate-500">{b.events} events · {b.suspicious} flagged · {fmt(b.last)}</span></button></li>)}</ul>}</Async></Section>
        </div>
        <div className="space-y-6 lg:col-span-2">
          {!current ? <Empty title="No batch selected" hint="Upload a log file or open a previous batch to see alerts and flagged events." /> : (
            <>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">{[['Events', current.summary.events], ['Failed logins', current.summary.failed_logins], ['Unique IPs', current.summary.unique_ips], ['Alerts', current.summary.alerts]].map(([k, v]) => <div key={k} className="card !p-3"><p className="text-xs uppercase text-slate-500">{k}</p><p className="text-2xl font-semibold text-cyan-400">{v}</p></div>)}</div>
              {current.warnings?.map((w) => <Notice key={w} tone="warn">{w}</Notice>)}
              {current.ml_meta?.skipped && <Notice>{current.ml_meta.skipped}</Notice>}
              <Section title={`Alerts (${current.alerts.length})`} right={<Link className="text-xs text-cyan-400" to={`/investigate?batch=${current.batch_id}`}>Investigate with AI agents →</Link>}>
                {current.alerts.length === 0 ? <p className="text-sm text-slate-500">No alerts raised for this batch. This does not prove the absence of malicious activity.</p> :
                  <ul className="space-y-3">{current.alerts.map((a, i) => <li key={i} className="rounded-lg bg-navy-900 p-3"><div className="flex flex-wrap items-center gap-2"><Badge value={a.severity} /><span className="font-medium text-slate-100">{a.title}</span>{a.source === 'ml' && <span className="rounded bg-navy-600 px-1.5 text-[10px] uppercase text-slate-300">ML signal</span>}</div><p className="mt-1 text-sm text-slate-400">{a.description}</p></li>)}</ul>}
              </Section>
              <Section title="Events" right={<label className="flex items-center gap-2 text-xs text-slate-400"><input type="checkbox" checked={suspOnly} onChange={(e) => setSuspOnly(e.target.checked)} /> Flagged only</label>}>
                <Async state={events}>{(rows) => rows.length === 0 ? <Empty title="No events to show" /> :
                  <div className="max-h-96 overflow-auto"><table className="w-full"><thead><tr><th className="th">Time</th><th className="th">Type</th><th className="th">User</th><th className="th">Source IP</th><th className="th">Outcome</th></tr></thead><tbody>
                    {rows.map((e) => <tr key={e.id} className="border-t border-navy-700"><td className="td whitespace-nowrap text-xs">{fmt(e.timestamp)}</td><td className="td">{e.event_type}</td><td className="td">{e.username}</td><td className="td font-mono text-xs">{e.src_ip}</td><td className="td"><Badge value={e.outcome === 'failure' ? 'failed' : e.outcome === 'success' ? 'success' : 'unknown'} /></td></tr>)}</tbody></table></div>}</Async>
              </Section>
            </>)}
        </div>
      </div>
    </>
  )
}
