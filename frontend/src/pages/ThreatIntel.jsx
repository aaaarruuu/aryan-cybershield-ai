import { useState } from 'react'
import { api } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { Async, Badge, Empty, ErrorBox, Notice, PageHeader, Section, fmt } from '../components/ui'

export function IntelResult({ r }) {
  const st = r.details?.engine_stats
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3"><span className="font-mono text-sm text-white">{r.indicator}</span><Badge value={r.verdict} />{r.is_ioc && <Badge value="malicious" className="!bg-red-500/25">IOC</Badge>}
        <span className="text-xs text-slate-500">{r.type}</span></div>
      {r.demo && <Notice tone="warn">Result from the bundled <strong>demo dataset</strong>, not a live service.{r.verdict === 'unknown' && ' Absence from the dataset does not mean the indicator is safe.'}</Notice>}
      {r.verdict === 'unavailable' && <Notice tone="warn">Lookup unavailable: {r.details?.error}. No verdict has been assumed.</Notice>}
      {st && <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">{Object.entries(st).map(([k, v]) => <div key={k} className="rounded-lg bg-navy-900 p-3"><p className="text-xs uppercase text-slate-500">{k}</p><p className="text-xl font-semibold text-slate-100">{v}</p></div>)}</div>}
      {r.details?.note && <p className="text-sm text-slate-400">{r.details.note}</p>}
      <p className="text-xs text-slate-500">Source: {r.source} · looked up {fmt(r.looked_up_at)}{r.cached ? ' (cached)' : ''}{r.score != null && ` · weighted score ${r.score}`}</p>
    </div>
  )
}

export default function ThreatIntel() {
  const [value, setValue] = useState('')
  const [res, setRes] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const history = useAsync(() => api.indicators(), [])
  const run = async (e, refresh = false) => {
    e?.preventDefault()
    if (!value.trim()) return setError('Enter an IP address, domain, URL or file hash')
    setBusy(true); setError('')
    try { setRes(await api.lookup(value.trim(), refresh)); history.reload() } catch (err) { setError(err.message); setRes(null) } finally { setBusy(false) }
  }
  return (
    <>
      <PageHeader title="Threat Intelligence" subtitle="Look up IP addresses, domains, URLs and file hashes. Results show their source and timestamp; missing data is never invented." />
      <div className="grid gap-6 lg:grid-cols-5">
        <div className="space-y-6 lg:col-span-3">
          <Section title="Indicator lookup">
            <form onSubmit={run} className="flex gap-2"><input aria-label="Indicator" className="input" placeholder="e.g. 203.0.113.45, example.com, https://…, SHA256" value={value} onChange={(e) => setValue(e.target.value)} />
              <button className="btn-primary" disabled={busy}>{busy ? 'Looking up…' : 'Lookup'}</button></form>
            <div className="mt-4 space-y-3"><ErrorBox message={error} />{res && <><IntelResult r={res} /><button className="btn-ghost" onClick={() => run(null, true)}>Refresh (bypass cache)</button></>}</div>
          </Section>
        </div>
        <div className="lg:col-span-2"><Section title="Recent lookups">
          <Async state={history}>{(rows) => rows.length === 0 ? <Empty title="No lookups yet" /> :
            <ul className="space-y-2">{rows.slice(0, 12).map((r) => <li key={r.indicator + r.source} className="flex items-center justify-between gap-2 text-sm"><button className="truncate font-mono text-left text-slate-300 hover:text-cyan-300" onClick={() => { setValue(r.indicator); setRes(r) }}>{r.indicator}</button><Badge value={r.verdict} /></li>)}</ul>}</Async>
        </Section></div>
      </div>
    </>
  )
}
