import { useState } from 'react'

const SEV = {
  critical: 'bg-red-500/15 text-red-300 ring-red-500/40',
  high: 'bg-orange-500/15 text-orange-300 ring-orange-500/40',
  medium: 'bg-yellow-500/15 text-yellow-200 ring-yellow-500/40',
  low: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
  malicious: 'bg-red-500/15 text-red-300 ring-red-500/40',
  phishing: 'bg-red-500/15 text-red-300 ring-red-500/40',
  suspicious: 'bg-orange-500/15 text-orange-300 ring-orange-500/40',
  clean: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
  legitimate: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
  unknown: 'bg-slate-500/15 text-slate-300 ring-slate-500/40',
  unavailable: 'bg-slate-500/15 text-slate-300 ring-slate-500/40',
  open: 'bg-cyan-500/15 text-cyan-300 ring-cyan-500/40',
  under_investigation: 'bg-blue-500/15 text-blue-300 ring-blue-500/40',
  awaiting_approval: 'bg-purple-500/15 text-purple-300 ring-purple-500/40',
  resolved: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
  closed: 'bg-slate-500/15 text-slate-300 ring-slate-500/40',
  pending: 'bg-purple-500/15 text-purple-300 ring-purple-500/40',
  approved: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
  rejected: 'bg-red-500/15 text-red-300 ring-red-500/40',
  success: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
  failed: 'bg-red-500/15 text-red-300 ring-red-500/40',
  skipped: 'bg-slate-500/15 text-slate-300 ring-slate-500/40',
  completed: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
  running: 'bg-blue-500/15 text-blue-300 ring-blue-500/40',
  queued: 'bg-slate-500/15 text-slate-300 ring-slate-500/40',
}

export const label = (s) => String(s ?? '').replace(/_/g, ' ')

export function Badge({ value, className = '', children }) {
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ring-1 ring-inset ${SEV[value] || SEV.unknown} ${className}`}>
      {children ?? label(value)}
    </span>
  )
}

export function PageHeader({ title, subtitle, children }) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-2xl font-semibold text-white">{title}</h1>
        {subtitle && <p className="mt-1 max-w-3xl text-sm text-slate-400">{subtitle}</p>}
      </div>
      <div className="flex flex-wrap gap-2">{children}</div>
    </div>
  )
}

export function Spinner({ text = 'Loading…' }) {
  return (
    <div role="status" className="flex items-center gap-3 p-6 text-sm text-slate-400">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
      {text}
    </div>
  )
}

export function ErrorBox({ message, onRetry }) {
  if (!message) return null
  return (
    <div role="alert" className="flex items-center justify-between gap-3 rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-200">
      <span>{message}</span>
      {onRetry && <button className="btn-ghost !py-1" onClick={onRetry}>Retry</button>}
    </div>
  )
}

export function Empty({ title, hint, children }) {
  return (
    <div className="rounded-xl border border-dashed border-navy-600 p-8 text-center">
      <p className="font-medium text-slate-300">{title}</p>
      {hint && <p className="mx-auto mt-1 max-w-md text-sm text-slate-500">{hint}</p>}
      {children && <div className="mt-4 flex justify-center gap-2">{children}</div>}
    </div>
  )
}

/** Handles the loading / error / empty / data states of a useAsync result uniformly. */
export function Async({ state, empty, children, loadingText }) {
  if (state.loading && !state.data) return <Spinner text={loadingText} />
  if (state.error) return <ErrorBox message={state.error} onRetry={state.reload} />
  if (empty && empty(state.data)) return null
  return children(state.data)
}

export function Stat({ label: l, value, sub, tone = 'cyan' }) {
  const tones = { cyan: 'text-cyan-400', red: 'text-red-400', orange: 'text-orange-400', green: 'text-neon-400', purple: 'text-purple-400' }
  return (
    <div className="card !p-4">
      <p className="text-xs uppercase tracking-wide text-slate-400">{l}</p>
      <p className={`mt-1 text-3xl font-semibold ${tones[tone]}`}>{value ?? '—'}</p>
      {sub && <p className="mt-1 text-xs text-slate-500">{sub}</p>}
    </div>
  )
}

export function Field({ label: l, id, children, hint }) {
  return (
    <div>
      <label htmlFor={id} className="label">{l}</label>
      {children}
      {hint && <p className="mt-1 text-xs text-slate-500">{hint}</p>}
    </div>
  )
}

export function Notice({ tone = 'info', children }) {
  const t = { info: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-100', warn: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-100', ok: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-100' }
  return <div className={`rounded-lg border p-3 text-sm ${t[tone]}`}>{children}</div>
}

export function Section({ title, children, right }) {
  return (
    <div className="card">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-300">{title}</h2>
        {right}
      </div>
      {children}
    </div>
  )
}

export function Tabs({ tabs, value, onChange }) {
  return (
    <div role="tablist" className="mb-4 flex gap-1 border-b border-navy-600">
      {tabs.map((t) => (
        <button key={t} role="tab" aria-selected={value === t} onClick={() => onChange(t)}
          className={`px-4 py-2 text-sm font-medium transition ${value === t ? 'border-b-2 border-cyan-400 text-cyan-300' : 'text-slate-400 hover:text-slate-200'}`}>{t}</button>
      ))}
    </div>
  )
}

export function Confirm({ children, onConfirm, text = 'Are you sure?', className = 'btn-danger' }) {
  const [asking, setAsking] = useState(false)
  if (!asking) return <button className={className} onClick={() => setAsking(true)}>{children}</button>
  return (
    <span className="inline-flex items-center gap-2 text-sm">
      {text}
      <button className="btn-danger !py-1" onClick={() => { setAsking(false); onConfirm() }}>Yes</button>
      <button className="btn-ghost !py-1" onClick={() => setAsking(false)}>No</button>
    </span>
  )
}

export const fmt = (iso) => (iso ? new Date(iso).toLocaleString() : '—')

export function Facts({ title, items, tone }) {
  return (
    <div>
      <h3 className={`mb-1 text-xs font-semibold uppercase tracking-wide ${tone === 'warn' ? 'text-yellow-300' : 'text-emerald-300'}`}>{title}</h3>
      {items?.length ? <ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">{items.map((i, n) => <li key={n}>{i}</li>)}</ul> : <p className="text-sm text-slate-500">None.</p>}
    </div>
  )
}
