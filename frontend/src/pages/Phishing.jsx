import { useState } from 'react'
import { api } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { Badge, ErrorBox, Facts, Field, PageHeader, Section } from '../components/ui'

const SAMPLES = {
  'Phishing sample': { subject: 'URGENT: Your account will be suspended', sender: 'security@paypa1-support.com', body: 'Dear customer, we detected unusual activity. Verify your password immediately or your account will be suspended within 24 hours.', urls: 'http://paypa1-support.com.verify-login.xyz/login' },
  'Legitimate sample': { subject: 'Team meeting notes - Tuesday', sender: 'bob@example.com', body: "Hi all, attached are the notes from Tuesday's meeting. Let me know if I missed anything. Thanks, Bob", urls: 'https://example.com/wiki/meeting-notes' },
}

export default function Phishing() {
  const [f, setF] = useState({ subject: '', sender: '', body: '', urls: '' })
  const [res, setRes] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const report = useAsync(() => api.modelReport(), [])
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  const submit = async (e) => {
    e.preventDefault()
    if (!f.subject && !f.sender && !f.body && !f.urls) return setError('Provide at least a subject, sender, body or URL')
    setBusy(true); setError('')
    try { setRes(await api.analysePhishing({ subject: f.subject, sender: f.sender, body: f.body, urls: f.urls.split(/\s+/).filter(Boolean) })) } catch (err) { setError(err.message); setRes(null) } finally { setBusy(false) }
  }
  const load = (s) => { setF(SAMPLES[s]); setRes(null) }
  return (
    <>
      <PageHeader title="Phishing Analysis" subtitle="Deterministic checks (sender, language, URLs) plus an ML text signal. The ML score alone can never label an email as phishing.">
        {Object.keys(SAMPLES).map((s) => <button key={s} className="btn-ghost" onClick={() => load(s)}>{s}</button>)}
      </PageHeader>
      <div className="grid gap-6 lg:grid-cols-2">
        <form onSubmit={submit} className="card space-y-4" aria-label="Email to analyse">
          <ErrorBox message={error} />
          <Field label="Sender address" id="sender"><input id="sender" className="input" value={f.sender} onChange={set('sender')} placeholder="name@domain.com" /></Field>
          <Field label="Subject" id="subject"><input id="subject" className="input" value={f.subject} onChange={set('subject')} /></Field>
          <Field label="Body" id="body"><textarea id="body" rows={8} className="input" value={f.body} onChange={set('body')} /></Field>
          <Field label="URLs (space or newline separated)" id="urls"><textarea id="urls" rows={2} className="input font-mono" value={f.urls} onChange={set('urls')} /></Field>
          <button className="btn-primary" disabled={busy}>{busy ? 'Analysing…' : 'Analyse email'}</button>
        </form>
        <div className="space-y-6">
          {res ? (
            <Section title="Result">
              <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-3"><Badge value={res.classification} className="!text-sm" /><span className="text-sm text-slate-300">Risk <Badge value={res.risk_level} /></span><span className="text-sm text-slate-400">Confidence {(res.confidence * 100).toFixed(0)}% · score {res.risk_score}/100</span></div>
                <p className="text-sm text-slate-300">{res.explanation}</p>
                <div><h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">Detected indicators ({res.indicators.length})</h3>
                  {res.indicators.length === 0 ? <p className="text-sm text-slate-500">No indicators found.</p> :
                    <ul className="space-y-2">{res.indicators.map((i) => <li key={i.id} className="rounded-lg bg-navy-900 p-2 text-sm"><span className="font-medium text-slate-100">{i.summary}</span> <span className="text-xs text-slate-500">(+{i.points}, {i.category})</span><p className="break-all font-mono text-xs text-slate-400">{i.evidence}</p></li>)}</ul>}</div>
                <Facts title="Recommended next steps" items={res.recommended_next_steps} />
                <p className="text-xs text-slate-500">ML phishing probability {(res.ml.phishing_probability * 100).toFixed(0)}% (contributed {res.ml.points_contributed} pts) · deterministic score {res.deterministic_score}. {res.limitations}</p>
              </div>
            </Section>
          ) : <Section title="Result"><p className="text-sm text-slate-500">Submit an email to see the classification, evidence and recommended steps.</p></Section>}
          <Section title="ML model evaluation">
            {report.loading ? <p className="text-sm text-slate-500">Loading…</p> : report.error ? <ErrorBox message={report.error} /> : report.data && (
              <div className="space-y-3 text-sm text-slate-300">
                <p className="rounded-lg border border-yellow-500/40 bg-yellow-500/10 p-2 text-yellow-100">{report.data.note}</p>
                <table className="w-full text-left"><thead><tr><th className="th">Set</th><th className="th">n</th><th className="th">Acc</th><th className="th">Prec</th><th className="th">Recall</th><th className="th">F1</th><th className="th">FPR</th></tr></thead><tbody>
                  {[['Synthetic hold-out', report.data.heldout_split], ['Hand-written', report.data.handwritten_eval]].filter(([, m]) => m).map(([n, m]) => <tr key={n} className="border-t border-navy-700"><td className="td">{n}</td><td className="td">{m.n}</td><td className="td">{m.accuracy}</td><td className="td">{m.precision}</td><td className="td">{m.recall}</td><td className="td">{m.f1}</td><td className="td">{m.false_positive_rate}</td></tr>)}</tbody></table>
                <p className="text-xs text-slate-500">{report.data.handwritten_eval?.note}</p>
              </div>)}
          </Section>
        </div>
      </div>
    </>
  )
}
