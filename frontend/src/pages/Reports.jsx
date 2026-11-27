import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { Async, Badge, Empty, PageHeader, Section, fmt } from '../components/ui'

const COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#34d399' }

export default function Reports() {
  const stats = useAsync(() => api.stats(30), [])
  const invs = useAsync(() => api.investigations(), [])
  return (
    <>
      <PageHeader title="Analytics & Reports" subtitle="Export investigation reports (PDF/CSV) that separate verified findings from AI hypotheses, and incident data (CSV).">
        <button className="btn-ghost" onClick={() => api.downloadIncidentsCsv()}>Export all incidents (CSV)</button>
      </PageHeader>
      <div className="grid gap-6 lg:grid-cols-2">
        <Section title="Incidents by severity"><Async state={stats}>{(s) => s.total_incidents === 0 ? <Empty title="No incidents to chart" /> :
          <ResponsiveContainer width="100%" height={240}><BarChart data={Object.entries(s.incidents_by_severity).map(([name, value]) => ({ name, value }))}><CartesianGrid stroke="#16294f" /><XAxis dataKey="name" stroke="#64748b" /><YAxis allowDecimals={false} stroke="#64748b" /><Tooltip contentStyle={{ background: '#0a1428', border: '1px solid #1e3a6b' }} /><Bar dataKey="value" radius={[4, 4, 0, 0]}>{Object.keys(s.incidents_by_severity).map((k) => <Cell key={k} fill={COLORS[k]} />)}</Bar></BarChart></ResponsiveContainer>}</Async></Section>
        <Section title="Detection summary"><Async state={stats}>{(s) => <dl className="grid grid-cols-2 gap-3 text-sm">{[['Events analysed', s.total_events], ['Flagged events', s.suspicious_events], ['Phishing detections', s.phishing_detections], ['Malicious indicators', s.malicious_indicators], ['Resolved incidents', s.resolved_incidents], ['Pending approvals', s.pending_approvals]].map(([k, v]) => <div key={k} className="rounded-lg bg-navy-900 p-3"><dt className="text-xs text-slate-500">{k}</dt><dd className="text-xl font-semibold text-slate-100">{v}</dd></div>)}</dl>}</Async></Section>
      </div>
      <div className="mt-6"><Section title="Investigation reports"><Async state={invs}>{(rows) => rows.length === 0 ? <Empty title="No investigations yet" hint="Run one from the AI Investigation Center to generate a report." /> :
        <div className="overflow-x-auto"><table className="w-full"><thead><tr><th className="th">#</th><th className="th">Title</th><th className="th">Risk</th><th className="th">Status</th><th className="th">Created</th><th className="th">Export</th></tr></thead><tbody>
          {rows.map((i) => <tr key={i.id} className="border-t border-navy-700"><td className="td">{i.id}</td><td className="td">{i.title}</td><td className="td">{i.risk_level ? <Badge value={i.risk_level} /> : '—'}</td><td className="td"><Badge value={i.status} /></td><td className="td text-xs">{fmt(i.created_at)}</td>
            <td className="td">{i.status === 'completed' ? <span className="flex gap-2"><button className="btn-ghost !py-1" onClick={() => api.downloadInvestigation(i.id, 'pdf')}>PDF</button><button className="btn-ghost !py-1" onClick={() => api.downloadInvestigation(i.id, 'csv')}>CSV</button></span> : '—'}</td></tr>)}</tbody></table></div>}</Async></Section></div>
    </>
  )
}
