import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { Async, Badge, Empty, Notice, PageHeader, Section, Stat, fmt, label } from '../components/ui'

const SEV_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#34d399' }
const tip = { contentStyle: { background: '#0a1428', border: '1px solid #1e3a6b', borderRadius: 8, color: '#e2e8f0' } }

export default function Dashboard() {
  const [days, setDays] = useState(14)
  const state = useAsync(() => api.stats(days), [days])
  const incidents = useAsync(() => api.incidents({ limit: 8 }), [])
  return (
    <>
      <PageHeader title="Security Operations Dashboard" subtitle="Live figures computed from the platform database.">
        <select aria-label="Time range" className="input !w-auto" value={days} onChange={(e) => setDays(Number(e.target.value))}>
          {[7, 14, 30, 90].map((d) => <option key={d} value={d}>Last {d} days</option>)}
        </select>
        <button className="btn-ghost" onClick={() => { state.reload(); incidents.reload() }}>Refresh</button>
      </PageHeader>
      <Async state={state}>{(s) => {
        const sev = Object.entries(s.incidents_by_severity).map(([name, value]) => ({ name, value }))
        const empty = s.total_events === 0 && s.total_incidents === 0
        return (
          <div className="space-y-6">
            {s.demo_mode && <Notice tone="warn"><strong>Demo mode:</strong> threat-intelligence verdicts come from a bundled sample dataset, and response actions are simulated only.</Notice>}
            {empty && <Empty title="No security data yet" hint="Upload a log file, analyse an email, or load the bundled sample log to see the dashboard populate.">
              <Link to="/logs" className="btn-primary">Open Log Analyzer</Link><Link to="/phishing" className="btn-ghost">Analyse an email</Link></Empty>}
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
              <Stat label="Security events" value={s.total_events} />
              <Stat label="Suspicious events" value={s.suspicious_events} tone="orange" />
              <Stat label="Phishing detections" value={s.phishing_detections} sub={`${s.suspicious_emails} suspicious emails`} tone="red" />
              <Stat label="Suspicious logins" value={s.suspicious_login_attempts} tone="orange" />
              <Stat label="Malicious indicators" value={s.malicious_indicators} sub={s.malicious_indicators_demo ? `${s.malicious_indicators_demo} from demo data` : undefined} tone="red" />
              <Stat label="Active investigations" value={s.active_investigations} tone="purple" />
              <Stat label="Resolved incidents" value={s.resolved_incidents} tone="green" />
              <Stat label="Pending approvals" value={s.pending_approvals} tone="purple" />
            </div>
            <div className="grid gap-6 lg:grid-cols-3">
              <div className="lg:col-span-2"><Section title="Threat trend">
                {s.trend.length === 0 ? <Empty title="No trend data in this period" /> :
                  <ResponsiveContainer width="100%" height={260}><LineChart data={s.trend}><CartesianGrid stroke="#16294f" /><XAxis dataKey="date" stroke="#64748b" fontSize={11} /><YAxis allowDecimals={false} stroke="#64748b" fontSize={11} /><Tooltip {...tip} /><Legend />
                    <Line type="monotone" dataKey="suspicious_events" name="Suspicious events" stroke="#22d3ee" strokeWidth={2} dot={false} /><Line type="monotone" dataKey="incidents" name="Incidents" stroke="#f97316" strokeWidth={2} dot /></LineChart></ResponsiveContainer>}
              </Section></div>
              <Section title="Incidents by severity">
                {s.total_incidents === 0 ? <Empty title="No incidents" /> :
                  <ResponsiveContainer width="100%" height={260}><PieChart><Pie data={sev} dataKey="value" nameKey="name" innerRadius={55} outerRadius={90} paddingAngle={2}>{sev.map((e) => <Cell key={e.name} fill={SEV_COLORS[e.name]} />)}</Pie><Tooltip {...tip} /><Legend /></PieChart></ResponsiveContainer>}
              </Section>
            </div>
            <div className="grid gap-6 lg:grid-cols-3">
              <div className="lg:col-span-2"><Section title="Recent incidents" right={<Link className="text-xs text-cyan-400" to="/incidents">View all</Link>}>
                <Async state={incidents}>{(rows) => rows.length === 0 ? <Empty title="No incidents recorded" /> :
                  <div className="overflow-x-auto"><table className="w-full"><thead><tr><th className="th">ID</th><th className="th">Title</th><th className="th">Severity</th><th className="th">Status</th></tr></thead>
                    <tbody>{rows.map((r) => <tr key={r.id} className="border-t border-navy-700"><td className="td font-mono text-xs">{r.incident_uid}</td><td className="td">{r.title}</td><td className="td"><Badge value={r.severity} /></td><td className="td"><Badge value={r.status} /></td></tr>)}</tbody></table></div>}</Async>
              </Section></div>
              <Section title="Recent activity">
                {s.recent_activity.length === 0 ? <Empty title="No activity" /> :
                  <ul className="space-y-2 text-sm">{s.recent_activity.map((a, i) => <li key={i} className="border-b border-navy-700 pb-2"><p className="text-slate-200">{label(a.action)}</p><p className="text-xs text-slate-500">{a.actor || 'system'} · {fmt(a.at)}</p></li>)}</ul>}
              </Section>
            </div>
            <Section title="Incident status">
              <ResponsiveContainer width="100%" height={180}><BarChart data={Object.entries(s.incidents_by_status).map(([name, value]) => ({ name: label(name), value }))}><CartesianGrid stroke="#16294f" /><XAxis dataKey="name" stroke="#64748b" fontSize={11} /><YAxis allowDecimals={false} stroke="#64748b" fontSize={11} /><Tooltip {...tip} /><Bar dataKey="value" fill="#22d3ee" radius={[4, 4, 0, 0]} /></BarChart></ResponsiveContainer>
            </Section>
          </div>
        )
      }}</Async>
    </>
  )
}
