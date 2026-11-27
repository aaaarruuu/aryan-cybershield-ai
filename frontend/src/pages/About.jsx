import { api } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { Async, PageHeader, Section } from '../components/ui'

export default function About() {
  const info = useAsync(() => api.about(), [])
  return (
    <>
      <PageHeader title="About Project" />
      <Async state={info}>{(i) => (
        <div className="grid max-w-4xl gap-6">
          <Section title={i.name}><p className="text-slate-300">{i.subtitle}</p><p className="mt-3 text-lg font-semibold text-cyan-400">Project Developed By: {i.developed_by}</p><p className="text-xs text-slate-500">Version {i.version}</p></Section>
          <Section title="What it does"><ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">
            <li>Phishing analysis combining deterministic checks with an ML text classifier.</li><li>Threat-intelligence lookups (VirusTotal, or a labelled demo dataset) with caching and source attribution.</li>
            <li>Security-log analysis with rules and Isolation Forest anomaly detection.</li><li>A LangGraph multi-agent investigation workflow with evidence-based risk scoring.</li><li>A RAG knowledge base with citations, incident management, and human-approved (simulated) response actions.</li></ul></Section>
          <Section title="Honest limitations"><ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">
            <li>It does not detect every attack; ML models here are trained on small synthetic data and are not production-grade.</li><li>Response actions are simulated; no real infrastructure is changed.</li><li>Retrieval is lexical, not deep semantic.</li><li>See documentation/LIMITATIONS.md for the full list.</li></ul></Section>
        </div>)}</Async>
    </>
  )
}
