import { useRef, useState } from 'react'
import { api } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { useAuth } from '../context/AuthContext'
import { Async, Badge, Confirm, Empty, ErrorBox, Notice, PageHeader, Section, fmt } from '../components/ui'

export default function Knowledge() {
  const { isAdmin } = useAuth()
  const docs = useAsync(() => api.docs(), [])
  const file = useRef()
  const [q, setQ] = useState('')
  const [hits, setHits] = useState(null)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)
  const wrap = async (fn) => { setBusy(true); setError(''); setMsg(''); try { await fn() } catch (e) { setError(e.message) } finally { setBusy(false) } }
  const upload = (e) => { e.preventDefault(); const f = file.current?.files?.[0]; if (!f) return setError('Choose a PDF, TXT, MD, CSV or JSON file'); wrap(async () => { const r = await api.uploadDoc(f); setMsg(`Added ${r.filename}: ${r.chunk_count} chunks${r.injection_flagged_chunks ? ` (${r.injection_flagged_chunks} chunk(s) flagged as possible prompt-injection and excluded from agent context)` : ''}`); file.current.value = ''; docs.reload() }) }
  const search = (e) => { e.preventDefault(); if (q.trim().length < 2) return setError('Enter at least 2 characters'); wrap(async () => setHits(await api.searchKnowledge(q.trim()))) }
  return (
    <>
      <PageHeader title="Knowledge Base" subtitle="Security documents used by the Response agent. Retrieval is lexical similarity with source citations; if nothing relevant exists, the system says so. All document text is treated as untrusted.">
        {isAdmin && <button className="btn-ghost" disabled={busy} onClick={() => wrap(async () => { const r = await api.loadBuiltinKnowledge(); setMsg(`Loaded: ${r.loaded.join(', ') || 'nothing new'}`); docs.reload() })}>Load MITRE ATT&CK + playbooks</button>}
      </PageHeader>
      <div className="mb-4 space-y-2"><ErrorBox message={error} />{msg && <Notice tone="ok">{msg}</Notice>}</div>
      <div className="grid gap-6 lg:grid-cols-2">
        <div className="space-y-6">
          <Section title="Upload document"><form onSubmit={upload} className="flex flex-wrap items-center gap-3"><input ref={file} type="file" aria-label="Document" accept=".pdf,.txt,.md,.csv,.json" className="text-sm text-slate-300 file:mr-3 file:rounded-lg file:border-0 file:bg-navy-600 file:px-3 file:py-2 file:text-slate-100" /><button className="btn-primary" disabled={busy}>Upload</button></form></Section>
          <Section title="Documents"><Async state={docs}>{(rows) => rows.length === 0 ? <Empty title="Knowledge base is empty" hint={isAdmin ? 'Load the bundled ATT&CK summary and playbooks, or upload your own.' : 'Ask an administrator to load the bundled documents, or upload your own.'} /> :
            <ul className="space-y-2">{rows.map((d) => <li key={d.id} className="flex items-center justify-between gap-2 rounded-lg bg-navy-900 p-2 text-sm"><div className="min-w-0"><p className="truncate text-slate-200">{d.filename}</p><p className="text-xs text-slate-500">{d.chunk_count} chunks · {(d.size_bytes / 1024).toFixed(0)} KB · {fmt(d.created_at)}</p></div>{isAdmin && <Confirm className="btn-ghost !py-1" text="Delete?" onConfirm={() => wrap(async () => { await api.deleteDoc(d.id); docs.reload() })}>Delete</Confirm>}</li>)}</ul>}</Async></Section>
        </div>
        <Section title="Semantic search">
          <form onSubmit={search} className="flex gap-2"><input aria-label="Search query" className="input" placeholder="e.g. how to contain brute force attacks" value={q} onChange={(e) => setQ(e.target.value)} /><button className="btn-primary" disabled={busy}>Search</button></form>
          <div className="mt-4 space-y-3">{hits && (hits.has_relevant ? hits.results.map((r, i) => <div key={i} className="rounded-lg bg-navy-900 p-3 text-sm"><div className="mb-1 flex items-center gap-2"><span className="font-medium text-cyan-300">{r.citation}</span><span className="text-xs text-slate-500">similarity {r.similarity}</span>{r.injection_suspected && <Badge value="suspicious">possible injection</Badge>}</div><p className="whitespace-pre-wrap text-slate-300">{r.text.slice(0, 500)}{r.text.length > 500 ? '…' : ''}</p></div>) : <Notice tone="warn">{hits.message}</Notice>)}</div>
        </Section>
      </div>
    </>
  )
}
