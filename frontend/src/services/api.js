// Thin API client. The JWT is kept in sessionStorage (cleared when the tab closes) and sent as a Bearer header.
// API keys for third-party services never reach the browser: lookups go through the backend.
const TOKEN_KEY = 'cybershield_token'

export const tokenStore = {
  get() { try { return sessionStorage.getItem(TOKEN_KEY) } catch { return null } },
  set(t) { try { sessionStorage.setItem(TOKEN_KEY, t) } catch { /* storage unavailable */ } },
  clear() { try { sessionStorage.removeItem(TOKEN_KEY) } catch { /* ignore */ } },
}

export class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status }
}

let onUnauthorized = () => {}
export const setUnauthorizedHandler = (fn) => { onUnauthorized = fn }

function messageFrom(body, status) {
  const d = body && body.detail
  if (typeof d === 'string') return d
  if (Array.isArray(d)) return d.map((e) => `${(e.loc || []).slice(1).join('.')}: ${e.msg}`).join('; ')
  return status === 429 ? 'Too many requests. Please wait a moment.' : `Request failed (${status})`
}

async function request(path, { method = 'GET', body, form, params, raw } = {}) {
  const url = new URL(`/api${path}`, window.location.origin)
  if (params) Object.entries(params).forEach(([k, v]) => v !== undefined && v !== null && v !== '' && url.searchParams.set(k, v))
  const headers = {}
  const token = tokenStore.get()
  if (token) headers.Authorization = `Bearer ${token}`
  let payload
  if (form) payload = form
  else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body) }
  let res
  try {
    res = await fetch(url, { method, headers, body: payload })
  } catch {
    throw new ApiError('Cannot reach the server. Check that the backend is running.', 0)
  }
  if (res.status === 401 && token) onUnauthorized()
  if (!res.ok) {
    let data = null
    try { data = await res.json() } catch { /* non-JSON error */ }
    throw new ApiError(messageFrom(data, res.status), res.status)
  }
  if (raw) return res
  if (res.status === 204) return null
  return res.json()
}

async function download(path, params, filename) {
  const res = await request(path, { params, raw: true })
  const blob = await res.blob()
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(a.href)
}

export const api = {
  register: (b) => request('/auth/register', { method: 'POST', body: b }),
  login: (b) => request('/auth/login', { method: 'POST', body: b }),
  logout: () => request('/auth/logout', { method: 'POST' }),
  me: () => request('/auth/me'),
  updateMe: (b) => request('/auth/me', { method: 'PATCH', body: b }),
  users: () => request('/auth/users'),
  updateUser: (id, b) => request(`/auth/users/${id}`, { method: 'PATCH', body: b }),

  stats: (days = 14) => request('/dashboard/stats', { params: { days } }),
  about: () => request('/about'),
  adminSettings: () => request('/admin/settings'),
  audit: (action) => request('/audit', { params: { action, limit: 100 } }),

  analysePhishing: (b) => request('/phishing/analyse', { method: 'POST', body: b }),
  modelReport: () => request('/phishing/model-report'),
  lookup: (value, refresh) => request('/intel/lookup', { method: 'POST', body: { value }, params: { refresh } }),
  indicators: (verdict) => request('/intel/indicators', { params: { verdict } }),

  uploadLogs: (file) => { const f = new FormData(); f.append('file', file); return request('/logs/upload', { method: 'POST', form: f }) },
  loadSampleLogs: () => request('/logs/load-sample', { method: 'POST' }),
  batches: () => request('/logs/batches'),
  batchAnalysis: (id) => request(`/logs/batches/${id}/analysis`),
  events: (params) => request('/logs/events', { params }),

  startInvestigation: (b) => request('/investigations', { method: 'POST', body: b }),
  investigations: () => request('/investigations'),
  investigation: (id) => request(`/investigations/${id}`),

  incidents: (params) => request('/incidents', { params }),
  incident: (id) => request(`/incidents/${id}`),
  createIncident: (b) => request('/incidents', { method: 'POST', body: b }),
  updateIncident: (id, b) => request(`/incidents/${id}`, { method: 'PATCH', body: b }),
  addNote: (id, note) => request(`/incidents/${id}/history`, { method: 'POST', body: { note } }),

  docs: () => request('/knowledge/documents'),
  uploadDoc: (file) => { const f = new FormData(); f.append('file', file); return request('/knowledge/documents', { method: 'POST', form: f }) },
  deleteDoc: (id) => request(`/knowledge/documents/${id}`, { method: 'DELETE' }),
  loadBuiltinKnowledge: () => request('/knowledge/load-builtin', { method: 'POST' }),
  searchKnowledge: (q) => request('/knowledge/search', { params: { q } }),

  approvals: (status) => request('/approvals', { params: { status } }),
  createApproval: (b) => request('/approvals', { method: 'POST', body: b }),
  approve: (id, note) => request(`/approvals/${id}/approve`, { method: 'POST', body: { note } }),
  reject: (id, note) => request(`/approvals/${id}/reject`, { method: 'POST', body: { note } }),
  rollback: (id) => request(`/approvals/${id}/rollback`, { method: 'POST' }),

  downloadInvestigation: (id, format) => download(`/reports/investigations/${id}`, { format }, `investigation-${id}.${format}`),
  downloadIncidentsCsv: () => download('/reports/incidents.csv', {}, 'incidents.csv'),
}
