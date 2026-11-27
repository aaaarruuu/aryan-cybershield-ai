import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Async, Badge, Confirm, Empty, ErrorBox, Spinner } from '../components/ui'
import { IntelResult } from '../pages/ThreatIntel'
import { api, setUnauthorizedHandler, tokenStore } from '../services/api'

afterEach(() => { vi.restoreAllMocks(); tokenStore.clear() })
const mockFetch = (status, body) => vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: status < 400, status, json: async () => body, blob: async () => new Blob(['x']) })

describe('Async states', () => {
  it('shows a loading indicator', () => { render(<Async state={{ loading: true, data: null }}>{() => <p>x</p>}</Async>); expect(screen.getByRole('status')).toBeInTheDocument() })
  it('shows an error with a working retry', async () => {
    const reload = vi.fn(); render(<Async state={{ loading: false, error: 'Boom', reload }}>{() => <p>x</p>}</Async>)
    expect(screen.getByRole('alert')).toHaveTextContent('Boom'); await userEvent.click(screen.getByText('Retry')); expect(reload).toHaveBeenCalled()
  })
  it('renders data when loaded', () => { render(<Async state={{ loading: false, data: [1] }}>{(d) => <p>{d.length} item</p>}</Async>); expect(screen.getByText('1 item')).toBeInTheDocument() })
  it('Empty, ErrorBox(null), Spinner and Badge render sensibly', () => {
    const { container } = render(<><Empty title="Nothing here" hint="Add one" /><ErrorBox message="" /><Spinner /><Badge value="under_investigation" /></>)
    expect(screen.getByText('Nothing here')).toBeInTheDocument(); expect(screen.getByText('under investigation')).toBeInTheDocument(); expect(container.querySelectorAll('[role=alert]')).toHaveLength(0)
  })
  it('Confirm requires a second click', async () => {
    const fn = vi.fn(); render(<Confirm onConfirm={fn}>Delete</Confirm>)
    await userEvent.click(screen.getByText('Delete')); expect(fn).not.toHaveBeenCalled(); await userEvent.click(screen.getByText('Yes')); expect(fn).toHaveBeenCalled()
  })
})

describe('Threat intel result honesty', () => {
  const base = { indicator: '1.2.3.4', type: 'ip', source: 'demo-sample-data', demo: true, looked_up_at: '2026-01-01T00:00:00Z', cached: false, details: {} }
  it('labels demo data and warns that unknown is not clean', () => {
    render(<IntelResult r={{ ...base, verdict: 'unknown', is_ioc: false }} />)
    expect(screen.getByText(/demo dataset/i)).toBeInTheDocument(); expect(screen.getByText(/does not mean the indicator is safe/i)).toBeInTheDocument()
  })
  it('flags unavailable lookups without assuming a verdict', () => {
    render(<IntelResult r={{ ...base, demo: false, source: 'virustotal', verdict: 'unavailable', details: { error: 'rate limit' } }} />)
    expect(screen.getByText(/Lookup unavailable: rate limit/)).toBeInTheDocument(); expect(screen.getByText(/No verdict has been assumed/)).toBeInTheDocument()
  })
  it('shows source and timestamp', () => { render(<IntelResult r={{ ...base, verdict: 'malicious', is_ioc: true }} />); expect(screen.getByText(/Source: demo-sample-data/)).toBeInTheDocument() })
})

describe('API client', () => {
  it('sends the bearer token and JSON body', async () => {
    tokenStore.set('abc'); const f = mockFetch(200, { ok: 1 })
    await api.lookup('8.8.8.8', true)
    const [url, init] = f.mock.calls[0]
    expect(String(url)).toContain('/api/intel/lookup'); expect(String(url)).toContain('refresh=true')
    expect(init.headers.Authorization).toBe('Bearer abc'); expect(JSON.parse(init.body)).toEqual({ value: '8.8.8.8' })
  })
  it('turns FastAPI validation errors into readable messages', async () => {
    mockFetch(422, { detail: [{ loc: ['body', 'title'], msg: 'String should have at least 3 characters' }] })
    await expect(api.createIncident({ title: 'x' })).rejects.toThrow('title: String should have at least 3 characters')
  })
  it('reports unreachable backend', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('fail'))
    await expect(api.stats()).rejects.toThrow(/Cannot reach the server/)
  })
  it('calls the unauthorized handler on 401 with a token', async () => {
    tokenStore.set('old'); const h = vi.fn(); setUnauthorizedHandler(h); mockFetch(401, { detail: 'Invalid or expired credentials' })
    await expect(api.me()).rejects.toThrow('Invalid or expired credentials'); expect(h).toHaveBeenCalled()
  })
  it('handles 204 and rate-limit responses', async () => {
    mockFetch(204, null); expect(await api.logout()).toBeNull()
    mockFetch(429, {}); await expect(api.stats()).rejects.toThrow(/Too many requests/)
  })
})

describe('Badge', () => {
  it('shows custom children instead of the status word', () => {
    render(<Badge value="open">investigation.completed</Badge>)
    expect(screen.getByText('investigation.completed')).toBeInTheDocument()
    expect(screen.queryByText('open')).not.toBeInTheDocument()
  })
})
