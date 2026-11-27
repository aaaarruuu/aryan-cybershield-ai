import { useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { ErrorBox, Field } from '../components/ui'

export function validate({ mode, email, name, password }) {
  const errs = {}
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) errs.email = 'Enter a valid email address'
  if (mode === 'register') {
    if (name.trim().length < 2) errs.name = 'Name must be at least 2 characters'
    if (password.length < 10) errs.password = 'Password must be at least 10 characters'
    else if (!/[A-Za-z]/.test(password) || !/\d/.test(password)) errs.password = 'Password must contain letters and digits'
  } else if (!password) errs.password = 'Enter your password'
  return errs
}

export default function Login() {
  const { user, login, register } = useAuth()
  const nav = useNavigate()
  const [mode, setMode] = useState('login')
  const [f, setF] = useState({ email: '', name: '', password: '' })
  const [errs, setErrs] = useState({})
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  if (user) return <Navigate to="/" replace />

  const submit = async (e) => {
    e.preventDefault()
    const v = validate({ mode, ...f })
    setErrs(v); setError('')
    if (Object.keys(v).length) return
    setBusy(true)
    try {
      if (mode === 'login') await login(f.email, f.password)
      else await register(f.email, f.name, f.password)
      nav('/')
    } catch (err) { setError(err.message) } finally { setBusy(false) }
  }
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  const err = (k) => errs[k] && <p role="alert" className="mt-1 text-xs text-red-300">{errs[k]}</p>

  return (
    <div className="grid min-h-full place-items-center bg-gradient-to-br from-navy-950 via-navy-900 to-navy-800 p-4">
      <div className="w-full max-w-md">
        <div className="mb-6 text-center">
          <h1 className="text-3xl font-bold tracking-wide text-white">ARYAN CYBERSHIELD AI</h1>
          <p className="mt-1 text-sm text-cyan-400">Agentic AI-Based Cybersecurity Intelligence and Threat Investigation Platform</p>
          <p className="mt-1 text-xs text-slate-500">Developed by Aryan</p>
        </div>
        <form onSubmit={submit} noValidate className="card space-y-4" aria-label={mode === 'login' ? 'Sign in' : 'Create account'}>
          <h2 className="text-lg font-semibold text-white">{mode === 'login' ? 'Sign in' : 'Create account'}</h2>
          <ErrorBox message={error} />
          {mode === 'register' && <Field label="Full name" id="name"><input id="name" className="input" value={f.name} onChange={set('name')} autoComplete="name" />{err('name')}</Field>}
          <Field label="Email" id="email"><input id="email" type="email" className="input" value={f.email} onChange={set('email')} autoComplete="email" />{err('email')}</Field>
          <Field label="Password" id="password" hint={mode === 'register' ? 'At least 10 characters, with letters and digits.' : undefined}>
            <input id="password" type="password" className="input" value={f.password} onChange={set('password')} autoComplete={mode === 'login' ? 'current-password' : 'new-password'} />{err('password')}
          </Field>
          <button className="btn-primary w-full" disabled={busy}>{busy ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'}</button>
          <p className="text-center text-sm text-slate-400">
            {mode === 'login' ? 'No account yet?' : 'Already registered?'}{' '}
            <button type="button" className="text-cyan-400 underline" onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setErrs({}); setError('') }}>
              {mode === 'login' ? 'Create one' : 'Sign in'}</button>
          </p>
          {mode === 'register' && <p className="text-center text-xs text-slate-500">The first account created becomes the administrator.</p>}
        </form>
      </div>
    </div>
  )
}
