import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider } from '../context/AuthContext'
import Login, { validate } from '../pages/Login'
import ProtectedRoute from '../components/ProtectedRoute'
import { api, tokenStore } from '../services/api'

vi.mock('../services/api', async (orig) => {
  const real = await orig()
  return { ...real, api: { login: vi.fn(), register: vi.fn(), me: vi.fn(), logout: vi.fn() } }
})

const USER = { id: 1, email: 'a@b.com', full_name: 'Ann Analyst', role: 'analyst', is_active: true, created_at: '2026-01-01T00:00:00Z' }
const setup = (path = '/login') => render(
  <MemoryRouter initialEntries={[path]}><AuthProvider>
    <Routes><Route path="/login" element={<Login />} /><Route element={<ProtectedRoute />}><Route path="/" element={<p>Secret dashboard</p>} /></Route></Routes>
  </AuthProvider></MemoryRouter>)

beforeEach(() => { vi.clearAllMocks(); tokenStore.clear() })

describe('validate()', () => {
  it('flags bad email, short/weak passwords and short names on register', () => {
    expect(validate({ mode: 'register', email: 'nope', name: 'A', password: 'short' })).toEqual({ email: expect.any(String), name: expect.any(String), password: expect.any(String) })
    expect(validate({ mode: 'register', email: 'a@b.com', name: 'Ann', password: 'onlyletterspass' }).password).toMatch(/letters and digits/)
  })
  it('accepts valid input and only requires a password on login', () => {
    expect(validate({ mode: 'register', email: 'a@b.com', name: 'Ann', password: 'StrongPass123' })).toEqual({})
    expect(validate({ mode: 'login', email: 'a@b.com', name: '', password: 'x' })).toEqual({})
    expect(validate({ mode: 'login', email: 'a@b.com', name: '', password: '' }).password).toBeTruthy()
  })
})

describe('Login page', () => {
  it('shows project identity', () => {
    setup()
    expect(screen.getByText('ARYAN CYBERSHIELD AI')).toBeInTheDocument()
    expect(screen.getByText(/Developed by Aryan/)).toBeInTheDocument()
  })
  it('shows validation errors and does not call the API', async () => {
    setup()
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findAllByRole('alert')).not.toHaveLength(0)
    expect(api.login).not.toHaveBeenCalled()
  })
  it('logs in, stores the token and reaches the protected page', async () => {
    api.login.mockResolvedValue({ access_token: 'tok123', user: USER })
    setup()
    await userEvent.type(screen.getByLabelText('Email'), 'a@b.com')
    await userEvent.type(screen.getByLabelText('Password'), 'StrongPass123')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    await waitFor(() => expect(api.login).toHaveBeenCalledWith({ email: 'a@b.com', password: 'StrongPass123' }))
    expect(tokenStore.get()).toBe('tok123')
  })
  it('displays the server error on failed login and stays logged out', async () => {
    api.login.mockRejectedValue(new Error('Incorrect email or password'))
    setup()
    await userEvent.type(screen.getByLabelText('Email'), 'a@b.com')
    await userEvent.type(screen.getByLabelText('Password'), 'wrongpassword1')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByText('Incorrect email or password')).toBeInTheDocument()
    expect(tokenStore.get()).toBeNull()
  })
  it('switches to registration and validates the password rule', async () => {
    setup()
    await userEvent.click(screen.getByRole('button', { name: 'Create one' }))
    await userEvent.type(screen.getByLabelText('Full name'), 'Ann')
    await userEvent.type(screen.getByLabelText('Email'), 'a@b.com')
    await userEvent.type(screen.getByLabelText('Password'), 'short')
    await userEvent.click(screen.getByRole('button', { name: 'Create account' }))
    expect(await screen.findByText(/at least 10 characters/i, { selector: 'p[role=alert]' })).toBeInTheDocument()
    expect(api.register).not.toHaveBeenCalled()
  })
})

describe('ProtectedRoute', () => {
  it('redirects unauthenticated visitors to login', async () => {
    setup('/')
    expect(await screen.findByRole('form', { name: 'Sign in' })).toBeInTheDocument()
    expect(screen.queryByText('Secret dashboard')).not.toBeInTheDocument()
  })
  it('lets an authenticated user (valid stored token) through', async () => {
    tokenStore.set('tok'); api.me.mockResolvedValue(USER)
    setup('/')
    expect(await screen.findByText('Secret dashboard')).toBeInTheDocument()
  })
  it('sends the user to login when the stored token is rejected', async () => {
    tokenStore.set('expired'); api.me.mockRejectedValue(new Error('Invalid or expired credentials'))
    setup('/')
    expect(await screen.findByRole('form', { name: 'Sign in' })).toBeInTheDocument()
    expect(tokenStore.get()).toBeNull()
  })
})
