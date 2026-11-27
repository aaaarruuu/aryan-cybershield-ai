import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { api, setUnauthorizedHandler, tokenStore } from '../services/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(!!tokenStore.get())

  const clear = useCallback(() => { tokenStore.clear(); setUser(null) }, [])

  useEffect(() => {
    setUnauthorizedHandler(clear) // expired/revoked token => back to login
    if (!tokenStore.get()) return
    api.me().then(setUser).catch(clear).finally(() => setLoading(false))
  }, [clear])

  const accept = (res) => { tokenStore.set(res.access_token); setUser(res.user); return res.user }
  const value = useMemo(() => ({
    user, loading,
    isAdmin: user?.role === 'admin',
    login: async (email, password) => accept(await api.login({ email, password })),
    register: async (email, full_name, password) => accept(await api.register({ email, full_name, password })),
    logout: async () => { try { await api.logout() } catch { /* token may already be invalid */ } clear() },
    refresh: async () => setUser(await api.me()),
  }), [user, loading, clear])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export const useAuth = () => useContext(AuthContext)
