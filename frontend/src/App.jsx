import { Navigate, Route, Routes } from 'react-router-dom'
import ProtectedRoute from './components/ProtectedRoute'
import AppLayout from './layouts/AppLayout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import ThreatIntel from './pages/ThreatIntel'
import Phishing from './pages/Phishing'
import LogAnalyzer from './pages/LogAnalyzer'
import Investigate from './pages/Investigate'
import Incidents from './pages/Incidents'
import Knowledge from './pages/Knowledge'
import Approvals from './pages/Approvals'
import Reports from './pages/Reports'
import Profile from './pages/Profile'
import Admin from './pages/Admin'
import About from './pages/About'

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<AppLayout />}>
          <Route index element={<Dashboard />} />
          <Route path="intel" element={<ThreatIntel />} />
          <Route path="phishing" element={<Phishing />} />
          <Route path="logs" element={<LogAnalyzer />} />
          <Route path="investigate" element={<Investigate />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="knowledge" element={<Knowledge />} />
          <Route path="approvals" element={<Approvals />} />
          <Route path="reports" element={<Reports />} />
          <Route path="profile" element={<Profile />} />
          <Route path="about" element={<About />} />
          <Route element={<ProtectedRoute adminOnly />}><Route path="admin" element={<Admin />} /></Route>
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
