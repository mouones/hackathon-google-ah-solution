import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import Login from './pages/Login'
import Register from './pages/Register'
import Dashboard from './pages/Dashboard'
import AnalyzeEmail from './pages/AnalyzeEmail'
import './App.css'

function App() {
  const [token, setToken] = useState(localStorage.getItem('token'))
  const [user, setUser] = useState(null)

  useEffect(() => {
    const storedUser = localStorage.getItem('user')
    if (storedUser) {
      setUser(JSON.parse(storedUser))
    }
  }, [])

  const handleLogin = (authToken, userData) => {
    setToken(authToken)
    setUser(userData)
    localStorage.setItem('token', authToken)
    localStorage.setItem('user', JSON.stringify(userData))
  }

  const handleLogout = () => {
    setToken(null)
    setUser(null)
    localStorage.removeItem('token')
    localStorage.removeItem('user')
  }

  return (
    <Router>
      <Routes>
        <Route path="/login" element={
          !token ? <Login onLogin={handleLogin} /> : <Navigate to="/dashboard" />
        } />
        <Route path="/register" element={
          !token ? <Register onRegister={handleLogin} /> : <Navigate to="/dashboard" />
        } />
        <Route path="/dashboard" element={
          token ? <Dashboard user={user} token={token} onLogout={handleLogout} /> : <Navigate to="/login" />
        } />
        <Route path="/analyze" element={
          token ? <AnalyzeEmail user={user} token={token} onLogout={handleLogout} /> : <Navigate to="/login" />
        } />
        <Route path="/" element={<Navigate to={token ? "/dashboard" : "/login"} />} />
      </Routes>
    </Router>
  )
}

export default App
