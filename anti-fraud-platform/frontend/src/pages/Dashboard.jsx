import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import axios from 'axios'

const API_URL = 'http://localhost:5000/api'

function Dashboard({ user, token, onLogout }) {
  const [stats, setStats] = useState({
    totalEmails: 0,
    phishingDetected: 0,
    safeEmails: 0
  })
  const [recentEmails, setRecentEmails] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchDashboardData()
  }, [])

  const fetchDashboardData = async () => {
    try {
      const response = await axios.get(`${API_URL}/email/history`, {
        headers: { Authorization: `Bearer ${token}` }
      })

      if (response.data.success) {
        const emails = response.data.data || []
        setRecentEmails(emails)
        
        // Calculate stats
        const totalEmails = emails.length
        const phishingDetected = emails.filter(e => 
          e.threat_level === 'dangerous' || e.threat_level === 'critical'
        ).length
        const safeEmails = emails.filter(e => e.threat_level === 'safe').length
        
        setStats({ totalEmails, phishingDetected, safeEmails })
      }
    } catch (err) {
      console.error('Error fetching dashboard data:', err)
    } finally {
      setLoading(false)
    }
  }

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString()
  }

  return (
    <div>
      <nav className="navbar">
        <h2>🛡️ Anti-Fraud Platform</h2>
        <div className="navbar-right">
          <span className="navbar-user">👤 {user?.name || 'User'}</span>
          <Link to="/analyze">
            <button className="btn-secondary">Analyze Email</button>
          </Link>
          <button className="btn-secondary" onClick={onLogout}>Logout</button>
        </div>
      </nav>

      <div className="dashboard-container">
        <div className="stats-grid">
          <div className="stat-card info">
            <h3>Total Emails Analyzed</h3>
            <div className="stat-value">{stats.totalEmails}</div>
          </div>
          <div className="stat-card danger">
            <h3>Phishing Detected</h3>
            <div className="stat-value">{stats.phishingDetected}</div>
          </div>
          <div className="stat-card success">
            <h3>Safe Emails</h3>
            <div className="stat-value">{stats.safeEmails}</div>
          </div>
        </div>

        <div className="email-list">
          <h2>Recent Analysis History</h2>
          {loading ? (
            <div className="empty-state">Loading...</div>
          ) : recentEmails.length === 0 ? (
            <div className="empty-state">
              <p>No emails analyzed yet. Start by analyzing your first email!</p>
              <Link to="/analyze">
                <button className="btn-primary" style={{ marginTop: '20px', maxWidth: '200px' }}>
                  Analyze Email
                </button>
              </Link>
            </div>
          ) : (
            recentEmails.map((email, index) => (
              <div key={index} className="email-item">
                <div className="email-header">
                  <div className="email-subject">{email.subject}</div>
                  <span className={`threat-badge ${email.threat_level}`}>
                    {email.threat_level}
                  </span>
                </div>
                <div className="email-details">
                  <div>From: {email.sender_email}</div>
                  <div>Threat Score: {email.threat_score}/100</div>
                  <div>Analyzed: {formatDate(email.analyzed_at)}</div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}

export default Dashboard
