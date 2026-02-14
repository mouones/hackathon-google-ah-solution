import { useState } from 'react'
import { Link } from 'react-router-dom'
import axios from 'axios'

const API_URL = 'http://localhost:5000/api'

function AnalyzeEmail({ user, token, onLogout }) {
  const [formData, setFormData] = useState({
    subject: '',
    body: '',
    sender: '',
    senderName: ''
  })
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    })
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    setResult(null)

    try {
      const response = await axios.post(
        `${API_URL}/email/analyze`,
        formData,
        { headers: { Authorization: `Bearer ${token}` } }
      )

      if (response.data.success) {
        setResult(response.data.data)
        // Reset form
        setFormData({
          subject: '',
          body: '',
          sender: '',
          senderName: ''
        })
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Analysis failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const getThreatClass = (score) => {
    if (score >= 70) return 'critical'
    if (score >= 50) return 'dangerous'
    if (score >= 30) return 'suspicious'
    return 'safe'
  }

  const getRecommendation = (threatLevel) => {
    const recommendations = {
      safe: '✅ This email appears safe. However, always verify sender authenticity before taking action.',
      suspicious: '⚠️ Exercise caution. Verify sender identity and avoid clicking links until confirmed legitimate.',
      dangerous: '🚨 High risk detected. Do not respond or click links. Report to IT security immediately.',
      critical: '⛔ CRITICAL THREAT. Quarantined automatically. Contact security team immediately.'
    }
    return recommendations[threatLevel] || recommendations.safe
  }

  return (
    <div>
      <nav className="navbar">
        <h2>🛡️ Anti-Fraud Platform</h2>
        <div className="navbar-right">
          <span className="navbar-user">👤 {user?.name || 'User'}</span>
          <Link to="/dashboard">
            <button className="btn-secondary">Dashboard</button>
          </Link>
          <button className="btn-secondary" onClick={onLogout}>Logout</button>
        </div>
      </nav>

      <div className="analyze-container">
        <div className="analyze-content">
          <div className="analyze-form">
            <h2>Analyze Email</h2>
            
            {error && <div className="error-message">{error}</div>}
            
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label>Email Subject</label>
                <input
                  type="text"
                  name="subject"
                  value={formData.subject}
                  onChange={handleChange}
                  required
                  placeholder="Enter email subject"
                />
              </div>
              
              <div className="form-group">
                <label>Sender Email</label>
                <input
                  type="email"
                  name="sender"
                  value={formData.sender}
                  onChange={handleChange}
                  required
                  placeholder="sender@example.com"
                />
              </div>
              
              <div className="form-group">
                <label>Sender Name (Optional)</label>
                <input
                  type="text"
                  name="senderName"
                  value={formData.senderName}
                  onChange={handleChange}
                  placeholder="Sender's display name"
                />
              </div>
              
              <div className="form-group">
                <label>Email Body</label>
                <textarea
                  name="body"
                  value={formData.body}
                  onChange={handleChange}
                  required
                  placeholder="Paste the email content here"
                  rows="10"
                />
              </div>
              
              <button type="submit" className="btn-primary" disabled={loading}>
                {loading ? 'Analyzing...' : 'Analyze Email'}
              </button>
            </form>
          </div>

          <div className="analyze-results">
            <h2>Analysis Results</h2>
            
            {!result && !loading && (
              <div className="empty-state">
                Fill out the form and click "Analyze Email" to see results
              </div>
            )}
            
            {loading && (
              <div className="empty-state">
                🔍 Analyzing email with ML model and 6 detection services...
              </div>
            )}
            
            {result && (
              <>
                <div className="threat-score-display">
                  <div className={`threat-circle ${getThreatClass(result.threat_score)}`}>
                    {result.threat_score}
                  </div>
                  <h3 style={{ color: '#333', marginBottom: '5px' }}>Threat Score</h3>
                  <span className={`threat-badge ${result.threat_level}`}>
                    {result.threat_level.toUpperCase()}
                  </span>
                </div>

                <div className="detection-checks">
                  <h3>Detection Checks</h3>
                  
                  <div className="check-item">
                    <span className="check-name">ML Model Prediction</span>
                    <span className={`check-status ${result.detected_threats?.ml_prediction === 'phishing' ? 'fail' : 'pass'}`}>
                      {result.detected_threats?.ml_prediction === 'phishing' ? '⚠️ Phishing' : '✓ Legitimate'}
                    </span>
                  </div>
                  
                  <div className="check-item">
                    <span className="check-name">Character Substitution</span>
                    <span className={`check-status ${result.detected_threats?.character_substitution?.hasSubstitution ? 'fail' : 'pass'}`}>
                      {result.detected_threats?.character_substitution?.hasSubstitution ? '⚠️ Detected' : '✓ Clean'}
                    </span>
                  </div>
                  
                  <div className="check-item">
                    <span className="check-name">Name Mismatch</span>
                    <span className={`check-status ${result.detected_threats?.name_match?.severity !== 'none' ? 'fail' : 'pass'}`}>
                      {result.detected_threats?.name_match?.severity !== 'none' 
                        ? `⚠️ ${result.detected_threats?.name_match?.severity}` 
                        : '✓ Match'}
                    </span>
                  </div>
                  
                  <div className="check-item">
                    <span className="check-name">Formality Score</span>
                    <span className={`check-status ${result.detected_threats?.formality?.score < 40 ? 'fail' : 'pass'}`}>
                      {result.detected_threats?.formality?.score || 0}/100
                    </span>
                  </div>
                  
                  <div className="check-item">
                    <span className="check-name">Suspicious Links</span>
                    <span className={`check-status ${result.detected_threats?.links?.riskScore > 50 ? 'fail' : 'pass'}`}>
                      {result.detected_threats?.links?.urlCount || 0} found
                    </span>
                  </div>
                  
                  {result.detected_threats?.virustotal && (
                    <div className="check-item">
                      <span className="check-name">VirusTotal Scan</span>
                      <span className={`check-status ${result.detected_threats?.virustotal?.malicious > 0 ? 'fail' : 'pass'}`}>
                        {result.detected_threats?.virustotal?.malicious || 0} malicious
                      </span>
                    </div>
                  )}
                </div>

                {result.automated_response && (
                  <div className="recommendations" style={{ background: '#fff3cd', borderLeft: '4px solid #ffc107' }}>
                    <h3>🚨 Automated Response Triggered</h3>
                    <p>
                      <strong>Actions Taken:</strong><br/>
                      {result.automated_response.map((action, idx) => (
                        <span key={idx}>• {action}<br/></span>
                      ))}
                    </p>
                  </div>
                )}

                <div className="recommendations">
                  <h3>Recommendation</h3>
                  <p>{getRecommendation(result.threat_level)}</p>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default AnalyzeEmail
