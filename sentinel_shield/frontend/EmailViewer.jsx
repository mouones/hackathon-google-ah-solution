import React, { useState, useEffect } from 'react'
import axios from 'axios'
import './EmailViewer.css'

const API_URL = 'http://localhost:8000/api/v1'

function EmailViewer({ emailId, onClose }) {
  const [email, setEmail] = useState(null)
  const [viewData, setViewData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedAttachment, setSelectedAttachment] = useState(null)
  const [sandboxUrl, setSandboxUrl] = useState(null)
  const [showSubmitDialog, setShowSubmitDialog] = useState(false)
  const [submitReason, setSubmitReason] = useState('')

  useEffect(() => {
    loadEmail()
  }, [emailId])

  const loadEmail = async () => {
    try {
      setLoading(true)
      // First get email data
      const emailResponse = await axios.get(`${API_URL}/emails/${emailId}`)
      const emailData = emailResponse.data

      setEmail(emailData)

      // Then get safe rendered version with highlights
      const viewResponse = await axios.post(`${API_URL}/email-viewer/view`, {
        email_id: emailId,
        subject: emailData.subject,
        sender: emailData.sender,
        sender_name: emailData.sender_name,
        body_html: emailData.body_html || emailData.body_text,
        attachments: emailData.attachments
      })

      setViewData(viewResponse.data)
    } catch (err) {
      setError('Failed to load email')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const openAttachmentInSandbox = async (attachment) => {
    try {
      const formData = new FormData()
      formData.append('file', attachment.file)

      const response = await axios.post(
        `${API_URL}/email-viewer/attachment/preview`,
        formData,
        {
          params: {
            attachment_id: attachment.id,
            filename: attachment.filename,
            use_sandbox: true
          }
        }
      )

      setSandboxUrl(response.data.sandbox_url)
      setSelectedAttachment(attachment)
    } catch (err) {
      alert('Failed to open sandbox: ' + err.message)
    }
  }

  const submitToAdmin = async () => {
    if (!submitReason.trim()) {
      alert('Please select a reason')
      return
    }

    try {
      const response = await axios.post(`${API_URL}/email-viewer/submit-to-admin`, {
        email_id: emailId,
        reason: submitReason,
        user_comment: document.getElementById('admin-comment')?.value
      })

      alert(`Email submitted! Tracking ID: ${response.data.submission_id}`)
      setShowSubmitDialog(false)
    } catch (err) {
      alert('Submission failed: ' + err.message)
    }
  }

  const getRiskBadgeColor = (risk) => {
    switch (risk) {
      case 'critical': return 'risk-critical'
      case 'dangerous': return 'risk-dangerous'
      case 'suspicious': return 'risk-suspicious'
      case 'low_risk': return 'risk-low'
      default: return 'risk-safe'
    }
  }

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return '#991b1b'
      case 'high': return '#dc2626'
      case 'medium': return '#f59e0b'
      default: return '#3b82f6'
    }
  }

  if (loading) {
    return <div className="email-viewer-loading">Loading secure email view...</div>
  }

  if (error) {
    return <div className="email-viewer-error">{error}</div>
  }

  return (
    <div className="email-viewer-container">
      {/* Header */}
      <div className="email-viewer-header">
        <div className="header-left">
          <h2>🛡️ Secure Email Viewer</h2>
          <span className={`risk-badge ${getRiskBadgeColor(viewData?.overall_risk)}`}>
            {viewData?.overall_risk.replace('_', ' ').toUpperCase()}
          </span>
        </div>
        <button className="close-btn" onClick={onClose}>✕</button>
      </div>

      {/* Warning Banner */}
      {viewData?.warning_message && (
        <div className={`warning-banner ${getRiskBadgeColor(viewData.overall_risk)}`}>
          <span className="warning-icon">⚠️</span>
          <span>{viewData.warning_message}</span>
        </div>
      )}

      {/* Email Metadata */}
      <div className="email-metadata">
        <div className="metadata-row">
          <strong>From:</strong>
          <span>{email.sender_name} &lt;{email.sender}&gt;</span>
        </div>
        <div className="metadata-row">
          <strong>Subject:</strong>
          <span>{email.subject}</span>
        </div>
        <div className="metadata-row">
          <strong>Date:</strong>
          <span>{new Date(email.date).toLocaleString()}</span>
        </div>
      </div>

      {/* Threats Detected */}
      {viewData?.highlights?.length > 0 && (
        <div className="threats-panel">
          <h3>🚨 Threats Detected ({viewData.highlights.length})</h3>
          <div className="threats-list">
            {viewData.highlights.map((highlight, idx) => (
              <div
                key={idx}
                className="threat-item"
                style={{ borderLeftColor: getSeverityColor(highlight.severity) }}
              >
                <div className="threat-header">
                  <span className={`severity-badge ${highlight.severity}`}>
                    {highlight.severity.toUpperCase()}
                  </span>
                  <span className="threat-type">{highlight.element_type.replace('_', ' ')}</span>
                </div>
                <div className="threat-original">
                  <strong>Found:</strong> "{highlight.original_text}"
                </div>
                <div className="threat-explanation">
                  <strong>Why it's dangerous:</strong> {highlight.explanation}
                </div>
                <div className="threat-action">
                  <strong>What to do:</strong> {highlight.suggested_action}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Attachments */}
      {viewData?.has_attachments && (
        <div className="attachments-panel">
          <h3>📎 Attachments</h3>
          <div className="attachments-list">
            {email.attachments?.map((att, idx) => {
              const risk = viewData.attachment_risks?.[att.filename]
              return (
                <div key={idx} className={`attachment-item risk-${risk?.risk_level}`}>
                  <div className="attachment-icon">
                    {risk?.risk_level === 'critical' ? '⛔' : risk?.risk_level === 'high' ? '⚠️' : '📄'}
                  </div>
                  <div className="attachment-info">
                    <div className="attachment-name">{att.filename}</div>
                    <div className="attachment-details">
                      {risk?.size_mb} MB • {risk?.extension}
                    </div>
                    {risk?.warning && (
                      <div className="attachment-warning">{risk.warning}</div>
                    )}
                  </div>
                  <div className="attachment-actions">
                    <button
                      className="btn-sandbox"
                      onClick={() => openAttachmentInSandbox(att)}
                    >
                      🔒 Open in Sandbox
                    </button>
                    <button
                      className="btn-download"
                      disabled={risk?.risk_level === 'critical'}
                    >
                      ⬇️ Download
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Email Body */}
      <div className="email-body-panel">
        <div className="panel-header">
          <h3>📧 Email Content</h3>
          <div className="view-controls">
            <label>
              <input type="checkbox" defaultChecked /> Show highlights
            </label>
          </div>
        </div>
        {viewData?.can_preview ? (
          <div
            className="email-body-content"
            dangerouslySetInnerHTML={{ __html: viewData.safe_html }}
          />
        ) : (
          <div className="preview-blocked">
            <h2>⛔ Preview Blocked</h2>
            <p>This email contains critical threats and cannot be safely previewed.</p>
            <p>Submit to admin for manual review.</p>
          </div>
        )}
      </div>

      {/* Action Buttons */}
      <div className="email-actions">
        <button
          className="btn-submit-admin"
          onClick={() => setShowSubmitDialog(true)}
        >
          🚩 Submit to Admin
        </button>
        <button className="btn-delete">🗑️ Delete Email</button>
        <button className="btn-mark-safe">✅ Mark as Safe</button>
      </div>

      {/* Submit to Admin Dialog */}
      {showSubmitDialog && (
        <div className="modal-overlay" onClick={() => setShowSubmitDialog(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>Submit Email to Security Team</h3>
            <div className="form-group">
              <label>Reason:</label>
              <select value={submitReason} onChange={(e) => setSubmitReason(e.target.value)}>
                <option value="">Select reason...</option>
                <option value="suspicious_link">Suspicious Link</option>
                <option value="malicious_attachment">Malicious Attachment</option>
                <option value="brand_impersonation">Brand Impersonation</option>
                <option value="urgency_manipulation">Urgency Manipulation</option>
                <option value="homoglyph_attack">Character Substitution</option>
                <option value="other">Other</option>
              </select>
            </div>
            <div className="form-group">
              <label>Additional Comments (optional):</label>
              <textarea
                id="admin-comment"
                rows="3"
                placeholder="Describe what made you suspicious..."
              />
            </div>
            <div className="modal-actions">
              <button className="btn-primary" onClick={submitToAdmin}>
                Submit
              </button>
              <button className="btn-secondary" onClick={() => setShowSubmitDialog(false)}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Sandbox Viewer */}
      {sandboxUrl && (
        <div className="modal-overlay" onClick={() => setSandboxUrl(null)}>
          <div className="modal-content modal-large" onClick={(e) => e.stopPropagation()}>
            <div className="sandbox-header">
              <h3>🔒 Sandbox Environment</h3>
              <div className="sandbox-info">
                <span>✅ Isolated</span>
                <span>🚫 No Network</span>
                <span>⏱️ Auto-destroy: 5min</span>
              </div>
              <button onClick={() => setSandboxUrl(null)}>✕</button>
            </div>
            <iframe
              src={sandboxUrl}
              className="sandbox-iframe"
              sandbox="allow-scripts"
              title="Sandbox Preview"
            />
            <div className="sandbox-footer">
              <p>⚠️ This file is running in an isolated environment. No harm can be done to your system.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default EmailViewer
