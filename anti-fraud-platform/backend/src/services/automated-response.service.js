/**
 * Automated Response Service
 * Implements 6-step containment system with sub-second response time
 * Based on NIST SP 800-61 incident response guidelines
 */

const pool = require('../config/database');

class AutomatedResponseService {
  constructor() {
    this.responseThreshold = 70; // Threat score threshold for auto-response
  }

  /**
   * Execute automated containment workflow
   * @param {Object} email - Analyzed email data
   * @param {number} userId - User ID
   * @returns {Promise<Object>} - Containment results
   */
  async executeContainment(email, userId) {
    const startTime = Date.now();
    const containmentLog = {
      emailId: email.id,
      userId,
      threatScore: email.threat_score,
      actions: [],
      startTime: new Date(),
      responseTime: 0
    };

    try {
      // Step 1: Quarantine Email (Immediate)
      const quarantine = await this.quarantineEmail(email.id);
      containmentLog.actions.push({
        step: 1,
        action: 'quarantine',
        success: quarantine.success,
        timestamp: new Date()
      });

      // Step 2: Block Sender/Domain
      const block = await this.blockSender(email.sender, email.sender_domain);
      containmentLog.actions.push({
        step: 2,
        action: 'block_sender',
        success: block.success,
        timestamp: new Date()
      });

      // Step 3: Protect User Account
      const accountProtection = await this.protectAccount(userId, email.threat_score);
      containmentLog.actions.push({
        step: 3,
        action: 'account_protection',
        success: accountProtection.success,
        timestamp: new Date()
      });

      // Step 4: Endpoint Isolation (if critical threat)
      if (email.threat_score >= 90) {
        const isolation = await this.flagEndpointIsolation(userId);
        containmentLog.actions.push({
          step: 4,
          action: 'endpoint_isolation',
          success: isolation.success,
          timestamp: new Date()
        });
      }

      // Step 5: Threat Intelligence Sharing
      const threatIntel = await this.shareThreatIntelligence(email);
      containmentLog.actions.push({
        step: 5,
        action: 'threat_intelligence',
        success: threatIntel.success,
        timestamp: new Date()
      });

      // Step 6: Organization-wide Alert
      const alert = await this.sendOrganizationAlert(email);
      containmentLog.actions.push({
        step: 6,
        action: 'org_alert',
        success: alert.success,
        timestamp: new Date()
      });

      // Calculate response time
      const endTime = Date.now();
      containmentLog.responseTime = endTime - startTime;
      containmentLog.success = true;

      // Log containment
      await this.logContainment(containmentLog);

      return {
        success: true,
        responseTime: containmentLog.responseTime,
        actionsCompleted: containmentLog.actions.length,
        details: containmentLog.actions
      };

    } catch (error) {
      containmentLog.success = false;
      containmentLog.error = error.message;
      await this.logContainment(containmentLog);

      return {
        success: false,
        error: error.message,
        responseTime: Date.now() - startTime
      };
    }
  }

  /**
   * Step 1: Quarantine email immediately
   * @param {number} emailId - Email ID
   * @returns {Promise<Object>}
   */
  async quarantineEmail(emailId) {
    try {
      await pool.query(
        'UPDATE analyzed_emails SET is_quarantined = TRUE, quarantine_time = NOW() WHERE id = ?',
        [emailId]
      );
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Step 2: Block sender email and domain
   * @param {string} sender - Sender email
   * @param {string} domain - Sender domain
   * @returns {Promise<Object>}
   */
  async blockSender(sender, domain) {
    try {
      // Block sender email
      await pool.query(
        'INSERT INTO blocked_senders (email, domain, block_reason, blocked_at) VALUES (?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE blocked_at = NOW()',
        [sender, domain, 'Automated threat containment']
      );

      // Block domain
      await pool.query(
        'INSERT INTO blocked_domains (domain, block_reason, blocked_at) VALUES (?, ?, NOW()) ON DUPLICATE KEY UPDATE blocked_at = NOW()',
        [domain, 'Automated threat containment']
      );

      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Step 3: Protect user account
   * @param {number} userId - User ID
   * @param {number} threatScore - Threat score
   * @returns {Promise<Object>}
   */
  async protectAccount(userId, threatScore) {
    try {
      const actions = [];

      // Force password reset for critical threats
      if (threatScore >= 85) {
        await pool.query(
          'UPDATE users SET force_password_reset = TRUE WHERE id = ?',
          [userId]
        );
        actions.push('password_reset_required');
      }

      // Lock account for severe threats
      if (threatScore >= 95) {
        await pool.query(
          'UPDATE users SET account_locked = TRUE, locked_at = NOW() WHERE id = ?',
          [userId]
        );
        actions.push('account_locked');
      }

      // Invalidate active sessions
      await pool.query(
        'UPDATE user_sessions SET is_active = FALSE WHERE user_id = ? AND is_active = TRUE',
        [userId]
      );
      actions.push('sessions_invalidated');

      return { success: true, actions };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Step 4: Flag endpoint for IT isolation
   * @param {number} userId - User ID
   * @returns {Promise<Object>}
   */
  async flagEndpointIsolation(userId) {
    try {
      await pool.query(
        'INSERT INTO endpoint_isolation_queue (user_id, reason, flagged_at, status) VALUES (?, ?, NOW(), ?)',
        [userId, 'Critical phishing threat detected', 'pending']
      );
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Step 5: Share threat intelligence (IOCs)
   * @param {Object} email - Email data
   * @returns {Promise<Object>}
   */
  async shareThreatIntelligence(email) {
    try {
      const iocs = {
        sender_email: email.sender,
        sender_domain: email.sender_domain,
        subject_hash: this.hashString(email.subject),
        body_hash: this.hashString(email.body),
        threat_type: 'phishing',
        threat_score: email.threat_score
      };

      await pool.query(
        'INSERT INTO threat_intelligence (ioc_type, ioc_value, threat_type, confidence, first_seen, last_seen) VALUES (?, ?, ?, ?, NOW(), NOW()) ON DUPLICATE KEY UPDATE last_seen = NOW(), occurrences = occurrences + 1',
        ['email', email.sender, 'phishing', email.threat_score]
      );

      await pool.query(
        'INSERT INTO threat_intelligence (ioc_type, ioc_value, threat_type, confidence, first_seen, last_seen) VALUES (?, ?, ?, ?, NOW(), NOW()) ON DUPLICATE KEY UPDATE last_seen = NOW(), occurrences = occurrences + 1',
        ['domain', email.sender_domain, 'phishing', email.threat_score]
      );

      return { success: true, iocs };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Step 6: Send organization-wide alert
   * @param {Object} email - Email data
   * @returns {Promise<Object>}
   */
  async sendOrganizationAlert(email) {
    try {
      await pool.query(
        'INSERT INTO organization_alerts (alert_type, severity, title, message, created_at) VALUES (?, ?, ?, ?, NOW())',
        [
          'phishing_detected',
          email.threat_score >= 90 ? 'critical' : 'high',
          `Phishing Threat Detected from ${email.sender}`,
          `A phishing email with threat score ${email.threat_score} was detected and automatically contained. Sender: ${email.sender}. All users should be cautious of similar emails.`
        ]
      );

      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Log containment action
   * @param {Object} log - Containment log
   * @returns {Promise<void>}
   */
  async logContainment(log) {
    try {
      await pool.query(
        'INSERT INTO containment_logs (email_id, user_id, threat_score, actions_taken, response_time_ms, success, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [
          log.emailId,
          log.userId,
          log.threatScore,
          JSON.stringify(log.actions),
          log.responseTime,
          log.success,
          log.startTime
        ]
      );
    } catch (error) {
      console.error('Failed to log containment:', error);
    }
  }

  /**
   * Simple hash function for IOCs
   * @param {string} str - String to hash
   * @returns {string} - Hash
   */
  hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return hash.toString(16);
  }

  /**
   * Check if automated response should trigger
   * @param {number} threatScore - Threat score
   * @returns {boolean}
   */
  shouldTrigger(threatScore) {
    return threatScore >= this.responseThreshold;
  }
}

module.exports = new AutomatedResponseService();
