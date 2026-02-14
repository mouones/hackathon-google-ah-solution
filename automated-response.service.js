"""
🚨 Automated Response & Containment System
Research-backed implementation for rapid threat response
"""

const pool = require('../config/database');
const { createAlert } = require('./alert.service');

class AutomatedResponseSystem {
    constructor() {
        this.responseMetrics = {
            avgResponseTime: 0,
            threatsQuarantined: 0,
            accountsProtected: 0,
            attacksBlocked: 0
        };
    }

    /**
     * Execute automated containment when threat is confirmed
     * ⏱️ Faster response = less damage
     */
    async executeContainment(emailId, threatData) {
        const startTime = Date.now();
        const actions = [];

        try {
            // 1. IMMEDIATE QUARANTINE
            const quarantine = await this.quarantineEmail(emailId);
            actions.push({ action: 'quarantine', status: quarantine.success, timestamp: new Date() });

            // 2. BLOCK SENDER/DOMAIN
            if (threatData.threat_score >= 70) {
                const block = await this.blockSender(emailId);
                actions.push({ action: 'block_sender', status: block.success, timestamp: new Date() });
            }

            // 3. DISABLE COMPROMISED ACCOUNT (if user clicked/interacted)
            if (threatData.user_interacted) {
                const accountAction = await this.protectCompromisedAccount(emailId);
                actions.push({ action: 'protect_account', status: accountAction.success, timestamp: new Date() });
            }

            // 4. ISOLATE ENDPOINT (conceptual - flag for IT team)
            if (threatData.threat_level === 'critical') {
                const isolation = await this.flagEndpointIsolation(emailId);
                actions.push({ action: 'endpoint_isolation', status: isolation.success, timestamp: new Date() });
            }

            // 5. THREAT INTELLIGENCE SHARING
            await this.shareThreatIntelligence(threatData);
            actions.push({ action: 'threat_intel_shared', status: true, timestamp: new Date() });

            // 6. ORGANIZATION-WIDE ALERT
            if (threatData.threat_level === 'critical') {
                await this.broadcastOrganizationAlert(emailId, threatData);
                actions.push({ action: 'org_alert', status: true, timestamp: new Date() });
            }

            // Calculate response time
            const responseTime = Date.now() - startTime;
            this.responseMetrics.avgResponseTime = responseTime;

            // Log containment actions
            await this.logContainment(emailId, actions, responseTime);

            return {
                success: true,
                responseTime: responseTime,
                actions: actions,
                message: `Threat contained in ${responseTime}ms`
            };

        } catch (error) {
            console.error('Automated containment error:', error);
            return {
                success: false,
                error: error.message,
                actions: actions
            };
        }
    }

    /**
     * Step 1: Immediate Email Quarantine
     */
    async quarantineEmail(emailId) {
        try {
            await pool.query(
                `UPDATE analyzed_emails 
                 SET status = 'quarantined', 
                     quarantined_at = NOW()
                 WHERE id = $1`,
                [emailId]
            );

            this.responseMetrics.threatsQuarantined++;

            return { success: true, action: 'Email quarantined' };
        } catch (error) {
            console.error('Quarantine error:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Step 2: Block Sender and Domain
     */
    async blockSender(emailId) {
        try {
            // Get sender info
            const emailData = await pool.query(
                'SELECT sender_email, user_id FROM analyzed_emails WHERE id = $1',
                [emailId]
            );

            if (emailData.rows.length === 0) return { success: false };

            const { sender_email, user_id } = emailData.rows[0];
            const domain = sender_email.split('@')[1];

            // Block sender email
            await pool.query(
                `INSERT INTO blocked_senders (email_address, reason, blocked_at)
                 VALUES ($1, $2, NOW())
                 ON CONFLICT (email_address) DO NOTHING`,
                [sender_email, 'Auto-blocked: High threat score']
            );

            // Block entire domain if highly suspicious
            await pool.query(
                `INSERT INTO blocked_domains (domain, reason, blocked_at)
                 VALUES ($1, $2, NOW())
                 ON CONFLICT (domain) DO NOTHING`,
                [domain, 'Auto-blocked: Associated with critical threat']
            );

            // Create incident record
            await pool.query(
                `INSERT INTO incidents (email_id, user_id, incident_type, severity, description, status)
                 VALUES ($1, $2, 'sender_blocked', 'high', $3, 'auto_resolved')`,
                [emailId, user_id, `Sender ${sender_email} auto-blocked`]
            );

            this.responseMetrics.attacksBlocked++;

            return { 
                success: true, 
                action: 'Sender and domain blocked',
                blocked_email: sender_email,
                blocked_domain: domain
            };
        } catch (error) {
            console.error('Block sender error:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Step 3: Protect Compromised Account
     */
    async protectCompromisedAccount(emailId) {
        try {
            const emailData = await pool.query(
                'SELECT user_id FROM analyzed_emails WHERE id = $1',
                [emailId]
            );

            if (emailData.rows.length === 0) return { success: false };

            const userId = emailData.rows[0].user_id;

            // Flag account for immediate password reset
            await pool.query(
                `UPDATE users 
                 SET requires_password_reset = true,
                     account_locked = true,
                     locked_reason = 'Potential compromise detected',
                     locked_at = NOW()
                 WHERE id = $1`,
                [userId]
            );

            // Invalidate all active sessions (conceptual - would integrate with session store)
            await pool.query(
                `INSERT INTO account_actions (user_id, action_type, reason, executed_at)
                 VALUES ($1, 'force_logout', 'Compromise detection', NOW())`,
                [userId]
            );

            // Notify user
            await createAlert({
                user_id: userId,
                alert_type: 'account_protected',
                severity: 'critical',
                message: '🚨 SECURITY ALERT: Your account has been temporarily locked due to suspicious activity. Please contact support to regain access.'
            });

            // Notify IT/SOC team
            await pool.query(
                `INSERT INTO soc_events (event_type, email_id, severity, description, status)
                 VALUES ('account_compromise', $1, 'critical', $2, 'investigating')`,
                [emailId, `User ${userId} account locked - potential compromise`]
            );

            this.responseMetrics.accountsProtected++;

            return { 
                success: true, 
                action: 'Account protected and locked',
                user_id: userId
            };
        } catch (error) {
            console.error('Account protection error:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Step 4: Flag Endpoint for Isolation
     */
    async flagEndpointIsolation(emailId) {
        try {
            const emailData = await pool.query(
                'SELECT user_id FROM analyzed_emails WHERE id = $1',
                [emailId]
            );

            if (emailData.rows.length === 0) return { success: false };

            const userId = emailData.rows[0].user_id;

            // Create endpoint isolation ticket
            await pool.query(
                `INSERT INTO endpoint_isolation_queue 
                 (user_id, email_id, priority, reason, status, created_at)
                 VALUES ($1, $2, 'critical', 'Critical threat detection', 'pending', NOW())`,
                [userId, emailId]
            );

            // Alert SOC team for manual isolation
            await pool.query(
                `INSERT INTO soc_events (event_type, email_id, severity, description, status)
                 VALUES ('endpoint_isolation_required', $1, 'critical', $2, 'new')`,
                [emailId, `URGENT: Endpoint isolation required for user ${userId}`]
            );

            // Notify user
            await createAlert({
                user_id: userId,
                alert_type: 'endpoint_isolation',
                severity: 'critical',
                message: '🔴 CRITICAL: Your device may have been exposed to a severe threat. IT team has been notified for immediate action.'
            });

            return { 
                success: true, 
                action: 'Endpoint flagged for isolation',
                user_id: userId
            };
        } catch (error) {
            console.error('Endpoint isolation error:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Step 5: Share Threat Intelligence
     */
    async shareThreatIntelligence(threatData) {
        try {
            // Extract IOCs (Indicators of Compromise)
            const iocs = {
                sender_email: threatData.sender_email,
                sender_domain: threatData.sender_email?.split('@')[1],
                urls: threatData.detected_urls || [],
                threat_score: threatData.threat_score,
                threat_indicators: threatData.threats,
                timestamp: new Date().toISOString()
            };

            // Store in threat intelligence database
            await pool.query(
                `INSERT INTO threat_intelligence 
                 (ioc_type, ioc_value, threat_level, source, metadata, shared_at)
                 VALUES ('email_threat', $1, $2, 'automated_detection', $3, NOW())`,
                [
                    JSON.stringify(iocs),
                    threatData.threat_level,
                    JSON.stringify(threatData)
                ]
            );

            // Share with partner organizations (conceptual)
            // In production, this would integrate with STIX/TAXII threat sharing platforms

            return { success: true };
        } catch (error) {
            console.error('Threat intelligence sharing error:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Step 6: Organization-wide Alert
     */
    async broadcastOrganizationAlert(emailId, threatData) {
        try {
            // Get organization of affected user
            const orgData = await pool.query(
                `SELECT u.organization FROM analyzed_emails ae
                 JOIN users u ON ae.user_id = u.id
                 WHERE ae.id = $1`,
                [emailId]
            );

            if (orgData.rows.length === 0) return;

            const organization = orgData.rows[0].organization;

            // Alert all users in same organization
            await pool.query(
                `INSERT INTO alerts (user_id, alert_type, severity, message)
                 SELECT u.id, 'org_threat_alert', 'high', $1
                 FROM users u
                 WHERE u.organization = $2`,
                [
                    `⚠️ ORGANIZATION ALERT: A critical phishing threat has been detected and blocked. Subject: "${threatData.subject}". Be vigilant for similar emails.`,
                    organization
                ]
            );

            return { success: true };
        } catch (error) {
            console.error('Organization alert error:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Log containment actions for audit trail
     */
    async logContainment(emailId, actions, responseTime) {
        try {
            await pool.query(
                `INSERT INTO containment_logs 
                 (email_id, actions, response_time_ms, executed_at)
                 VALUES ($1, $2, $3, NOW())`,
                [emailId, JSON.stringify(actions), responseTime]
            );
        } catch (error) {
            console.error('Containment logging error:', error);
        }
    }

    /**
     * Get response metrics
     */
    getMetrics() {
        return this.responseMetrics;
    }

    /**
     * Check if sender/domain is already blocked
     */
    async isBlocked(email) {
        try {
            const domain = email.split('@')[1];

            const result = await pool.query(
                `SELECT 1 FROM blocked_senders WHERE email_address = $1
                 UNION
                 SELECT 1 FROM blocked_domains WHERE domain = $2
                 LIMIT 1`,
                [email, domain]
            );

            return result.rows.length > 0;
        } catch (error) {
            console.error('Block check error:', error);
            return false;
        }
    }
}

// Additional database tables needed (add to schema)
const additionalTables = `
-- Blocked domains table
CREATE TABLE IF NOT EXISTS blocked_domains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    reason TEXT,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    blocked_by INT,
    FOREIGN KEY (blocked_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_domain (domain)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Account actions log
CREATE TABLE IF NOT EXISTS account_actions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action_type VARCHAR(100),
    reason TEXT,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Endpoint isolation queue
CREATE TABLE IF NOT EXISTS endpoint_isolation_queue (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    email_id INT,
    priority VARCHAR(20),
    reason TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (email_id) REFERENCES analyzed_emails(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Threat intelligence database
CREATE TABLE IF NOT EXISTS threat_intelligence (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ioc_type VARCHAR(100),
    ioc_value TEXT,
    threat_level VARCHAR(20),
    source VARCHAR(100),
    metadata JSON,
    shared_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ioc_type (ioc_type),
    INDEX idx_threat_level (threat_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Containment logs
CREATE TABLE IF NOT EXISTS containment_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_id INT,
    actions JSON,
    response_time_ms INT,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES analyzed_emails(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Add columns to users table for account protection
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS requires_password_reset BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS account_locked BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS locked_reason TEXT,
ADD COLUMN IF NOT EXISTS locked_at TIMESTAMP NULL;
`;

module.exports = { AutomatedResponseSystem, additionalTables };
