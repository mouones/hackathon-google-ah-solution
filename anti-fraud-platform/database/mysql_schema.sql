-- ============================================
-- Anti-Fraud Platform Database Schema (MySQL)
-- ============================================

-- Create database
CREATE DATABASE IF NOT EXISTS anti_fraud_db;
USE anti_fraud_db;

-- Users table (with SOC team roles)
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'citizen', -- 'soc_admin', 'soc_analyst', 'business_owner', 'citizen'
    organization VARCHAR(255),
    security_score INT DEFAULT 0,
    is_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Analyzed emails table (enhanced)
CREATE TABLE analyzed_emails (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    subject VARCHAR(500),
    sender_email VARCHAR(255),
    sender_name VARCHAR(255),
    signature_name VARCHAR(255),
    body TEXT,
    headers JSON,
    threat_score INT,
    threat_level VARCHAR(20), -- 'safe', 'suspicious', 'dangerous', 'critical'
    detected_threats JSON,
    ml_prediction FLOAT,
    
    -- Advanced detection flags
    has_char_substitution BOOLEAN DEFAULT FALSE,
    is_professional_format BOOLEAN DEFAULT TRUE,
    has_name_mismatch BOOLEAN DEFAULT FALSE,
    mail_server_valid BOOLEAN DEFAULT TRUE,
    
    -- Attachment & Link checks
    attachment_scan_result JSON,
    virustotal_results JSON,
    sandbox_results JSON,
    
    -- SOC Review
    review_status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'approved', 'blocked', 'escalated'
    reviewed_by INT,
    reviewed_at TIMESTAMP NULL,
    review_notes TEXT,
    
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'pending',
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_threat_score (threat_score),
    INDEX idx_threat_level (threat_level),
    INDEX idx_analyzed_at (analyzed_at),
    INDEX idx_review_status (review_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Threat indicators table
CREATE TABLE threat_indicators (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_id INT,
    indicator_type VARCHAR(100),
    severity VARCHAR(20), -- 'low', 'medium', 'high', 'critical'
    description TEXT,
    confidence FLOAT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES analyzed_emails(id) ON DELETE CASCADE,
    INDEX idx_email_id (email_id),
    INDEX idx_severity (severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Fraud ring patterns table
CREATE TABLE fraud_patterns (
    id INT AUTO_INCREMENT PRIMARY KEY,
    pattern_name VARCHAR(255),
    description TEXT,
    indicators JSON,
    severity VARCHAR(20),
    social_media_links JSON,
    attack_vector VARCHAR(100), -- 'email', 'social_media', 'combined'
    confirmed_cases INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_severity (severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Link verification table
CREATE TABLE link_verifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_id INT,
    url TEXT NOT NULL,
    virustotal_score INT,
    virustotal_data JSON,
    is_malicious BOOLEAN DEFAULT FALSE,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES analyzed_emails(id) ON DELETE CASCADE,
    INDEX idx_email_id (email_id),
    INDEX idx_is_malicious (is_malicious)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Attachment scans table
CREATE TABLE attachment_scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_id INT,
    filename VARCHAR(255),
    file_type VARCHAR(100),
    file_size INT,
    sandbox_result VARCHAR(50), -- 'safe', 'suspicious', 'malicious'
    sandbox_data JSON,
    has_macros BOOLEAN DEFAULT FALSE,
    has_scripts BOOLEAN DEFAULT FALSE,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES analyzed_emails(id) ON DELETE CASCADE,
    INDEX idx_email_id (email_id),
    INDEX idx_sandbox_result (sandbox_result)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- SOC events table
CREATE TABLE soc_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(100),
    email_id INT,
    severity VARCHAR(20),
    description TEXT,
    assigned_to INT,
    status VARCHAR(50) DEFAULT 'new', -- 'new', 'investigating', 'resolved', 'false_positive'
    resolution_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    FOREIGN KEY (email_id) REFERENCES analyzed_emails(id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_status (status),
    INDEX idx_severity (severity),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Attack response plans table
CREATE TABLE attack_response_plans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    plan_name VARCHAR(255),
    threat_type VARCHAR(100),
    severity VARCHAR(20),
    response_steps JSON,
    notification_template TEXT,
    auto_execute BOOLEAN DEFAULT FALSE,
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_threat_type (threat_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Incident response log
CREATE TABLE incident_responses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_id INT,
    plan_id INT,
    executed_steps JSON,
    success BOOLEAN DEFAULT TRUE,
    executed_by INT,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES analyzed_emails(id) ON DELETE CASCADE,
    FOREIGN KEY (plan_id) REFERENCES attack_response_plans(id) ON DELETE SET NULL,
    FOREIGN KEY (executed_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Incidents table
CREATE TABLE incidents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_id INT,
    user_id INT,
    incident_type VARCHAR(100),
    severity VARCHAR(20),
    status VARCHAR(50) DEFAULT 'open', -- 'open', 'investigating', 'resolved'
    description TEXT,
    actions_taken JSON,
    resolved_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES analyzed_emails(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_status (status),
    INDEX idx_severity (severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Alerts table
CREATE TABLE alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    alert_type VARCHAR(100),
    severity VARCHAR(20),
    message TEXT,
    `read` BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_read (`read`),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Training modules table
CREATE TABLE training_modules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    content JSON,
    quiz_questions JSON,
    duration_minutes INT,
    difficulty VARCHAR(20), -- 'beginner', 'intermediate', 'advanced'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- User training progress table
CREATE TABLE user_training_progress (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    module_id INT,
    progress INT DEFAULT 0,
    quiz_score INT,
    completed BOOLEAN DEFAULT FALSE,
    completed_at TIMESTAMP NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (module_id) REFERENCES training_modules(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_module (user_id, module_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Phishing simulations table
CREATE TABLE phishing_simulations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    simulation_type VARCHAR(100),
    email_sent_at TIMESTAMP,
    clicked BOOLEAN DEFAULT FALSE,
    clicked_at TIMESTAMP NULL,
    reported BOOLEAN DEFAULT FALSE,
    reported_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Blocked senders table (for attack response)
CREATE TABLE blocked_senders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_address VARCHAR(255) UNIQUE NOT NULL,
    reason TEXT,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    blocked_by INT,
    FOREIGN KEY (blocked_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_email_address (email_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Insert Demo Data
-- ============================================

-- Insert default admin user (password: admin123)
INSERT INTO users (email, password_hash, full_name, role, is_verified) VALUES
('admin@fraudguard.com', '$2b$10$YourHashedPasswordHere', 'Admin User', 'soc_admin', TRUE),
('analyst@fraudguard.com', '$2b$10$YourHashedPasswordHere', 'SOC Analyst', 'soc_analyst', TRUE),
('demo@business.com', '$2b$10$YourHashedPasswordHere', 'Demo Business', 'business_owner', TRUE);

-- Insert default attack response plans
INSERT INTO attack_response_plans (plan_name, threat_type, severity, response_steps, notification_template, auto_execute) VALUES
('Critical Threat Response', 'critical', 'critical', 
 '[{"action":"quarantine_email","description":"Immediately quarantine the email"},{"action":"block_sender","description":"Block sender from future emails"},{"action":"notify_user","message":"🚨 CRITICAL: Dangerous email detected and quarantined."},{"action":"escalate_to_soc","message":"Critical threat requiring immediate SOC review"},{"action":"notify_community","message":"⚠️ Security Alert: A critical threat has been detected."}]',
 'A critical security threat has been detected and blocked.', TRUE),
 
('Dangerous Threat Response', 'dangerous', 'high',
 '[{"action":"quarantine_email","description":"Quarantine suspicious email"},{"action":"notify_user","message":"⚠️ WARNING: Suspicious email detected."},{"action":"escalate_to_soc","message":"High-risk email requires SOC analyst review"}]',
 'A dangerous email has been quarantined pending review.', TRUE),
 
('Suspicious Email Warning', 'suspicious', 'medium',
 '[{"action":"notify_user","message":"ℹ️ NOTICE: This email contains suspicious elements."}]',
 'Suspicious activity detected. User has been notified.', TRUE);

-- Success message
SELECT '✅ Database schema created successfully!' as Status;
SELECT '✅ Demo users and response plans inserted!' as Status;
SELECT '🚀 Ready to connect your application!' as Status;
