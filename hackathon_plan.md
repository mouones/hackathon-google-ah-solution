# 🛡️ Anti-Fraud Platform - Small Business & Citizen Protection
## Technical Implementation Guide for 1-Day Hackathon

**Focus**: Protect small businesses and citizens from fraud rings operating on social media and email

---

## 📋 Table of Contents

1. [System Architecture](#system-architecture)
2. [Tech Stack Setup](#tech-stack-setup)
3. [Database Schema](#database-schema)
4. [Backend Implementation](#backend-implementation)
5. [Advanced Detection Features](#advanced-detection-features)
6. [SOC Team Dashboard](#soc-team-dashboard)
7. [Frontend Implementation](#frontend-implementation)
8. [Attack Response Plan](#attack-response-plan)
9. [Integration & Testing](#integration-testing)
10. [Deployment](#deployment)

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Frontend (React)                             │
│  ┌──────────┬──────────────┬─────────────┬────────────┬──────────┐ │
│  │  Email   │  SOC Team    │  Incident   │  Attack    │ Reports  │ │
│  │ Analysis │  Dashboard   │  Response   │  Plan      │ & Alerts │ │
│  └──────────┴──────────────┴─────────────┴────────────┴──────────┘ │
└────────────────────────┬───────────────────────────────────────────┘
                         │ REST API (JSON)
┌────────────────────────▼───────────────────────────────────────────┐
│                    Backend (Node.js/Express)                        │
│  ┌──────────┬──────────────┬─────────────┬──────────┬───────────┐ │
│  │   API    │  Detection   │  SOC Team   │  Attack  │ Approval  │ │
│  │  Routes  │   Engine     │  Controls   │ Response │  Workflow │ │
│  └──────────┴──────────────┴─────────────┴──────────┴───────────┘ │
└────────────────────────┬───────────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┬────────────────┐
         │               │               │                │
┌────────▼────────┐ ┌───▼────────┐ ┌───▼──────────┐ ┌──▼──────────┐
│   PostgreSQL    │ │  Sandbox   │ │ VirusTotal   │ │  ML Service │
│    Database     │ │  Service   │ │     API      │ │   (Python)  │
└─────────────────┘ └────────────┘ └──────────────┘ └─────────────┘
```

## 🎯 Key Protection Features

### 1. **Advanced Email Analysis**
- **Character Substitution Detection**: Detect "rn" vs "m", "vv" vs "w", lookalike characters
- **Formality Checker**: Accept only professional email formats
- **Name Mismatch Detection**: Compare sender name with email signature
- **Domain Validation**: Verify legitimate business domains

### 2. **Link & Attachment Security**
- **VirusTotal Integration**: Scan all URLs for known threats
- **Sandbox Execution**: Test attachments in isolated environment
- **File Type Validation**: Block dangerous file extensions
- **Macro Detection**: Identify scripts in documents

### 3. **SOC Team Features**
- **Event Monitoring**: Real-time threat dashboard
- **Manual Review Queue**: Approve/deny flagged items
- **Incident Response**: Automated attack response workflows
- **Audit Trail**: Complete logging of all decisions

### 4. **Fraud Ring Detection**
- **Pattern Recognition**: Identify coordinated attacks
- **Social Media Correlation**: Link email threats to social profiles
- **Small Business Protection**: Tailored rules for SMB threats
- **Citizen Alert System**: Community-wide threat notifications

---

## 🛠️ Tech Stack Setup

### Prerequisites Installation

```bash
# Install Node.js (v18+), Python (3.9+), PostgreSQL (14+)

# Verify installations
node --version
npm --version
python --version
psql --version
```

### Project Initialization

```bash
# Create project structure
mkdir anti-phishing-platform
cd anti-phishing-platform

# Initialize monorepo structure
mkdir -p backend frontend ml-service
```

---

## 💾 Database Schema

### PostgreSQL Schema

```sql
-- Create database
CREATE DATABASE anti_phishing_db;

-- Users table (with SOC team roles)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'citizen', -- 'soc_admin', 'soc_analyst', 'business_owner', 'citizen'
    organization VARCHAR(255), -- For small businesses
    security_score INTEGER DEFAULT 0,
    is_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Analyzed emails table (enhanced)
CREATE TABLE analyzed_emails (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    subject VARCHAR(500),
    sender_email VARCHAR(255),
    sender_name VARCHAR(255),
    signature_name VARCHAR(255), -- Name in email signature for mismatch detection
    body TEXT,
    headers JSONB,
    threat_score INTEGER, -- 0-100
    threat_level VARCHAR(20), -- 'safe', 'suspicious', 'dangerous', 'critical'
    detected_threats JSONB, -- Array of threat indicators
    ml_prediction FLOAT,
    
    -- Advanced detection flags
    has_char_substitution BOOLEAN DEFAULT FALSE,
    is_professional_format BOOLEAN DEFAULT TRUE,
    has_name_mismatch BOOLEAN DEFAULT FALSE,
    mail_server_valid BOOLEAN DEFAULT TRUE,
    
    -- Attachment & Link checks
    attachment_scan_result JSONB,
    virustotal_results JSONB,
    sandbox_results JSONB,
    
    -- SOC Review
    review_status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'approved', 'blocked', 'escalated'
    reviewed_by INTEGER REFERENCES users(id),
    reviewed_at TIMESTAMP,
    review_notes TEXT,
    
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'pending'
);

-- Fraud ring patterns table
CREATE TABLE fraud_patterns (
    id SERIAL PRIMARY KEY,
    pattern_name VARCHAR(255),
    description TEXT,
    indicators JSONB, -- Pattern matching rules
    severity VARCHAR(20),
    social_media_links JSONB, -- Links to social media profiles
    attack_vector VARCHAR(100), -- 'email', 'social_media', 'combined'
    confirmed_cases INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Link verification table
CREATE TABLE link_verifications (
    id SERIAL PRIMARY KEY,
    email_id INTEGER REFERENCES analyzed_emails(id),
    url TEXT NOT NULL,
    virustotal_score INTEGER,
    virustotal_data JSONB,
    is_malicious BOOLEAN DEFAULT FALSE,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Attachment scans table
CREATE TABLE attachment_scans (
    id SERIAL PRIMARY KEY,
    email_id INTEGER REFERENCES analyzed_emails(id),
    filename VARCHAR(255),
    file_type VARCHAR(100),
    file_size INTEGER,
    sandbox_result VARCHAR(50), -- 'safe', 'suspicious', 'malicious'
    sandbox_data JSONB,
    has_macros BOOLEAN DEFAULT FALSE,
    has_scripts BOOLEAN DEFAULT FALSE,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- SOC events table (for SOC team monitoring)
CREATE TABLE soc_events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(100), -- 'high_threat_detected', 'fraud_pattern_match', 'manual_review_required'
    email_id INTEGER REFERENCES analyzed_emails(id),
    severity VARCHAR(20),
    description TEXT,
    assigned_to INTEGER REFERENCES users(id),
    status VARCHAR(50) DEFAULT 'new', -- 'new', 'investigating', 'resolved', 'false_positive'
    resolution_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP
);

-- Attack response plans table
CREATE TABLE attack_response_plans (
    id SERIAL PRIMARY KEY,
    plan_name VARCHAR(255),
    threat_type VARCHAR(100),
    severity VARCHAR(20),
    response_steps JSONB, -- Array of automated response actions
    notification_template TEXT,
    auto_execute BOOLEAN DEFAULT FALSE,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Incident response log
CREATE TABLE incident_responses (
    id SERIAL PRIMARY KEY,
    email_id INTEGER REFERENCES analyzed_emails(id),
    plan_id INTEGER REFERENCES attack_response_plans(id),
    executed_steps JSONB,
    success BOOLEAN DEFAULT TRUE,
    executed_by INTEGER REFERENCES users(id),
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Threat indicators table
CREATE TABLE threat_indicators (
    id SERIAL PRIMARY KEY,
    email_id INTEGER REFERENCES analyzed_emails(id),
    indicator_type VARCHAR(100), -- 'suspicious_link', 'urgent_language', 'spoofed_sender'
    severity VARCHAR(20), -- 'low', 'medium', 'high', 'critical'
    description TEXT,
    confidence FLOAT, -- 0.0-1.0
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Incidents table
CREATE TABLE incidents (
    id SERIAL PRIMARY KEY,
    email_id INTEGER REFERENCES analyzed_emails(id),
    user_id INTEGER REFERENCES users(id),
    incident_type VARCHAR(100),
    severity VARCHAR(20),
    status VARCHAR(50) DEFAULT 'open', -- 'open', 'investigating', 'resolved'
    description TEXT,
    actions_taken JSONB,
    resolved_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Training modules table
CREATE TABLE training_modules (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    content JSONB, -- Array of slides/lessons
    quiz_questions JSONB,
    duration_minutes INTEGER,
    difficulty VARCHAR(20), -- 'beginner', 'intermediate', 'advanced'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User training progress table
CREATE TABLE user_training_progress (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    module_id INTEGER REFERENCES training_modules(id),
    progress INTEGER DEFAULT 0, -- 0-100
    quiz_score INTEGER,
    completed BOOLEAN DEFAULT FALSE,
    completed_at TIMESTAMP,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, module_id)
);

-- Phishing simulations table
CREATE TABLE phishing_simulations (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    simulation_type VARCHAR(100),
    email_sent_at TIMESTAMP,
    clicked BOOLEAN DEFAULT FALSE,
    clicked_at TIMESTAMP,
    reported BOOLEAN DEFAULT FALSE,
    reported_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Alerts table
CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    alert_type VARCHAR(100),
    severity VARCHAR(20),
    message TEXT,
    read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX idx_emails_user_id ON analyzed_emails(user_id);
CREATE INDEX idx_emails_threat_score ON analyzed_emails(threat_score);
CREATE INDEX idx_emails_analyzed_at ON analyzed_emails(analyzed_at);
CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_alerts_user_id ON alerts(user_id);
CREATE INDEX idx_alerts_read ON alerts(read);
```

---

## � Advanced Detection Features

### 1. Character Substitution Detection (src/services/char-detection.service.js)

```javascript
// Detect visual spoofing like "rn" vs "m", "vv" vs "w"
const detectCharacterSubstitution = (text) => {
  const substitutions = [];
  
  // Common visual substitutions
  const patterns = [
    { fake: 'rn', real: 'm', description: 'Letters "rn" used instead of "m"' },
    { fake: 'vv', real: 'w', description: 'Letters "vv" used instead of "w"' },
    { fake: 'cl', real: 'd', description: 'Letters "cl" used instead of "d"' },
    { fake: 'l1', real: 'li', description: 'Number "1" mixed with letter "l"' },
    { fake: '0', real: 'o', description: 'Number "0" used instead of letter "o"' },
  ];

  // Lookalike Unicode characters
  const unicodeLookalikes = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', // Cyrillic
    'ο': 'o', 'ν': 'v', 'α': 'a', // Greek
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M',
  };

  const textLower = text.toLowerCase();

  // Check for pattern substitutions
  patterns.forEach(({ fake, real, description }) => {
    if (textLower.includes(fake)) {
      // Check if it's in a suspicious context (domain names, brand names)
      const regex = new RegExp(`\\b\\w*${fake}\\w*\\b`, 'gi');
      const matches = text.match(regex);
      
      if (matches) {
        matches.forEach(match => {
          substitutions.push({
            type: 'character_substitution',
            original: match,
            pattern: `${fake} → ${real}`,
            description: description,
            severity: 'high',
            confidence: 0.85
          });
        });
      }
    }
  });

  // Check for Unicode lookalikes
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (unicodeLookalikes[char]) {
      substitutions.push({
        type: 'unicode_lookalike',
        character: char,
        lookalike: unicodeLookalikes[char],
        position: i,
        description: `Unicode character "${char}" looks like "${unicodeLookalikes[char]}"`,
        severity: 'critical',
        confidence: 0.95
      });
    }
  }

  // Check email domain spoofing
  const emailRegex = /[\w.-]+@[\w.-]+\.\w+/g;
  const emails = text.match(emailRegex) || [];
  
  emails.forEach(email => {
    const domain = email.split('@')[1];
    // Check if domain contains substitution patterns
    patterns.forEach(({ fake, real }) => {
      if (domain.includes(fake)) {
        substitutions.push({
          type: 'domain_spoofing',
          email: email,
          pattern: `${fake} in domain (possibly meant to be ${real})`,
          description: 'Domain may be spoofing legitimate organization',
          severity: 'critical',
          confidence: 0.9
        });
      }
    });
  });

  return {
    has_substitution: substitutions.length > 0,
    substitutions: substitutions,
    risk_score: Math.min(substitutions.length * 25, 100)
  };
};

module.exports = { detectCharacterSubstitution };
```

### 2. Email Formality & Professionalism Checker (src/services/formality.service.js)

```javascript
const checkEmailFormality = (email) => {
  const issues = [];
  let formalityScore = 100;

  const { subject, body, sender_email, sender_name } = email;
  const fullText = `${subject} ${body}`.toLowerCase();

  // 1. Check for professional email domain
  const domain = sender_email.split('@')[1];
  const freeDomains = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
    'aol.com', 'mail.com', 'protonmail.com', 'icloud.com'
  ];
  
  const isFreeDomain = freeDomains.includes(domain);
  
  // Red flag: Business communication from free email
  if (isFreeDomain && (
    fullText.includes('invoice') ||
    fullText.includes('payment') ||
    fullText.includes('contract') ||
    fullText.includes('business') ||
    fullText.includes('company')
  )) {
    issues.push({
      type: 'unprofessional_domain',
      description: 'Business-related email from free email provider',
      severity: 'high',
      impact: -30
    });
    formalityScore -= 30;
  }

  // 2. Grammar and spelling quality check
  const grammarIssues = [
    { pattern: /\b(ur|u r)\b/g, desc: 'Text speak detected ("ur", "u r")' },
    { pattern: /!!!+/g, desc: 'Excessive exclamation marks' },
    { pattern: /\?\?\?+/g, desc: 'Excessive question marks' },
    { pattern: /[A-Z]{10,}/g, desc: 'Excessive capitalization' },
    { pattern: /\b(gonna|wanna|gotta|ain\'t)\b/gi, desc: 'Informal contractions' },
  ];

  grammarIssues.forEach(({ pattern, desc }) => {
    if (pattern.test(fullText)) {
      issues.push({
        type: 'grammar_issue',
        description: desc,
        severity: 'medium',
        impact: -10
      });
      formalityScore -= 10;
    }
  });

  // 3. Professional structure check
  const hasGreeting = /\b(dear|hello|hi|good morning|good afternoon)\b/gi.test(body);
  const hasClosing = /\b(regards|sincerely|best|thanks|thank you)\b/gi.test(body);
  
  if (!hasGreeting && body.length > 100) {
    issues.push({
      type: 'missing_greeting',
      description: 'No professional greeting',
      severity: 'low',
      impact: -5
    });
    formalityScore -= 5;
  }

  if (!hasClosing && body.length > 100) {
    issues.push({
      type: 'missing_closing',
      description: 'No professional closing',
      severity: 'low',
      impact: -5
    });
    formalityScore -= 5;
  }

  // 4. Suspicious urgency in unprofessional context
  const urgentWords = ['urgent', 'immediate', 'asap', 'now', 'quickly', 'hurry'];
  const urgentCount = urgentWords.filter(word => fullText.includes(word)).length;
  
  if (urgentCount >= 2 && formalityScore < 70) {
    issues.push({
      type: 'urgent_unprofessional',
      description: 'Urgent language in unprofessional email',
      severity: 'high',
      impact: -20
    });
    formalityScore -= 20;
  }

  // 5. Professional signature check
  const hasSignature = /--|\n\n[A-Z][a-z]+ [A-Z][a-z]+\n/g.test(body);
  const hasContactInfo = /\d{3}[-.\s]?\d{3}[-.\s]?\d{4}|\+?\d{10,}/g.test(body);
  
  if (!hasSignature && body.length > 200) {
    issues.push({
      type: 'no_signature',
      description: 'No professional email signature',
      severity: 'medium',
      impact: -10
    });
    formalityScore -= 10;
  }

  formalityScore = Math.max(0, formalityScore);

  return {
    is_professional: formalityScore >= 60,
    formality_score: formalityScore,
    issues: issues,
    recommendations: formalityScore < 60 ? [
      'Email lacks professional formatting',
      'Verify sender through alternative communication channel',
      'Do not proceed with sensitive transactions'
    ] : []
  };
};

module.exports = { checkEmailFormality };
```

### 3. Name Mismatch Detection (src/services/name-match.service.js)

```javascript
const detectNameMismatch = (sender_name, body) => {
  // Extract name from signature
  const signaturePatterns = [
    /(?:regards|sincerely|best|thanks),?\s*\n\s*([A-Z][a-z]+(?: [A-Z][a-z]+)*)/gi,
    /\n([A-Z][a-z]+ [A-Z][a-z]+)\s*\n[\w\s@.-]+/g,
    /--\s*\n([A-Z][a-z]+ [A-Z][a-z]+)/g,
  ];

  let signatureName = null;
  
  for (const pattern of signaturePatterns) {
    const match = body.match(pattern);
    if (match && match[1]) {
      signatureName = match[1].trim();
      break;
    }
  }

  if (!signatureName || !sender_name) {
    return {
      has_mismatch: false,
      confidence: 'low',
      reason: 'Insufficient data to compare'
    };
  }

  // Normalize names for comparison
  const normalizeName = (name) => {
    return name
      .toLowerCase()
      .replace(/[^a-z\s]/g, '')
      .trim()
      .split(/\s+/)
      .sort()
      .join(' ');
  };

  const normalizedSender = normalizeName(sender_name);
  const normalizedSignature = normalizeName(signatureName);

  // Calculate similarity
  const senderParts = normalizedSender.split(' ');
  const signatureParts = normalizedSignature.split(' ');

  const commonParts = senderParts.filter(part => 
    signatureParts.includes(part)
  );

  const similarityRatio = commonParts.length / Math.max(senderParts.length, signatureParts.length);

  const hasMismatch = similarityRatio < 0.5;

  return {
    has_mismatch: hasMismatch,
    sender_name: sender_name,
    signature_name: signatureName,
    similarity: similarityRatio,
    confidence: hasMismatch ? 'high' : 'low',
    severity: hasMismatch ? 'high' : 'low',
    description: hasMismatch 
      ? `Sender name "${sender_name}" doesn't match signature "${signatureName}"`
      : 'Names match',
    threat_score: hasMismatch ? 40 : 0
  };
};

module.exports = { detectNameMismatch };
```

### 4. VirusTotal Link Verification (src/services/virustotal.service.js)

```javascript
const axios = require('axios');

// VirusTotal API key (get from environment)
const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VT_API_URL = 'https://www.virustotal.com/api/v3';

const scanUrl = async (url) => {
  if (!VT_API_KEY) {
    console.warn('VirusTotal API key not configured');
    return {
      scanned: false,
      error: 'API key not configured'
    };
  }

  try {
    // Submit URL for scanning
    const submitResponse = await axios.post(
      `${VT_API_URL}/urls`,
      `url=${encodeURIComponent(url)}`,
      {
        headers: {
          'x-apikey': VT_API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const analysisId = submitResponse.data.data.id;

    // Wait a bit for analysis
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Get analysis results
    const analysisResponse = await axios.get(
      `${VT_API_URL}/analyses/${analysisId}`,
      {
        headers: {
          'x-apikey': VT_API_KEY
        }
      }
    );

    const stats = analysisResponse.data.data.attributes.stats;
    
    return {
      scanned: true,
      url: url,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      total_scans: Object.values(stats).reduce((a, b) => a + b, 0),
      is_threat: (stats.malicious + stats.suspicious) > 0,
      threat_score: Math.min(((stats.malicious * 50) + (stats.suspicious * 25)), 100),
      scan_date: new Date().toISOString()
    };
  } catch (error) {
    console.error('VirusTotal scan error:', error.message);
    return {
      scanned: false,
      error: error.message,
      url: url
    };
  }
};

const scanAllUrlsInEmail = async (emailBody) => {
  // Extract all URLs
  const urlRegex = /(https?:\/\/[^\s<>"]+)/gi;
  const urls = emailBody.match(urlRegex) || [];
  
  if (urls.length === 0) {
    return {
      total_urls: 0,
      results: []
    };
  }

  // Limit to 10 URLs to avoid API quota issues
  const urlsToScan = [...new Set(urls)].slice(0, 10);
  
  const results = [];
  
  for (const url of urlsToScan) {
    const result = await scanUrl(url);
    results.push(result);
    
    // Rate limiting: wait 15 seconds between requests (VirusTotal free tier)
    if (urlsToScan.indexOf(url) < urlsToScan.length - 1) {
      await new Promise(resolve => setTimeout(resolve, 15000));
    }
  }

  const threatsFound = results.filter(r => r.is_threat).length;
  
  return {
    total_urls: urls.length,
    scanned_urls: results.length,
    results: results,
    has_threats: threatsFound > 0,
    threat_count: threatsFound,
    max_threat_score: Math.max(...results.map(r => r.threat_score || 0))
  };
};

module.exports = { scanUrl, scanAllUrlsInEmail };
```

### 5. Attachment Sandbox Scanner (src/services/sandbox.service.js)

```javascript
const fs = require('fs').promises;
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const execAsync = util.promisify(exec);

const scanAttachment = async (filePath, fileName) => {
  const results = {
    filename: fileName,
    file_path: filePath,
    scanned: true,
    threats: [],
    is_safe: true,
    sandbox_score: 0
  };

  try {
    // Get file stats
    const stats = await fs.stat(filePath);
    results.file_size = stats.size;

    // Check file extension
    const ext = path.extname(fileName).toLowerCase();
    const dangerousExtensions = [
      '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',
      '.vbs', '.js', '.jar', '.app', '.deb', '.rpm',
      '.msi', '.dmg', '.pkg', '.sh', '.ps1'
    ];

    if (dangerousExtensions.includes(ext)) {
      results.threats.push({
        type: 'dangerous_extension',
        description: `Executable file type: ${ext}`,
        severity: 'critical'
      });
      results.sandbox_score += 50;
      results.is_safe = false;
    }

    // Check for macro-enabled documents
    const macroExtensions = ['.docm', '.xlsm', '.pptm', '.dotm', '.xltm'];
    if (macroExtensions.includes(ext)) {
      results.threats.push({
        type: 'macro_enabled',
        description: 'Document may contain macros',
        severity: 'high'
      });
      results.sandbox_score += 30;
      results.is_safe = false;
      results.has_macros = true;
    }

    // Read file header to verify actual file type
    const buffer = await fs.readFile(filePath);
    const header = buffer.slice(0, 20);

    // Check for PE executable (Windows)
    if (header[0] === 0x4D && header[1] === 0x5A) { // MZ header
      results.threats.push({
        type: 'executable_detected',
        description: 'File is a Windows executable',
        severity: 'critical'
      });
      results.sandbox_score += 50;
      results.is_safe = false;
    }

    // Check for ELF executable (Linux)
    if (header[0] === 0x7F && header[1] === 0x45 && 
        header[2] === 0x4C && header[3] === 0x46) {
      results.threats.push({
        type: 'executable_detected',
        description: 'File is a Linux executable',
        severity: 'critical'
      });
      results.sandbox_score += 50;
      results.is_safe = false;
    }

    // Check for script content in text files
    if (['.txt', '.html', '.htm'].includes(ext)) {
      const content = buffer.toString('utf-8', 0, Math.min(buffer.length, 10000));
      
      const scriptPatterns = [
        /<script/gi,
        /javascript:/gi,
        /eval\(/gi,
        /document\.write/gi,
        /window\.location/gi,
        /onclick=/gi
      ];

      scriptPatterns.forEach(pattern => {
        if (pattern.test(content)) {
          results.threats.push({
            type: 'embedded_script',
            description: 'File contains embedded scripts',
            severity: 'high'
          });
          results.sandbox_score += 25;
          results.is_safe = false;
          results.has_scripts = true;
        }
      });
    }

    // Check file size anomalies
    if (stats.size > 50 * 1024 * 1024) { // > 50MB
      results.threats.push({
        type: 'suspicious_size',
        description: 'Unusually large file attachment',
        severity: 'medium'
      });
      results.sandbox_score += 10;
    }

    if (stats.size < 100 && !['.txt', '.html'].includes(ext)) {
      results.threats.push({
        type: 'suspicious_size',
        description: 'Unusually small file (possible decoy)',
        severity: 'low'
      });
      results.sandbox_score += 5;
    }

    results.sandbox_score = Math.min(results.sandbox_score, 100);

  } catch (error) {
    console.error('Sandbox scan error:', error);
    results.scanned = false;
    results.error = error.message;
  }

  return results;
};

module.exports = { scanAttachment };
```

---

## 👥 SOC Team Dashboard

### SOC Event Controller (src/controllers/soc.controller.js)

```javascript
const pool = require('../config/database');

// Get all pending events for SOC team
const getPendingEvents = async (req, res) => {
  try {
    const { severity, status = 'new', limit = 50 } = req.query;

    let query = `
      SELECT 
        se.*,
        ae.subject,
        ae.sender_email,
        ae.threat_score,
        ae.threat_level,
        u.email as user_email,
        u.organization
      FROM soc_events se
      JOIN analyzed_emails ae ON se.email_id = ae.id
      JOIN users u ON ae.user_id = u.id
      WHERE se.status = $1
    `;
    
    const params = [status];

    if (severity) {
      query += ` AND se.severity = $${params.length + 1}`;
      params.push(severity);
    }

    query += ` ORDER BY se.created_at DESC LIMIT $${params.length + 1}`;
    params.push(limit);

    const result = await pool.query(query, params);

    res.json({
      events: result.rows,
      total: result.rowCount
    });
  } catch (error) {
    console.error('Get SOC events error:', error);
    res.status(500).json({ error: 'Failed to retrieve events' });
  }
};

// Approve or block an email
const reviewEmail = async (req, res) => {
  try {
    const { id } = req.params;
    const { action, notes } = req.body; // action: 'approve' or 'block'
    const socUserId = req.user.id;

    // Update email review status
    const reviewStatus = action === 'approve' ? 'approved' : 'blocked';
    
    await pool.query(
      `UPDATE analyzed_emails 
       SET review_status = $1, reviewed_by = $2, reviewed_at = CURRENT_TIMESTAMP, review_notes = $3
       WHERE id = $4`,
      [reviewStatus, socUserId, notes, id]
    );

    // Update SOC event
    await pool.query(
      `UPDATE soc_events 
       SET status = 'resolved', resolution_notes = $1, resolved_at = CURRENT_TIMESTAMP
       WHERE email_id = $2 AND status = 'new'`,
      [notes, id]
    );

    // If blocked, trigger incident response
    if (action === 'block') {
      await pool.query(
        `INSERT INTO incidents (email_id, user_id, incident_type, severity, description)
         SELECT id, user_id, 'blocked_by_soc', threat_level, $1
         FROM analyzed_emails WHERE id = $2`,
        [`Blocked by SOC analyst: ${notes}`, id]
      );
    }

    res.json({
      message: `Email ${action}ed successfully`,
      action: reviewStatus
    });
  } catch (error) {
    console.error('Review email error:', error);
    res.status(500).json({ error: 'Failed to review email' });
  }
};

// Get SOC dashboard statistics
const getSOCStats = async (req, res) => {
  try {
    // Events by status
    const statusStats = await pool.query(`
      SELECT status, COUNT(*) as count
      FROM soc_events
      WHERE created_at >= NOW() - INTERVAL '24 hours'
      GROUP BY status
    `);

    // Pending review count
    const pendingReview = await pool.query(`
      SELECT COUNT(*) as count
      FROM analyzed_emails
      WHERE review_status = 'pending' AND threat_level IN ('suspicious', 'dangerous', 'critical')
    `);

    // Top threats today
    const topThreats = await pool.query(`
      SELECT 
        email_id,
        ae.subject,
        ae.sender_email,
        ae.threat_score,
        COUNT(*) as incident_count
      FROM soc_events se
      JOIN analyzed_emails ae ON se.email_id = ae.id
      WHERE se.created_at >= NOW() - INTERVAL '24 hours'
      GROUP BY email_id, ae.subject, ae.sender_email, ae.threat_score
      ORDER BY incident_count DESC, ae.threat_score DESC
      LIMIT 10
    `);

    // Fraud pattern matches
    const fraudPatterns = await pool.query(`
      SELECT COUNT(*) as count
      FROM fraud_patterns fp
      WHERE confirmed_cases > 0
    `);

    res.json({
      status_stats: statusStats.rows,
      pending_review: parseInt(pendingReview.rows[0].count),
      top_threats: topThreats.rows,
      active_fraud_patterns: parseInt(fraudPatterns.rows[0].count)
    });
  } catch (error) {
    console.error('SOC stats error:', error);
    res.status(500).json({ error: 'Failed to retrieve SOC statistics' });
  }
};

module.exports = {
  getPendingEvents,
  reviewEmail,
  getSOCStats
};
```

---

## 🚨 Attack Response Plan

### Attack Response Service (src/services/attack-response.service.js)

```javascript
const pool = require('../config/database');
const { createAlert } = require('./alert.service');

// Execute automated response plan
const executeResponsePlan = async (emailId, threatLevel) => {
  try {
    // Find matching response plan
    const planResult = await pool.query(
      `SELECT * FROM attack_response_plans 
       WHERE threat_type = $1 AND auto_execute = true 
       ORDER BY created_at DESC LIMIT 1`,
      [threatLevel]
    );

    if (planResult.rows.length === 0) {
      console.log('No auto-execute plan found for threat level:', threatLevel);
      return null;
    }

    const plan = planResult.rows[0];
    const executedSteps = [];

    // Execute response steps
    for (const step of plan.response_steps) {
      try {
        await executeStep(step, emailId);
        executedSteps.push({
          step: step.action,
          status: 'success',
          executed_at: new Date().toISOString()
        });
      } catch (error) {
        executedSteps.push({
          step: step.action,
          status: 'failed',
          error: error.message,
          executed_at: new Date().toISOString()
        });
      }
    }

    // Log response execution
    await pool.query(
      `INSERT INTO incident_responses (email_id, plan_id, executed_steps, executed_by)
       VALUES ($1, $2, $3, NULL)`,
      [emailId, plan.id, JSON.stringify(executedSteps)]
    );

    return {
      plan_executed: plan.plan_name,
      steps: executedSteps
    };
  } catch (error) {
    console.error('Execute response plan error:', error);
    throw error;
  }
};

// Execute individual response step
const executeStep = async (step, emailId) => {
  switch (step.action) {
    case 'quarantine_email':
      await pool.query(
        `UPDATE analyzed_emails SET status = 'quarantined' WHERE id = $1`,
        [emailId]
      );
      break;

    case 'notify_user':
      const emailData = await pool.query(
        'SELECT user_id FROM analyzed_emails WHERE id = $1',
        [emailId]
      );
      if (emailData.rows.length > 0) {
        await createAlert({
          user_id: emailData.rows[0].user_id,
          alert_type: 'threat_detected',
          severity: 'high',
          message: step.message || 'Potential threat detected in your email'
        });
      }
      break;

    case 'block_sender':
      await pool.query(
        `INSERT INTO blocked_senders (email_address, reason, blocked_at)
         SELECT sender_email, $1, CURRENT_TIMESTAMP
         FROM analyzed_emails WHERE id = $2
         ON CONFLICT (email_address) DO NOTHING`,
        ['Auto-blocked by attack response', emailId]
      );
      break;

    case 'escalate_to_soc':
      await pool.query(
        `INSERT INTO soc_events (event_type, email_id, severity, description)
         VALUES ('auto_escalated', $1, 'high', $2)`,
        [emailId, step.message || 'Automatically escalated threat']
      );
      break;

    case 'notify_community':
      // Notify all users in organization about threat
      await pool.query(
        `INSERT INTO alerts (user_id, alert_type, severity, message)
         SELECT u.id, 'community_threat', 'medium', $1
         FROM users u
         WHERE u.organization = (
           SELECT u2.organization FROM analyzed_emails ae
           JOIN users u2 ON ae.user_id = u2.id
           WHERE ae.id = $2
         )`,
        [step.message || 'Threat detected in your organization', emailId]
      );
      break;

    default:
      console.warn('Unknown response step:', step.action);
  }
};

// Create custom response plan
const createResponsePlan = async (planData) => {
  const {
    plan_name,
    threat_type,
    severity,
    response_steps,
    notification_template,
    auto_execute,
    created_by
  } = planData;

  const result = await pool.query(
    `INSERT INTO attack_response_plans 
     (plan_name, threat_type, severity, response_steps, notification_template, auto_execute, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING *`,
    [
      plan_name,
      threat_type,
      severity,
      JSON.stringify(response_steps),
      notification_template,
      auto_execute,
      created_by
    ]
  );

  return result.rows[0];
};

module.exports = {
  executeResponsePlan,
  createResponsePlan
};
```

### Default Response Plans (src/utils/default-plans.js)

```javascript
// Seed database with default attack response plans

const defaultPlans = [
  {
    plan_name: 'Critical Threat - Immediate Action',
    threat_type: 'critical',
    severity: 'critical',
    auto_execute: true,
    response_steps: [
      {
        action: 'quarantine_email',
        description: 'Immediately quarantine the email'
      },
      {
        action: 'block_sender',
        description: 'Block sender from future emails'
      },
      {
        action: 'notify_user',
        message: '🚨 CRITICAL: Dangerous email detected and quarantined. Do not interact with this message.'
      },
      {
        action: 'escalate_to_soc',
        message: 'Critical threat requiring immediate SOC review'
      },
      {
        action: 'notify_community',
        message: '⚠️ Security Alert: A critical phishing threat has been detected in your organization. Please be vigilant.'
      }
    ],
    notification_template: 'A critical security threat has been detected and blocked.'
  },
  {
    plan_name: 'Dangerous Threat - Review Required',
    threat_type: 'dangerous',
    severity: 'high',
    auto_execute: true,
    response_steps: [
      {
        action: 'quarantine_email',
        description: 'Quarantine suspicious email'
      },
      {
        action: 'notify_user',
        message: '⚠️ WARNING: Suspicious email detected. This message has been flagged for review.'
      },
      {
        action: 'escalate_to_soc',
        message: 'High-risk email requires SOC analyst review'
      }
    ],
    notification_template: 'A dangerous email has been quarantined pending review.'
  },
  {
    plan_name: 'Suspicious - User Warning',
    threat_type: 'suspicious',
    severity: 'medium',
    auto_execute: true,
    response_steps: [
      {
        action: 'notify_user',
        message: 'ℹ️ NOTICE: This email contains suspicious elements. Please verify before taking any action.'
      }
    ],
    notification_template: 'Suspicious activity detected. User has been notified.'
  },
  {
    plan_name: 'Fraud Ring Detection',
    threat_type: 'fraud_pattern',
    severity: 'critical',
    auto_execute: true,
    response_steps: [
      {
        action: 'quarantine_email',
        description: 'Quarantine emails matching fraud pattern'
      },
      {
        action: 'block_sender',
        description: 'Block all senders in fraud ring'
      },
      {
        action: 'notify_community',
        message: '🚨 FRAUD ALERT: Coordinated fraud attack detected. Multiple malicious emails have been blocked.'
      },
      {
        action: 'escalate_to_soc',
        message: 'Fraud ring pattern detected - requires investigation'
      }
    ],
    notification_template: 'Coordinated fraud attack detected and mitigated.'
  }
];

module.exports = { defaultPlans };

```bash
cd backend
npm init -y

# Install dependencies
npm install express cors dotenv bcrypt jsonwebtoken pg
npm install nodemailer joi helmet morgan
npm install --save-dev nodemon

# Create structure
mkdir -p src/{config,controllers,middleware,models,routes,services,utils}
touch src/server.js src/app.js .env
```

### 2. Configuration Files

**package.json scripts:**
```json
{
  "scripts": {
    "start": "node src/server.js",
    "dev": "nodemon src/server.js",
    "seed": "node src/utils/seed.js"
  }
}
```

**.env:**
```env
PORT=5000
NODE_ENV=development
DATABASE_URL=postgresql://user:password@localhost:5432/anti_phishing_db
JWT_SECRET=your-super-secret-jwt-key-change-in-production
ML_SERVICE_URL=http://localhost:8000
FRONTEND_URL=http://localhost:5173
```

### 3. Database Connection (src/config/database.js)

```javascript
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

pool.on('connect', () => {
  console.log('✅ Database connected successfully');
});

pool.on('error', (err) => {
  console.error('❌ Unexpected database error:', err);
  process.exit(-1);
});

module.exports = pool;
```

### 4. Main Application (src/app.js)

```javascript
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
require('dotenv').config();

const authRoutes = require('./routes/auth.routes');
const emailRoutes = require('./routes/email.routes');
const dashboardRoutes = require('./routes/dashboard.routes');
const trainingRoutes = require('./routes/training.routes');
const incidentRoutes = require('./routes/incident.routes');

const app = express();

// Middleware
app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));
app.use(morgan('dev'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/emails', emailRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/training', trainingRoutes);
app.use('/api/incidents', incidentRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({
    error: {
      message: err.message || 'Internal server error',
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    }
  });
});

module.exports = app;
```

### 5. Server Entry Point (src/server.js)

```javascript
const app = require('./app');
const pool = require('./config/database');

const PORT = process.env.PORT || 5000;

const startServer = async () => {
  try {
    // Test database connection
    await pool.query('SELECT NOW()');
    console.log('✅ Database connection verified');

    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📝 Environment: ${process.env.NODE_ENV}`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

startServer();
```

### 6. Authentication Middleware (src/middleware/auth.js)

```javascript
const jwt = require('jsonwebtoken');
const pool = require('../config/database');

const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const result = await pool.query(
      'SELECT id, email, role, full_name FROM users WHERE id = $1',
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.user = result.rows[0];
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

module.exports = { authenticate, requireAdmin };
```

### 7. Auth Controller (src/controllers/auth.controller.js)

```javascript
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../config/database');

const register = async (req, res) => {
  try {
    const { email, password, full_name, role = 'employee' } = req.body;

    // Check if user exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const password_hash = await bcrypt.hash(password, 10);

    // Create user
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, full_name, role) 
       VALUES ($1, $2, $3, $4) 
       RETURNING id, email, full_name, role, created_at`,
      [email, password_hash, full_name, role]
    );

    const user = result.rows[0];

    // Generate token
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    await pool.query(
      'UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = $1',
      [user.id]
    );

    // Generate token
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role,
        security_score: user.security_score
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
};

module.exports = { register, login };
```

### 8. Email Analysis Controller (src/controllers/email.controller.js)

```javascript
const pool = require('../config/database');
const { analyzeEmail } = require('../services/analysis.service');
const { createAlert } = require('../services/alert.service');

const analyzeEmailEndpoint = async (req, res) => {
  try {
    const { subject, sender_email, sender_name, body, headers } = req.body;
    const userId = req.user.id;

    // Call analysis service
    const analysisResult = await analyzeEmail({
      subject,
      sender_email,
      sender_name,
      body,
      headers
    });

    // Save to database
    const emailResult = await pool.query(
      `INSERT INTO analyzed_emails 
       (user_id, subject, sender_email, sender_name, body, headers, 
        threat_score, threat_level, detected_threats, ml_prediction)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING *`,
      [
        userId,
        subject,
        sender_email,
        sender_name,
        body,
        JSON.stringify(headers || {}),
        analysisResult.threat_score,
        analysisResult.threat_level,
        JSON.stringify(analysisResult.threats),
        analysisResult.ml_confidence
      ]
    );

    const email = emailResult.rows[0];

    // Save individual threat indicators
    for (const threat of analysisResult.threats) {
      await pool.query(
        `INSERT INTO threat_indicators 
         (email_id, indicator_type, severity, description, confidence)
         VALUES ($1, $2, $3, $4, $5)`,
        [email.id, threat.type, threat.severity, threat.description, threat.confidence]
      );
    }

    // Create alert if high risk
    if (analysisResult.threat_score >= 70) {
      await createAlert({
        user_id: userId,
        alert_type: 'high_risk_email',
        severity: analysisResult.threat_level,
        message: `High-risk email detected: ${subject}`
      });
    }

    res.json({
      id: email.id,
      threat_score: email.threat_score,
      threat_level: email.threat_level,
      threats: analysisResult.threats,
      recommendations: analysisResult.recommendations,
      analyzed_at: email.analyzed_at
    });
  } catch (error) {
    console.error('Email analysis error:', error);
    res.status(500).json({ error: 'Analysis failed' });
  }
};

const getAnalyzedEmails = async (req, res) => {
  try {
    const userId = req.user.id;
    const { limit = 50, offset = 0, threat_level } = req.query;

    let query = `
      SELECT id, subject, sender_email, sender_name, threat_score, 
             threat_level, analyzed_at, status
      FROM analyzed_emails
      WHERE user_id = $1
    `;
    const params = [userId];

    if (threat_level) {
      query += ` AND threat_level = $${params.length + 1}`;
      params.push(threat_level);
    }

    query += ` ORDER BY analyzed_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    res.json({
      emails: result.rows,
      total: result.rowCount
    });
  } catch (error) {
    console.error('Get emails error:', error);
    res.status(500).json({ error: 'Failed to retrieve emails' });
  }
};

const getEmailDetails = async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    const emailResult = await pool.query(
      'SELECT * FROM analyzed_emails WHERE id = $1 AND user_id = $2',
      [id, userId]
    );

    if (emailResult.rows.length === 0) {
      return res.status(404).json({ error: 'Email not found' });
    }

    const email = emailResult.rows[0];

    const threatsResult = await pool.query(
      'SELECT * FROM threat_indicators WHERE email_id = $1 ORDER BY severity DESC',
      [id]
    );

    res.json({
      ...email,
      threat_indicators: threatsResult.rows
    });
  } catch (error) {
    console.error('Get email details error:', error);
    res.status(500).json({ error: 'Failed to retrieve email details' });
  }
};

module.exports = {
  analyzeEmailEndpoint,
  getAnalyzedEmails,
  getEmailDetails
};
```

### 9. Enhanced Email Analysis Service (src/services/analysis.service.js)

```javascript
const axios = require('axios');
const { detectCharacterSubstitution } = require('./char-detection.service');
const { checkEmailFormality } = require('./formality.service');
const { detectNameMismatch } = require('./name-match.service');
const { scanAllUrlsInEmail } = require('./virustotal.service');

// Rule-based threat detection (ENHANCED)
const detectThreats = (email) => {
  const threats = [];

  // 1. Suspicious link detection
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const urls = email.body.match(urlRegex) || [];
  
  const suspiciousPatterns = [
    /bit\.ly|tinyurl|goo\.gl|ow\.ly/i,
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    /-secure|-verify|-update|-confirm|-account/i
  ];

  urls.forEach(url => {
    suspiciousPatterns.forEach(pattern => {
      if (pattern.test(url)) {
        threats.push({
          type: 'suspicious_link',
          severity: 'high',
          description: `Suspicious URL detected: ${url.substring(0, 50)}...`,
          confidence: 0.85
        });
      }
    });
  });

  // 2. Urgency language detection
  const urgentKeywords = [
    'urgent', 'immediate action', 'act now', 'expires today',
    'suspended', 'locked', 'verify now', 'click here immediately',
    'limited time', 'alert', 'warning', 'final notice'
  ];

  const bodyLower = email.body.toLowerCase() + ' ' + email.subject.toLowerCase();
  const urgentMatches = urgentKeywords.filter(keyword => 
    bodyLower.includes(keyword)
  );

  if (urgentMatches.length >= 2) {
    threats.push({
      type: 'urgent_language',
      severity: 'medium',
      description: `Urgent language detected: ${urgentMatches.join(', ')}`,
      confidence: 0.75
    });
  }

  // 3. Sender verification issues
  if (email.sender_email) {
    const domain = email.sender_email.split('@')[1];
    const suspiciousDomains = ['gmail.com', 'yahoo.com', 'hotmail.com'];
    
    if (suspiciousDomains.includes(domain) && 
        bodyLower.match(/\b(bank|paypal|amazon|microsoft|apple|government|tax|irs)\b/)) {
      threats.push({
        type: 'sender_mismatch',
        severity: 'high',
        description: 'Official organization email from free email provider',
        confidence: 0.9
      });
    }
  }

  // 4. Request for sensitive information
  const sensitiveKeywords = [
    'password', 'ssn', 'social security', 'credit card',
    'bank account', 'pin', 'security code', 'cvv', 'routing number'
  ];

  const sensitiveMatches = sensitiveKeywords.filter(keyword =>
    bodyLower.includes(keyword)
  );

  if (sensitiveMatches.length >= 1) {
    threats.push({
      type: 'sensitive_info_request',
      severity: 'critical',
      description: `Requests sensitive information: ${sensitiveMatches.join(', ')}`,
      confidence: 0.95
    });
  }

  // 5. Attachment warnings
  if (email.body.match(/\.(exe|scr|bat|cmd|vbs|js|jar|zip|rar|7z)\b/i)) {
    threats.push({
      type: 'dangerous_attachment',
      severity: 'high',
      description: 'Potentially dangerous attachment type mentioned',
      confidence: 0.8
    });
  }

  // 6. Social media fraud indicators
  const socialMediaScams = [
    'facebook offer', 'instagram giveaway', 'twitter contest',
    'tiktok promotion', 'social media prize', 'you have won',
    'claim your reward', 'congratulations you won'
  ];

  const socialScamMatches = socialMediaScams.filter(keyword =>
    bodyLower.includes(keyword)
  );

  if (socialScamMatches.length >= 1) {
    threats.push({
      type: 'social_media_scam',
      severity: 'high',
      description: 'Social media fraud indicators detected',
      confidence: 0.8
    });
  }

  return threats;
};

// Calculate threat score
const calculateThreatScore = (threats, charSubScore, formalityScore, nameMismatch, vtScore) => {
  if (threats.length === 0 && charSubScore === 0 && formalityScore > 70) return 5;

  const severityScores = {
    low: 10,
    medium: 25,
    high: 40,
    critical: 50
  };

  let score = 0;
  
  // Rule-based threats
  threats.forEach(threat => {
    score += severityScores[threat.severity] * threat.confidence;
  });

  // Character substitution
  score += charSubScore * 0.8;

  // Formality issues
  if (formalityScore < 60) {
    score += (60 - formalityScore) * 0.5;
  }

  // Name mismatch
  if (nameMismatch.has_mismatch) {
    score += 40;
  }

  // VirusTotal results
  score += vtScore;

  return Math.min(100, Math.round(score));
};

// Determine threat level
const getThreatLevel = (score) => {
  if (score < 30) return 'safe';
  if (score < 60) return 'suspicious';
  if (score < 85) return 'dangerous';
  return 'critical';
};

// Main analysis function (ENHANCED)
const analyzeEmail = async (email) => {
  try {
    // 1. Character substitution detection
    const charSubResult = detectCharacterSubstitution(
      email.subject + ' ' + email.body + ' ' + email.sender_email
    );

    // 2. Formality check
    const formalityResult = checkEmailFormality(email);

    // 3. Name mismatch detection
    const nameMismatchResult = detectNameMismatch(
      email.sender_name,
      email.body
    );

    // 4. Rule-based detection
    const threats = detectThreats(email);

    // 5. Add character substitution threats
    if (charSubResult.has_substitution) {
      threats.push(...charSubResult.substitutions);
    }

    // 6. Add formality issues as threats
    if (!formalityResult.is_professional) {
      formalityResult.issues.forEach(issue => {
        threats.push({
          type: issue.type,
          severity: issue.severity,
          description: issue.description,
          confidence: 0.7
        });
      });
    }

    // 7. Add name mismatch threat
    if (nameMismatchResult.has_mismatch) {
      threats.push({
        type: 'name_mismatch',
        severity: nameMismatchResult.severity,
        description: nameMismatchResult.description,
        confidence: 0.85
      });
    }

    // 8. VirusTotal scan (async, may take time)
    let vtResults = { has_threats: false, max_threat_score: 0 };
    try {
      vtResults = await scanAllUrlsInEmail(email.body);
      if (vtResults.has_threats) {
        threats.push({
          type: 'malicious_url',
          severity: 'critical',
          description: `${vtResults.threat_count} malicious URLs detected by VirusTotal`,
          confidence: 0.95
        });
      }
    } catch (vtError) {
      console.warn('VirusTotal scan failed:', vtError.message);
    }

    // Calculate final threat score
    const threatScore = calculateThreatScore(
      threats,
      charSubResult.risk_score || 0,
      formalityResult.formality_score,
      nameMismatchResult,
      vtResults.max_threat_score || 0
    );
    
    const threatLevel = getThreatLevel(threatScore);

    // ML prediction (if service is available)
    let mlConfidence = 0;
    try {
      const mlResponse = await axios.post(
        `${process.env.ML_SERVICE_URL}/predict`,
        {
          subject: email.subject,
          body: email.body,
          sender: email.sender_email
        },
        { timeout: 3000 }
      );
      mlConfidence = mlResponse.data.confidence;
    } catch (mlError) {
      console.warn('ML service unavailable, using rule-based only');
    }

    // Generate recommendations
    const recommendations = generateRecommendations(threats, threatLevel);

    return {
      threat_score: threatScore,
      threat_level: threatLevel,
      threats,
      ml_confidence: mlConfidence,
      recommendations,
      
      // Enhanced detection results
      has_char_substitution: charSubResult.has_substitution,
      is_professional_format: formalityResult.is_professional,
      formality_score: formalityResult.formality_score,
      has_name_mismatch: nameMismatchResult.has_mismatch,
      signature_name: nameMismatchResult.signature_name,
      virustotal_results: vtResults,
      
      // SOC review flag
      requires_soc_review: threatScore >= 60 || threatLevel === 'critical'
    };
  } catch (error) {
    console.error('Analysis error:', error);
    throw error;
  }
};

// Generate recommendations
const generateRecommendations = (threats, threatLevel) => {
  const recommendations = [];

  if (threatLevel === 'critical') {
    recommendations.push('🚨 CRITICAL THREAT - DO NOT interact with this email');
    recommendations.push('🗑️ Delete immediately and report to SOC team');
    recommendations.push('🔒 Change passwords if you clicked any links');
    recommendations.push('📢 Alert your IT security team NOW');
  } else if (threatLevel === 'dangerous') {
    recommendations.push('🚨 DO NOT click any links or download attachments');
    recommendations.push('🗑️ Delete this email immediately');
    recommendations.push('📢 Report to your IT security team');
  } else if (threatLevel === 'suspicious') {
    recommendations.push('⚠️ Exercise extreme caution with this email');
    recommendations.push('🔍 Verify sender through alternative means');
    recommendations.push('❌ Do not provide any sensitive information');
    recommendations.push('📞 Contact the sender via known phone number to verify');
  } else {
    recommendations.push('✅ Email appears safe based on analysis');
    recommendations.push('🛡️ Still verify unexpected requests');
    recommendations.push('🔗 Hover over links before clicking');
  }

  return recommendations;
};

module.exports = { analyzeEmail };
```

### 10. Dashboard Controller (src/controllers/dashboard.controller.js)

```javascript
const pool = require('../config/database');

const getDashboardStats = async (req, res) => {
  try {
    const userId = req.user.id;
    const isAdmin = req.user.role === 'admin';

    // Get email statistics
    const emailStatsQuery = isAdmin
      ? `SELECT 
           COUNT(*) as total_emails,
           COUNT(CASE WHEN threat_level = 'dangerous' THEN 1 END) as dangerous,
           COUNT(CASE WHEN threat_level = 'suspicious' THEN 1 END) as suspicious,
           COUNT(CASE WHEN threat_level = 'safe' THEN 1 END) as safe,
           AVG(threat_score) as avg_threat_score
         FROM analyzed_emails
         WHERE analyzed_at >= NOW() - INTERVAL '30 days'`
      : `SELECT 
           COUNT(*) as total_emails,
           COUNT(CASE WHEN threat_level = 'dangerous' THEN 1 END) as dangerous,
           COUNT(CASE WHEN threat_level = 'suspicious' THEN 1 END) as suspicious,
           COUNT(CASE WHEN threat_level = 'safe' THEN 1 END) as safe,
           AVG(threat_score) as avg_threat_score
         FROM analyzed_emails
         WHERE user_id = $1 AND analyzed_at >= NOW() - INTERVAL '30 days'`;

    const emailStats = await pool.query(
      emailStatsQuery,
      isAdmin ? [] : [userId]
    );

    // Get recent threats
    const recentThreatsQuery = isAdmin
      ? `SELECT e.id, e.subject, e.sender_email, e.threat_score, 
           e.threat_level, e.analyzed_at, u.email as user_email
         FROM analyzed_emails e
         JOIN users u ON e.user_id = u.id
         WHERE e.threat_level IN ('dangerous', 'suspicious')
         ORDER BY e.analyzed_at DESC
         LIMIT 10`
      : `SELECT id, subject, sender_email, threat_score, 
           threat_level, analyzed_at
         FROM analyzed_emails
         WHERE user_id = $1 AND threat_level IN ('dangerous', 'suspicious')
         ORDER BY analyzed_at DESC
         LIMIT 10`;

    const recentThreats = await pool.query(
      recentThreatsQuery,
      isAdmin ? [] : [userId]
    );

    // Get threat trends (last 7 days)
    const trendQuery = isAdmin
      ? `SELECT 
           DATE(analyzed_at) as date,
           COUNT(*) as total,
           COUNT(CASE WHEN threat_level = 'dangerous' THEN 1 END) as dangerous,
           COUNT(CASE WHEN threat_level = 'suspicious' THEN 1 END) as suspicious
         FROM analyzed_emails
         WHERE analyzed_at >= NOW() - INTERVAL '7 days'
         GROUP BY DATE(analyzed_at)
         ORDER BY date`
      : `SELECT 
           DATE(analyzed_at) as date,
           COUNT(*) as total,
           COUNT(CASE WHEN threat_level = 'dangerous' THEN 1 END) as dangerous,
           COUNT(CASE WHEN threat_level = 'suspicious' THEN 1 END) as suspicious
         FROM analyzed_emails
         WHERE user_id = $1 AND analyzed_at >= NOW() - INTERVAL '7 days'
         GROUP BY DATE(analyzed_at)
         ORDER BY date`;

    const trends = await pool.query(trendQuery, isAdmin ? [] : [userId]);

    // Get open incidents count
    const incidentsQuery = isAdmin
      ? `SELECT COUNT(*) as open_incidents FROM incidents WHERE status = 'open'`
      : `SELECT COUNT(*) as open_incidents FROM incidents 
         WHERE user_id = $1 AND status = 'open'`;

    const incidents = await pool.query(incidentsQuery, isAdmin ? [] : [userId]);

    res.json({
      email_stats: emailStats.rows[0],
      recent_threats: recentThreats.rows,
      trends: trends.rows,
      open_incidents: parseInt(incidents.rows[0].open_incidents)
    });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to retrieve dashboard statistics' });
  }
};

const getAlerts = async (req, res) => {
  try {
    const userId = req.user.id;
    const { limit = 20, unread_only = false } = req.query;

    let query = 'SELECT * FROM alerts WHERE user_id = $1';
    const params = [userId];

    if (unread_only === 'true') {
      query += ' AND read = false';
    }

    query += ` ORDER BY created_at DESC LIMIT ${params.length + 1}`;
    params.push(limit);

    const result = await pool.query(query, params);

    res.json({
      alerts: result.rows,
      unread_count: result.rows.filter(a => !a.read).length
    });
  } catch (error) {
    console.error('Get alerts error:', error);
    res.status(500).json({ error: 'Failed to retrieve alerts' });
  }
};

module.exports = { getDashboardStats, getAlerts };
```

### 11. Routes Setup

**src/routes/auth.routes.js:**
```javascript
const express = require('express');
const { register, login } = require('../controllers/auth.controller');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);

module.exports = router;
```

**src/routes/email.routes.js:**
```javascript
const express = require('express');
const { authenticate } = require('../middleware/auth');
const {
  analyzeEmailEndpoint,
  getAnalyzedEmails,
  getEmailDetails
} = require('../controllers/email.controller');

const router = express.Router();

router.use(authenticate);

router.post('/analyze', analyzeEmailEndpoint);
router.get('/', getAnalyzedEmails);
router.get('/:id', getEmailDetails);

module.exports = router;
```

**src/routes/dashboard.routes.js:**
```javascript
const express = require('express');
const { authenticate } = require('../middleware/auth');
const { getDashboardStats, getAlerts } = require('../controllers/dashboard.controller');

const router = express.Router();

router.use(authenticate);

router.get('/stats', getDashboardStats);
router.get('/alerts', getAlerts);

module.exports = router;
```

### 12. Alert Service (src/services/alert.service.js)

```javascript
const pool = require('../config/database');

const createAlert = async ({ user_id, alert_type, severity, message }) => {
  try {
    const result = await pool.query(
      `INSERT INTO alerts (user_id, alert_type, severity, message)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [user_id, alert_type, severity, message]
    );

    return result.rows[0];
  } catch (error) {
    console.error('Create alert error:', error);
    throw error;
  }
};

module.exports = { createAlert };
```

---

## 🎨 Frontend Implementation

### 1. Project Setup

```bash
cd ../frontend
npm create vite@latest . -- --template react
npm install

# Install dependencies
npm install react-router-dom axios recharts lucide-react
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p

# Create structure
mkdir -p src/{components,pages,services,hooks,utils,context}
```

### 2. Tailwind Configuration (tailwind.config.js)

```javascript
/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: '#3b82f6',
        danger: '#ef4444',
        warning: '#f59e0b',
        success: '#10b981',
      }
    },
  },
  plugins: [],
}
```

### 3. API Service (src/services/api.js)

```javascript
import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Auth
export const auth = {
  login: (credentials) => api.post('/auth/login', credentials),
  register: (userData) => api.post('/auth/register', userData),
};

// Email analysis
export const emails = {
  analyze: (emailData) => api.post('/emails/analyze', emailData),
  getAll: (params) => api.get('/emails', { params }),
  getById: (id) => api.get(`/emails/${id}`),
};

// Dashboard
export const dashboard = {
  getStats: () => api.get('/dashboard/stats'),
  getAlerts: (params) => api.get('/dashboard/alerts', { params }),
};

export default api;
```

### 4. Auth Context (src/context/AuthContext.jsx)

```javascript
import React, { createContext, useState, useContext, useEffect } from 'react';
import { auth as authService } from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const userData = localStorage.getItem('user');
    
    if (token && userData) {
      setUser(JSON.parse(userData));
    }
    setLoading(false);
  }, []);

  const login = async (credentials) => {
    const response = await authService.login(credentials);
    const { token, user } = response.data;
    
    localStorage.setItem('token', token);
    localStorage.setItem('user', JSON.stringify(user));
    setUser(user);
    
    return user;
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};
```

### 5. Login Page (src/pages/LoginPage.jsx)

```javascript
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Shield, Mail, Lock } from 'lucide-react';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await login({ email, password });
      navigate('/dashboard');
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-white rounded-2xl shadow-xl p-8">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-100 rounded-full mb-4">
            <Shield className="w-8 h-8 text-blue-600" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900">PhishGuard</h1>
          <p className="text-gray-600 mt-2">Protect your business from phishing</p>
        </div>

        {error && (
          <div className="bg-red-50 text-red-600 p-3 rounded-lg mb-4 text-sm">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Email Address
            </label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="you@company.com"
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="••••••••"
                required
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 text-white py-3 rounded-lg font-semibold hover:bg-blue-700 transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>

        <p className="text-center text-sm text-gray-600 mt-6">
          Demo: admin@demo.com / password123
        </p>
      </div>
    </div>
  );
}
```

### 6. Dashboard Page (src/pages/DashboardPage.jsx)

```javascript
import React, { useState, useEffect } from 'react';
import { dashboard as dashboardService } from '../services/api';
import { 
  Shield, AlertTriangle, Mail, TrendingUp, 
  Clock, CheckCircle, XCircle 
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

export default function DashboardPage() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async () => {
    try {
      const response = await dashboardService.getStats();
      setStats(response.data);
    } catch (error) {
      console.error('Failed to load dashboard:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  const { email_stats, recent_threats, trends } = stats;

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
          <p className="text-gray-600 mt-2">Real-time threat monitoring and analysis</p>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <StatCard
            icon={<Mail className="w-6 h-6" />}
            label="Total Emails Analyzed"
            value={email_stats.total_emails}
            color="blue"
          />
          <StatCard
            icon={<XCircle className="w-6 h-6" />}
            label="Dangerous Threats"
            value={email_stats.dangerous}
            color="red"
          />
          <StatCard
            icon={<AlertTriangle className="w-6 h-6" />}
            label="Suspicious Emails"
            value={email_stats.suspicious}
            color="yellow"
          />
          <StatCard
            icon={<CheckCircle className="w-6 h-6" />}
            label="Safe Emails"
            value={email_stats.safe}
            color="green"
          />
        </div>

        {/* Threat Trends Chart */}
        <div className="bg-white rounded-xl shadow-sm p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Threat Trends (Last 7 Days)</h2>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={trends}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip />
              <Line type="monotone" dataKey="dangerous" stroke="#ef4444" strokeWidth={2} name="Dangerous" />
              <Line type="monotone" dataKey="suspicious" stroke="#f59e0b" strokeWidth={2} name="Suspicious" />
              <Line type="monotone" dataKey="total" stroke="#3b82f6" strokeWidth={2} name="Total" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Recent Threats */}
        <div className="bg-white rounded-xl shadow-sm p-6">
          <h2 className="text-xl font-semibold mb-4">Recent Threats</h2>
          <div className="space-y-3">
            {recent_threats.map((threat) => (
              <ThreatItem key={threat.id} threat={threat} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon, label, value, color }) {
  const colors = {
    blue: 'bg-blue-100 text-blue-600',
    red: 'bg-red-100 text-red-600',
    yellow: 'bg-yellow-100 text-yellow-600',
    green: 'bg-green-100 text-green-600',
  };

  return (
    <div className="bg-white rounded-xl shadow-sm p-6">
      <div className={`inline-flex p-3 rounded-lg ${colors[color]} mb-4`}>
        {icon}
      </div>
      <div className="text-2xl font-bold text-gray-900">{value}</div>
      <div className="text-sm text-gray-600">{label}</div>
    </div>
  );
}

function ThreatItem({ threat }) {
  const levelColors = {
    dangerous: 'bg-red-100 text-red-700',
    suspicious: 'bg-yellow-100 text-yellow-700',
    safe: 'bg-green-100 text-green-700',
  };

  return (
    <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:bg-gray-50">
      <div className="flex-1">
        <div className="font-medium text-gray-900">{threat.subject}</div>
        <div className="text-sm text-gray-600">{threat.sender_email}</div>
      </div>
      <div className="flex items-center gap-4">
        <span className={`px-3 py-1 rounded-full text-xs font-medium ${levelColors[threat.threat_level]}`}>
          {threat.threat_level}
        </span>
        <div className="text-2xl font-bold text-gray-900">{threat.threat_score}</div>
      </div>
    </div>
  );
}
```

### 7. Email Analysis Page (src/pages/AnalyzePage.jsx)

```javascript
import React, { useState } from 'react';
import { emails as emailService } from '../services/api';
import { Mail, AlertCircle, CheckCircle, XCircle } from 'lucide-react';

export default function AnalyzePage() {
  const [formData, setFormData] = useState({
    subject: '',
    sender_email: '',
    sender_name: '',
    body: '',
  });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);

    try {
      const response = await emailService.analyze(formData);
      setResult(response.data);
    } catch (error) {
      console.error('Analysis failed:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl font-bold text-gray-900 mb-8">Analyze Email</h1>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Form */}
          <div className="bg-white rounded-xl shadow-sm p-6">
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Subject
                </label>
                <input
                  type="text"
                  value={formData.subject}
                  onChange={(e) => setFormData({ ...formData, subject: e.target.value })}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Urgent: Verify your account"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Sender Email
                </label>
                <input
                  type="email"
                  value={formData.sender_email}
                  onChange={(e) => setFormData({ ...formData, sender_email: e.target.value })}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="noreply@suspicious-site.com"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Sender Name
                </label>
                <input
                  type="text"
                  value={formData.sender_name}
                  onChange={(e) => setFormData({ ...formData, sender_name: e.target.value })}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Security Team"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Email Body
                </label>
                <textarea
                  value={formData.body}
                  onChange={(e) => setFormData({ ...formData, body: e.target.value })}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent h-32"
                  placeholder="Your account will be suspended unless you verify immediately..."
                  required
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-blue-600 text-white py-3 rounded-lg font-semibold hover:bg-blue-700 transition disabled:opacity-50"
              >
                {loading ? 'Analyzing...' : 'Analyze Email'}
              </button>
            </form>
          </div>

          {/* Results */}
          {result && (
            <div className="bg-white rounded-xl shadow-sm p-6">
              <h2 className="text-xl font-semibold mb-4">Analysis Results</h2>

              {/* Threat Score */}
              <div className="mb-6">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-700">Threat Score</span>
                  <span className="text-2xl font-bold">{result.threat_score}/100</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-3">
                  <div
                    className={`h-3 rounded-full ${
                      result.threat_score >= 70
                        ? 'bg-red-500'
                        : result.threat_score >= 30
                        ? 'bg-yellow-500'
                        : 'bg-green-500'
                    }`}
                    style={{ width: `${result.threat_score}%` }}
                  />
                </div>
                <div className="flex justify-between text-xs text-gray-500 mt-1">
                  <span>Safe</span>
                  <span>Suspicious</span>
                  <span>Dangerous</span>
                </div>
              </div>

              {/* Threat Level Badge */}
              <div className="mb-6">
                <span
                  className={`inline-block px-4 py-2 rounded-full text-sm font-medium ${
                    result.threat_level === 'dangerous'
                      ? 'bg-red-100 text-red-700'
                      : result.threat_level === 'suspicious'
                      ? 'bg-yellow-100 text-yellow-700'
                      : 'bg-green-100 text-green-700'
                  }`}
                >
                  {result.threat_level.toUpperCase()}
                </span>
              </div>

              {/* Detected Threats */}
              <div className="mb-6">
                <h3 className="font-semibold mb-3">Detected Threats</h3>
                <div className="space-y-2">
                  {result.threats.map((threat, index) => (
                    <div key={index} className="p-3 bg-red-50 border border-red-200 rounded-lg">
                      <div className="flex items-start gap-2">
                        <AlertCircle className="w-5 h-5 text-red-600 mt-0.5" />
                        <div className="flex-1">
                          <div className="font-medium text-red-900">{threat.type.replace('_', ' ').toUpperCase()}</div>
                          <div className="text-sm text-red-700">{threat.description}</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recommendations */}
              <div>
                <h3 className="font-semibold mb-3">Recommendations</h3>
                <div className="space-y-2">
                  {result.recommendations.map((rec, index) => (
                    <div key={index} className="flex items-start gap-2 text-sm text-gray-700">
                      <CheckCircle className="w-4 h-4 text-blue-600 mt-0.5" />
                      <span>{rec}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
```

### 8. Main App (src/App.jsx)

```javascript
import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import AnalyzePage from './pages/AnalyzePage';
import Navbar from './components/Navbar';

function PrivateRoute({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return <div>Loading...</div>;
  }

  return user ? children : <Navigate to="/login" />;
}

function AppRoutes() {
  const { user } = useAuth();

  return (
    <Routes>
      <Route path="/login" element={user ? <Navigate to="/dashboard" /> : <LoginPage />} />
      <Route
        path="/dashboard"
        element={
          <PrivateRoute>
            <Navbar />
            <DashboardPage />
          </PrivateRoute>
        }
      />
      <Route
        path="/analyze"
        element={
          <PrivateRoute>
            <Navbar />
            <AnalyzePage />
          </PrivateRoute>
        }
      />
      <Route path="/" element={<Navigate to="/dashboard" />} />
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}
```

### 9. Navbar Component (src/components/Navbar.jsx)

```javascript
import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Shield, LogOut, LayoutDashboard, Mail } from 'lucide-react';

export default function Navbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <nav className="bg-white border-b border-gray-200">
      <div className="max-w-7xl mx-auto px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-8">
            <Link to="/dashboard" className="flex items-center gap-2">
              <Shield className="w-8 h-8 text-blue-600" />
              <span className="text-xl font-bold text-gray-900">PhishGuard</span>
            </Link>

            <div className="flex items-center gap-4">
              <Link
                to="/dashboard"
                className="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-gray-100 transition"
              >
                <LayoutDashboard className="w-5 h-5" />
                <span>Dashboard</span>
              </Link>
              <Link
                to="/analyze"
                className="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-gray-100 transition"
              >
                <Mail className="w-5 h-5" />
                <span>Analyze Email</span>
              </Link>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <span className="text-sm text-gray-600">{user?.email}</span>
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-4 py-2 text-red-600 hover:bg-red-50 rounded-lg transition"
            >
              <LogOut className="w-5 h-5" />
              <span>Logout</span>
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}
```

---

## 🤖 ML Detection Engine (Optional)

### Python Service Setup (ml-service/)

```bash
cd ../ml-service
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

pip install fastapi uvicorn scikit-learn pandas numpy python-multipart
```

**main.py:**
```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pickle
import numpy as np

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EmailData(BaseModel):
    subject: str
    body: str
    sender: str

# Simple feature extraction
def extract_features(email_data):
    features = []
    
    text = (email_data.subject + " " + email_data.body).lower()
    
    # Feature 1: Number of suspicious keywords
    suspicious_words = ['urgent', 'verify', 'suspended', 'click', 'immediately']
    features.append(sum(word in text for word in suspicious_words))
    
    # Feature 2: Number of URLs
    features.append(text.count('http'))
    
    # Feature 3: Has sensitive word requests
    sensitive = ['password', 'ssn', 'credit card', 'bank account']
    features.append(1 if any(word in text for word in sensitive) else 0)
    
    # Feature 4: Email length
    features.append(len(text))
    
    # Feature 5: Has free email domain
    free_domains = ['gmail.com', 'yahoo.com', 'hotmail.com']
    features.append(1 if any(domain in email_data.sender for domain in free_domains) else 0)
    
    return np.array(features).reshape(1, -1)

@app.post("/predict")
async def predict(email: EmailData):
    try:
        features = extract_features(email)
        
        # Simple rule-based scoring for demo
        score = 0
        if features[0][0] >= 2: score += 30  # Suspicious keywords
        if features[0][1] >= 2: score += 20  # Multiple URLs
        if features[0][2] == 1: score += 40  # Sensitive info request
        if features[0][4] == 1: score += 10  # Free email
        
        confidence = min(score / 100.0, 0.95)
        
        return {
            "confidence": confidence,
            "is_phishing": confidence > 0.7
        }
    except Exception as e:
        return {"error": str(e), "confidence": 0}

@app.get("/health")
async def health():
    return {"status": "ok"}

if