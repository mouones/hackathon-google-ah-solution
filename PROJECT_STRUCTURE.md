```
anti-fraud-platform/
│
├── 📁 backend/
│   ├── 📁 src/
│   │   ├── 📁 config/
│   │   │   └── database.js                    # MySQL connection (mysql2)
│   │   │
│   │   ├── 📁 controllers/
│   │   │   ├── auth.controller.js              # Login, register, JWT
│   │   │   ├── email.controller.js             # Email analysis endpoint
│   │   │   ├── dashboard.controller.js         # Stats, metrics
│   │   │   ├── soc.controller.js               # SOC team features
│   │   │   └── incident.controller.js          # Incident management
│   │   │
│   │   ├── 📁 middleware/
│   │   │   ├── auth.js                         # JWT verification
│   │   │   └── error-handler.js                # Global error handling
│   │   │
│   │   ├── 📁 services/
│   │   │   ├── char-detection.service.js       # ⭐ Character substitution (rn vs m)
│   │   │   ├── formality.service.js            # ⭐ Email professionalism check
│   │   │   ├── name-match.service.js           # ⭐ Sender name mismatch
│   │   │   ├── virustotal.service.js           # ⭐ VirusTotal API integration
│   │   │   ├── sandbox.service.js              # ⭐ Attachment scanning
│   │   │   ├── link-analyzer.service.js        # ⭐⭐ Advanced link analysis:
│   │   │   │                                   #    - Domain age (WHOIS)
│   │   │   │                                   #    - Subdomain analysis
│   │   │   │                                   #    - Brand impersonation
│   │   │   │                                   #    - Redirect behavior
│   │   │   │                                   #    - Ephemeral domains
│   │   │   ├── analysis.service.js             # Main email analysis orchestrator
│   │   │   ├── automated-response.service.js   # ⭐⭐ Automated containment:
│   │   │   │                                   #    - Quarantine email
│   │   │   │                                   #    - Block sender/domain
│   │   │   │                                   #    - Protect accounts
│   │   │   │                                   #    - Endpoint isolation
│   │   │   │                                   #    - Threat intel sharing
│   │   │   └── alert.service.js                # Alert creation
│   │   │
│   │   ├── 📁 routes/
│   │   │   ├── auth.routes.js
│   │   │   ├── email.routes.js
│   │   │   ├── dashboard.routes.js
│   │   │   ├── soc.routes.js
│   │   │   └── incident.routes.js
│   │   │
│   │   ├── 📁 utils/
│   │   │   ├── seed.js                         # Database seeding
│   │   │   └── default-plans.js                # Default response plans
│   │   │
│   │   ├── app.js                              # Express app setup
│   │   └── server.js                           # Server entry point
│   │
│   ├── package.json
│   ├── .env                                    # Environment variables
│   └── .gitignore
│
├── 📁 ml-service/                              # Python ML Service
│   ├── 📁 models/
│   │   └── phishing_detector.joblib            # Trained model
│   │
│   ├── 📁 datasets/
│   │   ├── web_phishing.csv                    # Kaggle dataset 1
│   │   ├── email_phishing.csv                  # Kaggle dataset 2
│   │   └── processed_phishing_data.csv         # Cleaned data
│   │
│   ├── 📁 services/
│   │   └── link_analyzer.py                    # ⭐ Python link analyzer
│   │
│   ├── main.py                                 # FastAPI server
│   ├── data_preparation.py                     # ⭐ Dataset processing
│   ├── train_model.py                          # ⭐ ML model training
│   ├── code_visibility_checker.py              # ⭐ Code obfuscation detector
│   ├── requirements.txt
│   └── venv/                                   # Virtual environment
│
├── 📁 frontend/                                # React Frontend (Optional)
│   ├── 📁 src/
│   │   ├── 📁 components/
│   │   │   ├── Navbar.jsx
│   │   │   ├── StatCard.jsx
│   │   │   └── ThreatItem.jsx
│   │   │
│   │   ├── 📁 pages/
│   │   │   ├── LoginPage.jsx
│   │   │   ├── DashboardPage.jsx              # SOC dashboard
│   │   │   ├── AnalyzePage.jsx                # Email analysis UI
│   │   │   └── SOCQueuePage.jsx               # Manual review queue
│   │   │
│   │   ├── 📁 services/
│   │   │   └── api.js                          # Axios API client
│   │   │
│   │   ├── 📁 context/
│   │   │   └── AuthContext.jsx                # Auth state
│   │   │
│   │   ├── App.jsx
│   │   └── main.jsx
│   │
│   ├── package.json
│   ├── tailwind.config.js
│   └── vite.config.js
│
├── 📁 tests/                                   # Integration tests
│   ├── auth.test.js
│   ├── email-analysis.test.js
│   ├── link-analyzer.test.js
│   └── automated-response.test.js
│
├── 📁 database/
│   ├── mysql_schema.sql                        # ⭐ Complete MySQL schema
│   └── seed_data.sql                           # Sample data
│
└── 📁 docs/                                    # Documentation
    ├── hackathon_plan.md                       # Complete implementation guide
    ├── SYSTEM_CHECK.md                         # Prerequisites report
    ├── ML_DATASET_GUIDE.md                     # Dataset & ML training
    ├── DEVELOPMENT_ROADMAP.md                  # Step-by-step guide
    ├── START_HERE.md                           # Quick start
    └── API_DOCUMENTATION.md                    # API endpoints
```

---

## 🌟 KEY FEATURES BY FILE

### ⭐ Character Substitution Detection
**File**: `backend/src/services/char-detection.service.js`
**Features**:
- Detects "rn" vs "m", "vv" vs "w", "cl" vs "d"
- Unicode lookalike characters (Cyrillic, Greek)
- Domain name spoofing
- Visual phishing attacks

### ⭐ Email Formality Checker
**File**: `backend/src/services/formality.service.js`
**Features**:
- Professional domain validation
- Grammar and spelling quality
- Structure analysis (greeting, closing, signature)
- Urgency vs professionalism correlation
- Scores 0-100 for formality

### ⭐ Name Mismatch Detection
**File**: `backend/src/services/name-match.service.js`
**Features**:
- Extracts signature name from email body
- Compares with sender name
- Similarity scoring
- Flags mismatches as high-severity

### ⭐⭐ Advanced Link Analyzer
**File**: `backend/src/services/link-analyzer.service.js`
**Features**:
- **Domain Age**: WHOIS lookup, flags domains < 30 days
- **Subdomain Analysis**: 
  - Multiple subdomain levels (suspicious)
  - Brand in subdomain but not domain (high risk)
  - Suspicious keywords in subdomain
- **Brand Impersonation**: 
  - Checks against known brands list
  - Typosquatting detection
  - Similarity scoring
- **Redirect Behavior**:
  - Tracks redirect chains
  - Flags domain changes
  - Multiple redirect detection
- **Ephemeral Domains**: Detects .tk, .ml, .ga, .cf, .gq, .top, .xyz
- **URL Structure**: IP addresses, excessive length, @ symbol

### ⭐ VirusTotal Integration
**File**: `backend/src/services/virustotal.service.js`
**Features**:
- Scans all URLs in email
- Returns malicious/suspicious/harmless counts
- Auto-flags known threats
- Rate limiting (15s delay for free tier)

### ⭐ Sandbox Scanner
**File**: `backend/src/services/sandbox.service.js`
**Features**:
- File extension checking (.exe, .scr, .bat)
- File header verification (PE, ELF)
- Macro-enabled document detection
- Embedded script detection
- File size anomaly detection

### ⭐⭐ Automated Response System
**File**: `backend/src/services/automated-response.service.js`
**Features**:
- **Immediate Quarantine**: < 100ms response
- **Sender Blocking**: Email + domain blacklisting
- **Account Protection**: 
  - Force password reset
  - Lock account
  - Invalidate sessions
- **Endpoint Isolation**: Flag for IT team
- **Threat Intel Sharing**: IOC extraction and storage
- **Org-wide Alerts**: Community protection
- **Audit Trail**: Complete action logging
- **Metrics**: Response time tracking

### ⭐ Code Visibility Checker
**File**: `ml-service/code_visibility_checker.py`
**Features**:
- Obfuscation detection (base64, exec/eval, char codes)
- Hidden character detection (zero-width, RTL override)
- Homoglyph identification
- Malicious pattern detection (file ops, network, process execution)
- Code reformatting (long lines, minification)
- Encoding tricks detection (hex, unicode, octal)

### ⭐ Dataset Processing
**File**: `ml-service/data_preparation.py`
**Features**:
- Loads 2 Kaggle datasets (18,000+ emails)
- Extracts 15+ features per email
- Feature engineering:
  - Urgency keyword counting
  - Sensitive word detection
  - URL counting and analysis
  - Character substitution scoring
  - Formality calculation
- Train/test split
- Data export for training

### ⭐ ML Model Training
**File**: `ml-service/train_model.py`
**Features**:
- TF-IDF text vectorization (1000 features, trigrams)
- Gradient Boosting Classifier (200 estimators)
- Feature combination (text + numerical)
- Model evaluation (accuracy, classification report)
- Model persistence (joblib)
- Prediction API

---

## 📦 NPM PACKAGES NEEDED

```json
{
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "dotenv": "^16.0.3",
    "bcrypt": "^5.1.0",
    "jsonwebtoken": "^9.0.0",
    "mysql2": "^3.6.0",
    "nodemailer": "^6.9.4",
    "joi": "^17.9.2",
    "helmet": "^7.0.0",
    "morgan": "^1.10.0",
    "axios": "^1.4.0",
    "whois": "^2.13.7",
    "tldextract": "^0.1.5"
  },
  "devDependencies": {
    "nodemon": "^3.0.1",
    "jest": "^29.6.2",
    "supertest": "^6.3.3"
  }
}
```

## 🐍 PYTHON PACKAGES NEEDED

```txt
fastapi==0.103.1
uvicorn==0.23.2
scikit-learn==1.3.0
pandas==2.1.0
numpy==1.24.3
joblib==1.3.2
kagglehub==0.2.0
python-whois==0.8.0
tldextract==3.4.4
autopep8==2.0.4
transformers==4.33.0
torch==2.0.1
```

---

## 🎯 CRITICAL FILES TO CREATE FIRST

### 1. Database Schema
```powershell
# Already created: C:\hack\mysql_schema.sql
mysql -u root -p < C:\hack\mysql_schema.sql
```

### 2. ML Data Preparation
```python
# Create: ml-service/data_preparation.py
# Use code from ML_DATASET_GUIDE.md
```

### 3. Backend Database Connection
```javascript
// Create: backend/src/config/database.js
const mysql = require('mysql2/promise');
require('dotenv').config();

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: process.env.DB_PASSWORD,
  database: 'anti_fraud_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

module.exports = pool;
```

### 4. Environment Variables
```env
# Create: backend/.env
PORT=5000
NODE_ENV=development
DB_PASSWORD=your_mysql_password
DATABASE_URL=mysql://root:your_mysql_password@localhost:3306/anti_fraud_db
JWT_SECRET=your-super-secret-jwt-key-change-in-production
ML_SERVICE_URL=http://localhost:8000
FRONTEND_URL=http://localhost:5173
VIRUSTOTAL_API_KEY=your-virustotal-api-key
```

---

## ⚡ PERFORMANCE OPTIMIZATIONS

### 1. Database Indexes (Already in schema)
```sql
-- Critical indexes for performance
INDEX idx_user_id ON analyzed_emails(user_id);
INDEX idx_threat_score ON analyzed_emails(threat_score);
INDEX idx_review_status ON analyzed_emails(review_status);
INDEX idx_status ON soc_events(status);
```

### 2. Connection Pooling
```javascript
// MySQL connection pool (10 connections)
const pool = mysql.createPool({ connectionLimit: 10 });
```

### 3. Caching (Optional)
```bash
npm install node-cache
```

```javascript
const NodeCache = require('node-cache');
const cache = new NodeCache({ stdTTL: 600 }); // 10 min cache
```

### 4. Rate Limiting
```bash
npm install express-rate-limit
```

```javascript
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);
```

---

## 🚀 DEPLOYMENT READY

### Docker Compose (Optional)
```yaml
version: '3.8'
services:
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: password
      MYSQL_DATABASE: anti_fraud_db
    ports:
      - "3306:3306"
  
  backend:
    build: ./backend
    ports:
      - "5000:5000"
    depends_on:
      - mysql
  
  ml-service:
    build: ./ml-service
    ports:
      - "8000:8000"
```

---

This structure gives you everything you need for a production-ready fraud detection platform! 🎉
