# 🚀 DEVELOPMENT ROADMAP - Anti-Fraud Platform
## Priority-Based Implementation Guide

---

## 📊 PHASE 0: Dataset & ML Preparation (START HERE)

### Step 1: Setup ML Environment
```bash
cd C:\hack
mkdir ml-service datasets models

# Install Python packages
pip install kagglehub pandas numpy scikit-learn
pip install transformers torch  # For pre-trained models
pip install whois python-whois tldextract  # For link analysis
pip install fastapi uvicorn python-multipart
pip install autopep8  # For code formatting
```

### Step 2: Download & Process Datasets
```bash
cd ml-service
# Create dataset loader script
python
```

```python
import kagglehub

# Download datasets
web_path = kagglehub.dataset_download("shashwatwork/web-page-phishing-detection-dataset")
email_path = kagglehub.dataset_download("naserabdullahalam/phishing-email-dataset")

print(f"Web dataset: {web_path}")
print(f"Email dataset: {email_path}")
```

### Step 3: Process and Train Model
```bash
# Use the data_preparation.py script from ML_DATASET_GUIDE.md
python data_preparation.py

# Train model
python train_model.py

# Expected output: models/phishing_detector.joblib
```

**Time Estimate**: 2-3 hours  
**Output**: Trained ML model ready for API integration

---

## 📊 PHASE 1: Core Backend (PRIORITY 1)

### Database Setup
```bash
# Start MySQL
# Run mysql_schema.sql
mysql -u root -p < C:\hack\mysql_schema.sql

# Verify
mysql -u root -p
```

```sql
USE anti_fraud_db;
SHOW TABLES;
-- Should show all 20+ tables
```

### Backend Foundation

**Priority Order**:

1. ✅ **Database Connection** (30 min)
   - `backend/src/config/database.js` - MySQL connection with mysql2
   - Test connection

2. ✅ **Authentication** (1 hour)
   - `backend/src/middleware/auth.js`
   - `backend/src/controllers/auth.controller.js`
   - `backend/src/routes/auth.routes.js`
   - JWT tokens, bcrypt passwords

3. ✅ **Email Analysis Core** (2 hours)
   - `backend/src/services/char-detection.service.js` - Character substitution
   - `backend/src/services/formality.service.js` - Professional email check
   - `backend/src/services/name-match.service.js` - Name mismatch detection
   - `backend/src/controllers/email.controller.js`

4. ✅ **Advanced Link Analysis** (2 hours)
   - Install: `npm install whois tldextract axios`
   - `backend/src/services/link-analyzer.service.js`
   - Domain age checking
   - Subdomain analysis
   - Brand impersonation detection
   - Redirect behavior analysis

5. ✅ **VirusTotal Integration** (1 hour)
   - Get API key from virustotal.com
   - `backend/src/services/virustotal.service.js`
   - Rate limiting (15s between requests for free tier)

6. ✅ **Sandbox Scanner** (1 hour)
   - `backend/src/services/sandbox.service.js`
   - File header analysis
   - Macro detection
   - Script scanning

7. ✅ **SOC Team Features** (2 hours)
   - `backend/src/controllers/soc.controller.js`
   - Manual review queue
   - Approve/block workflow
   - Event tracking

8. ✅ **Automated Response** (1.5 hours)
   - `backend/src/services/automated-response.service.js`
   - Quarantine
   - Block sender/domain
   - Account protection
   - Endpoint isolation

**Time Estimate**: 11 hours total  
**Result**: Fully functional backend API

---

## 📊 PHASE 2: ML Service Integration (PRIORITY 2)

### FastAPI ML Service

```bash
cd ml-service
python -m venv venv
.\venv\Scripts\activate
pip install fastapi uvicorn scikit-learn pandas numpy joblib
```

Create `main.py`:
```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import joblib
from pydantic import BaseModel

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"])

# Load trained model
model = joblib.load('models/phishing_detector.joblib')

class EmailData(BaseModel):
    subject: str
    body: str
    sender: str
    
@app.post("/predict")
async def predict(email: EmailData):
    # Extract features and predict
    features = extract_features(email)
    prediction = model.predict(features)
    confidence = model.predict_proba(features)[0][1]
    
    return {
        "is_phishing": bool(prediction),
        "confidence": float(confidence),
        "threat_score": int(confidence * 100)
    }

@app.get("/health")
async def health():
    return {"status": "ok"}
```

Start service:
```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

**Time Estimate**: 2 hours  
**Result**: ML predictions available via API

---

## 📊 PHASE 3: Testing & Validation (PRIORITY 3)

### Create Test Suite

```bash
cd backend
npm install --save-dev jest supertest
```

Test files:
- `tests/auth.test.js` - Authentication
- `tests/email-analysis.test.js` - Email analysis
- `tests/link-analyzer.test.js` - Link analysis
- `tests/automated-response.test.js` - Response system

Run tests:
```bash
npm test
```

**Time Estimate**: 3 hours  
**Result**: Validated backend functionality

---

## 📊 PHASE 4: Frontend (LAST PRIORITY)

### Setup React Frontend

```bash
cd frontend
npm create vite@latest . -- --template react
npm install react-router-dom axios recharts lucide-react
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p
```

**Build Order**:

1. Login/Auth (1 hour)
2. Dashboard - SOC view (2 hours)
3. Email Analysis Page (1.5 hours)
4. Alert System (1 hour)
5. Reports/Stats (1.5 hours)

**Time Estimate**: 7 hours  
**Result**: Functional UI

---

## 🎯 RECOMMENDED DEVELOPMENT SEQUENCE

### Day 1: Core Functionality (8-10 hours)
```
Morning (4 hours):
✅ Setup ML environment
✅ Download and process datasets
✅ Train ML model
✅ Setup database (MySQL)

Afternoon (4-6 hours):
✅ Backend: Database connection
✅ Backend: Authentication
✅ Backend: Email analysis core
✅ Backend: Link analysis
```

### Day 2: Advanced Features (8-10 hours)
```
Morning (4-5 hours):
✅ VirusTotal integration
✅ Sandbox scanner
✅ SOC team features
✅ Automated response system

Afternoon (4-5 hours):
✅ ML service API
✅ Integration testing
✅ Bug fixes
```

### Day 3: UI & Polish (Optional)
```
All day (7-8 hours):
✅ Frontend development
✅ Connect to backend
✅ Testing end-to-end
```

---

## 🔥 QUICK START COMMANDS

### 1. Initialize Project Structure
```powershell
cd C:\hack
mkdir anti-fraud-platform
cd anti-fraud-platform
mkdir backend frontend ml-service datasets models tests

# Initialize Backend
cd backend
npm init -y
npm install express cors dotenv bcrypt jsonwebtoken mysql2
npm install nodemailer joi helmet morgan whois tldextract axios
npm install --save-dev nodemon jest supertest

mkdir -p src/{config,controllers,middleware,models,routes,services,utils}

# Initialize Frontend
cd ../frontend
npm create vite@latest . -- --template react
npm install

# Initialize ML Service
cd ../ml-service
python -m venv venv
.\venv\Scripts\activate
pip install fastapi uvicorn scikit-learn pandas numpy joblib
pip install kagglehub whois python-whois tldextract autopep8
```

### 2. Setup Database
```powershell
# Start MySQL service
net start MySQL80

# Create database
mysql -u root -p < C:\hack\mysql_schema.sql
```

### 3. Environment Variables
Create `backend/.env`:
```env
PORT=5000
NODE_ENV=development
DATABASE_URL=mysql://root:yourpassword@localhost:3306/anti_fraud_db
JWT_SECRET=your-super-secret-jwt-key-change-in-production
ML_SERVICE_URL=http://localhost:8000
FRONTEND_URL=http://localhost:5173
VIRUSTOTAL_API_KEY=get-from-virustotal.com
```

### 4. Start Development Servers
```powershell
# Terminal 1: Backend
cd backend
npm run dev

# Terminal 2: ML Service
cd ml-service
.\venv\Scripts\activate
uvicorn main:app --reload

# Terminal 3: Frontend (later)
cd frontend
npm run dev
```

---

## 📈 Success Metrics

### Core Features (Must Have):
- [ ] Email analysis with 90%+ accuracy
- [ ] Character substitution detection
- [ ] Link analysis with VirusTotal
- [ ] SOC team review queue
- [ ] Automated response triggers
- [ ] Subdomain risk assessment
- [ ] Brand impersonation detection

### Advanced Features (Nice to Have):
- [ ] Sandbox attachment scanning
- [ ] Domain age checking
- [ ] Redirect analysis
- [ ] Code visibility checker
- [ ] Threat intelligence sharing
- [ ] Organization-wide alerts

### Performance Targets:
- [ ] Email analysis < 2 seconds
- [ ] ML prediction < 500ms
- [ ] Automated response < 1 second
- [ ] 95%+ uptime

---

## 🛠️ Debugging Tips

### Common Issues:

**MySQL Connection Failed**:
```powershell
# Check service
Get-Service MySQL80

# Start service
net start MySQL80

# Test connection
mysql -u root -p
```

**VirusTotal Rate Limit**:
```javascript
// Add delay between requests
await new Promise(resolve => setTimeout(resolve, 15000));
```

**ML Service Not Starting**:
```powershell
# Activate venv first
cd ml-service
.\venv\Scripts\activate
python -c "import fastapi; print('OK')"
```

---

## 🎯 FOCUS: Backend First, Frontend Last!

The plan emphasizes:
1. ✅ **ML Model** - Train and test first
2. ✅ **Backend API** - Full functionality
3. ✅ **Advanced Detection** - All research-backed features
4. ✅ **Testing** - Validate everything works
5. ⏭️ **Frontend** - Simple UI to demonstrate

**Estimated Total Time**: 20-25 hours for fully functional backend + ML
