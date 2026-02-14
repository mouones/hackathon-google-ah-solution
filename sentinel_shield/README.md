# Sentinel Shield - Enterprise Security Platform

🛡️ **On-premise security solution for SMBs**

## Quick Start

```powershell
# 1. Activate virtual environment
.\venv\Scripts\Activate

# 2. Start the backend
cd src
uvicorn main:app --reload --port 8000

# 3. Access dashboard
# Open http://localhost:8000
```

## Project Structure

```
sentinel_shield/
├── src/
│   ├── main.py                 # FastAPI application entry
│   ├── api/                    # API routes
│   │   ├── auth.py            # Authentication endpoints
│   │   ├── emails.py          # Email analysis endpoints
│   │   ├── links.py           # Link analysis endpoints
│   │   ├── threats.py         # Threat intelligence endpoints
│   │   └── dashboard.py       # Dashboard data endpoints
│   ├── modules/               # Core security modules
│   │   ├── phishing_detector.py
│   │   ├── link_analyzer.py
│   │   ├── malware_analyzer.py
│   │   └── auto_response.py
│   ├── models/                # Database models
│   │   ├── user.py
│   │   ├── email.py
│   │   └── threat.py
│   ├── services/              # Business logic
│   │   ├── email_service.py
│   │   ├── ml_service.py
│   │   └── alert_service.py
│   └── utils/                 # Utilities
│       ├── config.py
│       ├── database.py
│       └── security.py
├── datasets/                  # Training data & threat intel
├── models/                    # ML models
├── config/                    # Configuration files
├── tests/                     # Test suite
└── docker/                    # Docker configuration
```

## Features

- 🎣 **Phishing Detection** - ML-powered email analysis
- 🔗 **Link Security** - URL reputation and analysis
- 🦠 **Malware Sandbox** - Safe file execution
- 🌐 **Network Segmentation** - VLAN isolation
- ⚡ **Auto Response** - Sub-second containment
- 📊 **Dashboard** - Real-time security monitoring
- 🎓 **Phishing Simulations** - Employee training

## Tech Stack

- **Backend:** FastAPI (Python 3.11+)
- **Frontend:** React + TypeScript
- **Database:** PostgreSQL
- **Cache:** Redis
- **ML:** PyTorch, Transformers
- **Container:** Docker

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/login` | POST | User authentication |
| `/api/v1/emails/analyze` | POST | Analyze email threat |
| `/api/v1/links/analyze` | POST | Analyze URL threat |
| `/api/v1/alerts` | GET | List active alerts |
| `/api/v1/dashboard/stats` | GET | Dashboard statistics |

## Documentation

- [Architecture Document](./Sentinel_Shield_Architecture.html) - Use cases, diagrams, design
- [Complete Documentation](./Sentinel_Shield_Complete_Documentation.html) - All features

## License

MIT License - See LICENSE file
