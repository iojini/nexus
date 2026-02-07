# 🛡️ NEXUS - Cyber Threat Intelligence Platform

A production-ready threat intelligence platform that aggregates, analyzes, and visualizes indicators of compromise (IOCs) from multiple open-source threat feeds using machine learning.

[![Live Demo](https://img.shields.io/badge/demo-live-brightgreen)](https://nexus-cti.vercel.app)
[![Python](https://img.shields.io/badge/python-3.9+-blue)](https://python.org)
[![React](https://img.shields.io/badge/react-18-61dafb)](https://reactjs.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

🌐 **[Live Demo](https://nexus-cti.vercel.app)** | 📡 **[API](https://hrtip.onrender.com/health)**

---

## ✨ Features

### 🔍 Multi-Source Threat Aggregation
- **URLhaus** - Malicious URL database
- **ThreatFox** - IOC sharing platform
- **OpenPhish** - Phishing intelligence
- **AlienVault OTX** - Open threat exchange
- **Feodo Tracker** - Botnet C2 tracking
- **MalwareBazaar** - Malware sample database

### 🧠 Machine Learning Analysis
- **Threat Clustering** - DBSCAN algorithm groups related IOCs into potential campaigns
- **Anomaly Detection** - Isolation Forest identifies unusual patterns
- **Confidence Scoring** - Multi-factor scoring with source corroboration

### 🎯 MITRE ATT&CK Integration
- Automatic mapping of threats to ATT&CK techniques
- Kill chain coverage visualization
- Tactic-level heatmaps

### 📊 Interactive Dashboard
- Real-time threat landscape overview
- IOC type distribution charts
- Malware family tracking
- 24-hour activity patterns
- Searchable IOC database

---

## 🖥️ Screenshots

### Threat Overview Dashboard
Real-time statistics showing 505+ IOCs from 6 active feeds, 79% ATT&CK coverage, and ML-detected anomalies.

### MITRE ATT&CK Heatmap
Visual kill chain coverage showing threat distribution across tactics and techniques.

### Campaign Detection
ML-powered clustering identifies related threat activity and potential coordinated campaigns.

---

## 🏗️ Architecture
```
┌────────────────────────────────────────────────────────────────┐
│                        THREAT FEEDS                            │
│  URLhaus │ ThreatFox │ OpenPhish │ OTX │ Feodo │ MalwareBazaar │
└─────────────────────────┬──────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                     COLLECTOR LAYER                             │
│  Feed Parsers → Normalizer → Deduplicator → Confidence Scorer  │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                     ANALYSIS ENGINE                             │
│  MITRE Mapper │ Threat Clusterer │ Anomaly Detector │ Enricher │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌──────────────┐   ┌──────────────┐   ┌──────────────────────────┐
│   Supabase   │◄──│   FastAPI    │──▶│     React Dashboard      │
│  PostgreSQL  │   │   Backend    │   │  Vite + Tailwind + Charts│
└──────────────┘   └──────────────┘   └──────────────────────────┘
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Frontend** | React 18, Vite, Tailwind CSS, Recharts, Lucide Icons |
| **Backend** | Python 3.9+, FastAPI, Uvicorn |
| **ML/Analysis** | scikit-learn (DBSCAN, Isolation Forest), pandas, NumPy |
| **Database** | PostgreSQL (Supabase) |
| **Threat Intel** | STIX/TAXII, Custom feed parsers |
| **Deployment** | Vercel (frontend), Render (API), Supabase (DB) |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Node.js 18+
- Supabase account (free tier works)

### 1. Clone the Repository
```bash
git clone https://github.com/iojini/nexus.git
cd nexus
```

### 2. Backend Setup
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Set environment variables
export SUPABASE_URL="your-supabase-url"
export SUPABASE_KEY="your-supabase-anon-key"

# Collect threat data
python -m collector.feed_manager

# Start API server
python -m analyzer.api
```

### 3. Frontend Setup
```bash
cd dashboard/frontend
npm install
npm run dev
```

Visit `http://localhost:5173` to view the dashboard.

---

## 📡 API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/stats` | GET | Database statistics |
| `/dashboard-data` | GET | Full dashboard payload |
| `/analyze` | POST | Analyze custom IOC list |

### Example Request
```bash
curl https://hrtip.onrender.com/dashboard-data | jq
```

---

## 📁 Project Structure
```
nexus/
├── analyzer/           # ML analysis engine
│   ├── api.py         # FastAPI server
│   ├── clustering.py  # DBSCAN threat clustering
│   ├── anomaly_detector.py
│   └── feature_engineering.py
├── collector/          # Threat feed collectors
│   ├── feed_manager.py
│   └── feeds/         # Individual feed parsers
├── processor/          # Data processing
│   ├── mitre_mapper.py
│   ├── scorer.py
│   └── enricher.py
├── integrations/       # SIEM/SOAR connectors
├── reports/           # PDF report generator
├── dashboard/
│   └── frontend/      # React dashboard
└── database.py        # Supabase client
```

---

## 🔮 Future Enhancements

- [ ] Historical trend analysis
- [ ] Threat actor attribution
- [ ] YARA rule generation
- [ ] Slack/Teams alerting
- [ ] Custom feed support
- [ ] IOC export (STIX, CSV, JSON)

---

## 📄 License

MIT License - feel free to use this project for learning or as a portfolio piece.

---

## 👤 Author

**Irene** - [GitHub](https://github.com/iojini)

---

*Built with ☕ and a passion for cybersecurity*
