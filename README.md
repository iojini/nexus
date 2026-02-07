# NEXUS - Threat Intelligence Platform

A real-time cyber threat intelligence platform that aggregates, analyzes, and visualizes indicators of compromise (IOCs) from multiple threat feeds.

🌐 **Live Demo**: [nexus-cti.vercel.app](https://nexus-cti.vercel.app)

![Dashboard Screenshot](dashboard/frontend/public/screenshot.png)

## Features

- **Real-time IOC Aggregation** - Collects threat data from 6+ feeds (URLhaus, ThreatFox, OpenPhish, AlienVault OTX, etc.)
- **MITRE ATT&CK Mapping** - Automatically maps threats to ATT&CK techniques and tactics
- **ML-Powered Analysis** - Clustering and anomaly detection to identify campaigns
- **Interactive Dashboard** - Visualize threat landscape with charts and heatmaps
- **IOC Database** - Searchable database with confidence scoring

## Tech Stack

**Frontend**
- React + Vite
- Tailwind CSS
- Recharts

**Backend**
- Python + FastAPI
- scikit-learn (ML)
- STIX/TAXII support

**Infrastructure**
- Vercel (frontend)
- Render (API)
- Supabase (PostgreSQL)

## Architecture
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Threat    │────▶│   FastAPI   │────▶│  Supabase   │
│   Feeds     │     │   Backend   │     │  Database   │
└─────────────┘     └──────┬──────┘     └─────────────┘
                          │
                          ▼
                   ┌─────────────┐
                   │    React    │
                   │  Dashboard  │
                   └─────────────┘
```

## Local Development

### Prerequisites
- Python 3.9+
- Node.js 18+
- Supabase account

### Backend Setup
```bash
cd ~/projects/nexus
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export SUPABASE_URL="your-supabase-url"
export SUPABASE_KEY="your-supabase-key"

python -m analyzer.api
```

### Frontend Setup
```bash
cd dashboard/frontend
npm install
npm run dev
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /stats` | Database statistics |
| `GET /dashboard-data` | Aggregated dashboard data |
| `POST /analyze` | Analyze IOC list |

## Screenshots

### Threat Overview
Real-time stats, IOC distribution, and threat type breakdown.

### MITRE ATT&CK Map
Kill chain heatmap showing technique coverage.

### Campaigns
ML-detected threat clusters and anomalies.

## License

MIT

## Author

Built by [Irene](https://github.com/iojini)
