# AI-Powered SIEM Analyzer

A full-stack Security Information and Event Management system built from scratch with AI-driven threat detection.

## What it does
- Ingests logs from 10+ sources — SSH, Nginx, Windows, MySQL, AWS, Docker, firewall, RDP, FTP
- Uses LLM to parse any log format automatically — no regex needed
- Detects threats every 60 seconds automatically using Groq LLM
- Maps attacks to MITRE ATT&CK framework
- Remembers repeat attackers and escalates severity
- Sends Discord alerts for critical/high incidents
- Generates PDF incident reports automatically
- Live web dashboard with 5 tabs

## Tech Stack
- **Backend:** Python, FastAPI
- **Storage:** Elasticsearch, PostgreSQL, Redis
- **AI:** Groq LLM (Llama 3.3 70B)
- **Automation:** Celery background workers
- **Infrastructure:** Docker, Docker Compose
- **Frontend:** HTML, CSS, JavaScript

## Setup

### Requirements
- Docker + Docker Compose
- Python 3.11+
- Groq API key (free at groq.com)
- Discord webhook URL (optional)

### Installation
```bash
git clone https://github.com/Raghadi01/siem-analyzer
cd siem-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Add your GROQ_API_KEY, GROQ_MODEL, ES_HOST, DISCORD_WEBHOOK_URL to .env
```

### Running
```bash
# Terminal 1 — Start services and API
docker-compose up -d
uvicorn app.main:app --reload

# Terminal 2 — Celery worker
celery -A app.worker worker --loglevel=info

# Terminal 3 — Celery beat scheduler
celery -A app.worker beat --loglevel=info

# Open dashboard
http://localhost:8000/dashboard
```

### Attack simulator
```bash
python3 simulate.py
```

## Features
- AI log parser — accepts any log format, no regex maintenance
- Multi-source correlation — same IP across SSH, Nginx, Syslog = multi-stage attack
- Attacker memory — repeat attackers escalate to Critical automatically
- IP investigation — full timeline of any attacker activity
- PDF reports — professional incident reports generated automatically
- Discord alerts — real-time notifications for critical threats

## Detected attack types
- SSH and RDP brute force
- Web attacks (path traversal, SQL injection, .env exposure)
- Persistence (reverse shell cron, backdoor users, scheduled tasks)
- Windows Event Log attacks (4625, 4624, 4688, 4698)
- Cloud attacks (AWS Console login, privilege escalation)
- Container escape
- Data exfiltration
- Network reconnaissance and port scanning
