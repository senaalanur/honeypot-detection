# Honeypot Detection System

An AI-powered distributed honeypot that captures attacker activity across SSH, HTTP,
and FTP services, analyses threats in real-time using Claude AI, and stores structured
intelligence for investigation.

## Architecture
```
Attackers → [SSH / HTTP / FTP Honeypots]
                      ↓
              [Redis Event Bus]
                      ↓
           [AI Analysis Engine] ← Claude API
            (threat scoring, IOC extraction,
             MITRE ATT&CK mapping)
                      ↓
         ┌────────────┴────────────┐
    [PostgreSQL]          [Elasticsearch]
    (structured           (full-text search)
     time-series)
         └────────────┬────────────┘
              [FastAPI REST API]
                      ↓
           [Alert Manager]
        (Slack + Gmail, rate-limited)
```

## Key Features

- **Adaptive deception** — AI generates dynamic fake responses tailored to each attacker
- **Threat intelligence** — MITRE ATT&CK TTP mapping, IOC extraction, intent classification
- **Dual storage** — PostgreSQL for structured queries, Elasticsearch for full-text search
- **Real-time alerts** — Slack and Gmail notifications with 5-minute rate limiting per IP
- **Production-ready** — async Python, structured JSON logging, Docker Compose, CI/CD

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Honeypot services | Python `asyncio` (raw TCP servers) |
| AI analysis | Anthropic Claude API |
| Event streaming | Redis Pub/Sub |
| Structured storage | PostgreSQL + asyncpg |
| Search | Elasticsearch |
| REST API | FastAPI + uvicorn |
| Alerting | Slack webhooks + Gmail SMTP |
| Containerisation | Docker Compose |
| CI/CD | GitHub Actions |

## Quick Start
```bash
# 1. Clone and configure
git clone https://github.com/senaalanur/honeypot-detection.git
cd honeypot-detection
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# 2. Start everything
docker compose -f docker/docker-compose.yml up --build

# 3. The system is now running:
#    SSH honeypot  → localhost:2222
#    HTTP honeypot → localhost:8080
#    FTP honeypot  → localhost:2121
#    REST API      → localhost:8000
#    Kibana        → localhost:5601
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /api/events?limit=100` | Recent attack events |
| `GET /api/stats` | 24h statistics |
| `GET /api/search?q=<query>` | Full-text search across all events |

## Running Tests
```bash
pip install -e ".[dev]"
pytest tests/ -v --cov=src
```

## Project Structure
```
src/
├── honeypot/       # SSH, HTTP, FTP async listeners
├── analysis/       # AI classifier, IOC extractor
├── storage/        # PostgreSQL + Elasticsearch clients
├── alerts/         # Slack + Gmail alert manager
├── api/            # FastAPI REST routes
└── core/           # Config, logging, Redis event bus
```

## License

MIT