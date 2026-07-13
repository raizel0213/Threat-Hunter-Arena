# Threat Hunter Arena

A gamified SOC analyst skills-demonstration platform. Players investigate
synthetic intrusions built from real, schema-accurate log sources, identify
IOCs, reconstruct attack chains mapped to MITRE ATT&CK, and submit Sigma
and YARA detection rules that are compiled and executed against the actual
generated data — producing a real precision/recall-based score.

Built as a personal portfolio centerpiece for SOC Analyst and Threat Hunter
roles. Every detection mechanic is functionally real: no mocked scoring,
no hardcoded "correct answer" string matching.

---

## What it demonstrates

| Skill | How it's shown |
|---|---|
| Detection engineering | Real Sigma rule parsing via pySigma, evaluated against generated logs |
| YARA rule development | yara-python compilation + matching against recovered artifact samples |
| MITRE ATT&CK mapping | Technique-level scoring tracked across all cases, ATT&CK coverage heatmap |
| Log analysis | Multi-source correlation (auth, DNS, process, firewall logs) |
| Threat hunting | Signal-to-noise discrimination in Tier 3 (0.3–1.5% attack signal) |
| Full-stack development | FastAPI + SQLite backend, React + Vite frontend |

---

## Cases

| ID | Title | Tier | Sources | Attack chain |
|---|---|---|---|---|
| case-001 | Midnight Knock | 1 | auth | SSH brute force → credential success |
| case-002 | Invoice 4471 | 2 | process + DNS + auth | Phishing macro → encoded PS → C2 beacon → lateral movement |
| case-003 | Quiet Resignation | 3 | process + DNS + firewall | Data staging → domain lookup → 480MB chunked exfil |

---

## Running locally

### Prerequisites
- Python 3.11+
- Node 18+ (or `bun`)

### Setup

```bash
# Backend
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload

# Frontend (separate terminal)
cd frontend
npm install                     # or: bun install
npm run dev                     # or: bun run dev
```

Open `http://localhost:5173`. Backend API docs at `http://localhost:8000/docs`.

---

## Running with Docker (production)

Single command to build and run the full stack:

```bash
docker compose up --build
```

App runs at `http://localhost:3000`. To change the port:

```bash
PORT=8080 docker compose up --build
```

To stop: `docker compose down`
To wipe data volume: `docker compose down -v`

### What Docker does
- Builds the React frontend and serves it via nginx
- Proxies `/api/*` requests to the FastAPI backend
- Persists the SQLite database in a named Docker volume
- Waits for the backend healthcheck before starting the frontend

---

## Configuration

All backend settings are environment variables. Edit `backend/.env`:

| Variable | Default | Description |
|---|---|---|
| `ALLOWED_ORIGINS` | `http://localhost:5173,...` | CORS allowed origins (comma-separated) |
| `RATE_LIMIT_SUBMIT` | `10/minute` | Submission rate limit per IP |
| `RATE_LIMIT_DEFAULT` | `60/minute` | General rate limit per IP |
| `YARA_TIMEOUT_SECONDS` | `5` | Max YARA rule execution time |
| `MAX_RULE_BYTES` | `32768` | Max rule size (32 KB) |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

---

## Scoring

Each submission is scored 0–100 across four independent signals:

- **IOC accuracy (30 pts)** — F1 score comparing submitted IPs/usernames against ground truth
- **MITRE mapping (20 pts)** — F1 score on technique IDs against the case's ground-truth ATT&CK chain
- **Detection rule (40 pts)** — real TP/FP/FN evaluation of submitted Sigma and/or YARA rule against the case's log/sample set. False positives on benign noise are penalized. On cases with recovered artifacts (case-002), points split 20/20 between Sigma log detection and YARA file detection.
- **Speed bonus (10 pts)** — full 10 pts at/under par time, linear decay to zero at 3× par

---

## Project structure

```
threat-hunter-arena/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app, rate limiting, validation
│   │   ├── core/config.py       # Env-based configuration
│   │   ├── generators/          # Synthetic log generators (auth, DNS, process, firewall)
│   │   ├── scenarios/           # Case definitions (3 tiers)
│   │   ├── scoring/             # Sigma validator, YARA validator, score engine
│   │   └── models/db.py         # SQLAlchemy models + safe column migration
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── .env.example
│   └── .gitignore
├── frontend/
│   ├── src/
│   │   ├── App.jsx              # Hash-based routing
│   │   ├── api/client.js        # API fetch wrapper
│   │   ├── components/          # Navbar, LogPanel, SubmissionForm, ResultsPanel, ...
│   │   └── pages/               # CaseList, CaseDetail, Leaderboard, MitreHeatmap
│   ├── Dockerfile               # Multi-stage: Node build → nginx serve
│   ├── nginx.conf
│   └── .env.example
├── docker-compose.yml
├── Makefile
└── README.md
```

---

## Make commands

```bash
make install        # Install all dependencies (backend venv + frontend npm)
make dev-backend    # Start FastAPI dev server (port 8000)
make dev-frontend   # Start Vite dev server  (port 5173)
make docker-up      # Build and run full stack via Docker (port 3000)
make docker-down    # Stop Docker stack
make docker-logs    # Tail Docker logs
make docker-clean   # Remove containers, volumes, images
```
