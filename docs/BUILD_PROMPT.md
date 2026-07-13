# Threat Hunter Arena — Master Build Prompt

Build a complete, working, real (not simulated/mocked) SOC analyst training and
benchmarking platform called **Threat Hunter Arena**. This is a resume/portfolio
project for a cybersecurity professional pursuing SOC Analyst / Threat Hunter
roles. Every detection, log source, and scoring mechanism must be functionally
real — no placeholder logic, no fake "AI thinks this is malicious" stubs.

## Core Concept

The player is given a "case": a folder of synthetic logs representing a live
intrusion (auth logs, DNS queries, firewall events, process trees, file
integrity events). The player must:

1. Identify Indicators of Compromise (IOCs) in the raw logs
2. Reconstruct the attack chain (sequence of attacker actions)
3. Map each stage to MITRE ATT&CK tactics/techniques (correct technique IDs)
4. Submit a working Sigma or YARA detection rule that would catch the attack
   in the provided logs WITHOUT flagging the clean/benign log noise in the
   same case (false-positive penalty)

The player is scored on accuracy, speed, and false-positive rate. Cases have
difficulty tiers. There's a leaderboard.

## Tech Stack (mandatory)

- **Backend:** Python, FastAPI, SQLite (no external DB dependency)
- **Log generation:** pure Python, deterministic-but-randomized synthetic
  log generator (seeded, so cases are reproducible for scoring)
- **Detection validation:** real Sigma rule parsing/evaluation (use the
  `pySigma` library) and real YARA rule compilation/matching (use the
  `yara-python` library) against the actual generated log/sample files —
  not string-matching hacks
- **Frontend:** React + Vite, package manager `bun`, Tailwind core utility
  classes only
- **MITRE mapping:** use the real MITRE ATT&CK technique ID taxonomy
  (e.g., T1110 Brute Force, T1021 Lateral Movement, T1567 Exfiltration)

## Architecture

```
threat-hunter-arena/
├── backend/
│   ├── app/
│   │   ├── main.py                 # FastAPI app entrypoint
│   │   ├── core/                   # config, db session, constants
│   │   ├── generators/             # synthetic log generators by source type
│   │   │   ├── auth_log_gen.py
│   │   │   ├── dns_log_gen.py
│   │   │   ├── firewall_log_gen.py
│   │   │   └── process_log_gen.py
│   │   ├── scenarios/              # attack chain definitions (the "cases")
│   │   │   ├── scenario_base.py
│   │   │   ├── case_001_brute_force_lateral.py
│   │   │   ├── case_002_phishing_exfil.py
│   │   │   └── ...
│   │   ├── scoring/                # validation + scoring engine
│   │   │   ├── sigma_validator.py
│   │   │   ├── yara_validator.py
│   │   │   ├── mitre_scorer.py
│   │   │   └── score_engine.py
│   │   ├── models/                 # pydantic + SQLite ORM models
│   │   └── data/                   # generated case files live here at runtime
│   ├── requirements.txt
│   └── tests/
├── frontend/
│   ├── src/
│   │   ├── pages/ (CaseList, CaseDetail, Submit, Leaderboard, MitreHeatmap)
│   │   ├── components/
│   │   └── api/
│   ├── package.json
├── docs/
│   ├── README.md
│   ├── ARCHITECTURE.md
│   └── SCENARIO_AUTHORING_GUIDE.md
└── docker-compose.yml (optional, for one-command local run)
```

## Functional Requirements

### 1. Log Generators
Each generator produces realistic, schema-correct synthetic logs (e.g.
Windows Security Event Log style auth logs, BIND/dnsmasq-style DNS query
logs, iptables/pfSense-style firewall logs, Sysmon-style process creation
trees). Generators accept a `seed` and a `scenario_config` so the same case
always reproduces identically. Logs must include realistic noise (benign
traffic) mixed in with the actual attack events, at a ratio configurable per
difficulty tier.

### 2. Scenario / Case Definitions
Each case defines:
- A named attack chain (ordered list of attacker actions)
- Which MITRE ATT&CK technique ID each action maps to
- Which log sources are involved
- Ground-truth IOCs (IPs, hashes, usernames, domains) for scoring
- Difficulty tier (1–3)

Build at minimum 3 complete cases for v1:
1. **Tier 1:** Brute-force SSH login → successful auth (single auth log source)
2. **Tier 2:** Phishing-delivered malware → C2 beacon via DNS → lateral
   movement via SMB (multi-source: process + DNS + auth logs)
3. **Tier 3:** Insider threat → data staging → exfiltration over HTTPS
   (multi-source with heavier benign noise, harder signal-to-noise ratio)

### 3. Scoring Engine
- **IOC accuracy:** compare submitted IOCs against ground truth (precision/recall)
- **MITRE mapping accuracy:** compare submitted technique IDs against the
  case's ground-truth chain
- **Detection rule validation:** actually run the submitted Sigma/YARA rule
  against the case's full log/sample set; reward true positives, penalize
  false positives on the benign noise, penalize false negatives on missed
  attack events
- **Speed bonus:** time from case start to submission
- Produce a final composite score (0–100) with a breakdown by category

### 4. API Endpoints (FastAPI)
- `GET /cases` — list available cases with difficulty/metadata
- `GET /cases/{id}` — fetch case logs + briefing (no ground truth exposed)
- `POST /cases/{id}/submit` — submit IOCs, MITRE mapping, and detection rule;
  returns score breakdown
- `GET /leaderboard` — top scores across all players/cases
- `GET /mitre/heatmap/{player_id}` — techniques covered by a player across
  all completed cases, for the ATT&CK Navigator-style visualization

### 5. Frontend
- Case list view with difficulty badges
- Case detail view: log viewer (searchable/filterable), timer, submission form
  for IOCs / MITRE technique picker / Sigma-or-YARA rule editor (with syntax
  highlighting)
- Results view: score breakdown, what was missed, correct chain reveal
- MITRE ATT&CK heatmap visualization of techniques covered
- Leaderboard page
- Apply the frontend-design skill for visual polish — no generic
  Bootstrap-default aesthetic; should look like a professional SOC tool
  (dark theme, monospace for logs, data-dense layout)

## Non-Negotiables

- No mocked/fake validation — Sigma and YARA rules must actually execute
  against real generated data
- No hardcoded "correct answer" string matching for rule submissions
- Logs must be schema-realistic enough that someone who knows the real log
  format would recognize it
- Must run locally with `bun install && bun run dev` (frontend) and
  `pip install -r requirements.txt && uvicorn app.main:app --reload` (backend)
- Include a README with setup instructions, screenshots placeholder section,
  and a clear explanation of what the project demonstrates for a resume reader

## Delivery Format

Deliver as a complete zipped project. Include a top-level README.md framed
for a portfolio/resume context (skills demonstrated: detection engineering,
synthetic log generation, Sigma/YARA rule development, MITRE ATT&CK mapping,
full-stack development). Do not include any "for students" or "training
platform for an institute" framing — this is a personal skills-demonstration
project.
