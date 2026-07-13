"""
Threat Hunter Arena — FastAPI backend (production-hardened).
"""
import logging
import re
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator, model_validator
from sqlalchemy.orm import Session
from sqlalchemy import desc
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.core.config import (
    ALLOWED_ORIGINS, RATE_LIMIT_SUBMIT, RATE_LIMIT_DEFAULT,
    MAX_PLAYER_NAME_LEN, MAX_IOC_COUNT, MAX_RULE_BYTES, LOG_LEVEL,
)
from app.models.db import init_db, get_session, Submission
from app.scoring.score_engine import compute_score
from app.scenarios.case_001_brute_force import Case001BruteForce
from app.scenarios.case_002_phishing_lateral import Case002PhishingLateral
from app.scenarios.case_003_insider_exfil import Case003InsiderExfil

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Rate limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=[RATE_LIMIT_DEFAULT])

# ── Case registry (generated once at startup) ─────────────────────────────────
CASE_REGISTRY = {
    "case-001": Case001BruteForce(seed=1337),
    "case-002": Case002PhishingLateral(seed=2024),
    "case-003": Case003InsiderExfil(seed=4242),
}
PAR_SECONDS = {
    "case-001": 600,
    "case-002": 1200,
    "case-003": 1800,
}
_VALID_NAME = re.compile(r"^[A-Za-z0-9_\-\.]{1,32}$")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise DB and pre-generate all cases at startup (not on first request)."""
    init_db()
    for case_id, case in CASE_REGISTRY.items():
        case.ensure_generated()
        log.info("Case %s pre-generated (%s log entries)", case_id,
                 sum(len(v) for v in case.player_logs.values()))
    log.info("Startup complete. CORS origins: %s", ALLOWED_ORIGINS)
    yield
    log.info("Shutdown.")


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Threat Hunter Arena API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None,
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# ── Request / response models ─────────────────────────────────────────────────
class SubmissionRequest(BaseModel):
    player_name: str
    submitted_ips: list[str] = []
    submitted_usernames: list[str] = []
    submitted_mitre_ids: list[str] = []
    sigma_rule_yaml: str = ""
    yara_rule_text: str = ""
    elapsed_seconds: float

    @field_validator("player_name")
    @classmethod
    def validate_player_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("player_name cannot be empty")
        if len(v) > MAX_PLAYER_NAME_LEN:
            raise ValueError(f"player_name max {MAX_PLAYER_NAME_LEN} characters")
        if not _VALID_NAME.match(v):
            raise ValueError("player_name: letters, digits, _ - . only")
        return v

    @field_validator("submitted_ips", "submitted_usernames", "submitted_mitre_ids")
    @classmethod
    def limit_lists(cls, v: list[str]) -> list[str]:
        return [s.strip() for s in v[:MAX_IOC_COUNT] if s.strip()]

    @field_validator("sigma_rule_yaml", "yara_rule_text")
    @classmethod
    def limit_rule_size(cls, v: str) -> str:
        if len(v.encode()) > MAX_RULE_BYTES:
            raise ValueError(f"Rule exceeds {MAX_RULE_BYTES // 1024} KB limit")
        return v

    @field_validator("elapsed_seconds")
    @classmethod
    def clamp_elapsed(cls, v: float) -> float:
        return max(0.0, min(v, 86400.0))  # clamp: 0s – 24h


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "cases": len(CASE_REGISTRY)}


@app.get("/cases")
@limiter.limit(RATE_LIMIT_DEFAULT)
def list_cases(request: Request):
    return [case.to_case_summary() for case in CASE_REGISTRY.values()]


@app.get("/cases/{case_id}")
@limiter.limit(RATE_LIMIT_DEFAULT)
def get_case(request: Request, case_id: str):
    case = CASE_REGISTRY.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case.to_case_detail()


@app.post("/cases/{case_id}/submit")
@limiter.limit(RATE_LIMIT_SUBMIT)
def submit_case(
    request: Request,
    case_id: str,
    submission: SubmissionRequest,
    db: Session = Depends(get_session),
):
    case = CASE_REGISTRY.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    log.info("Submission: player=%s case=%s elapsed=%.1fs",
             submission.player_name, case_id, submission.elapsed_seconds)

    breakdown = compute_score(
        submitted_ips=submission.submitted_ips,
        submitted_usernames=submission.submitted_usernames,
        submitted_mitre_ids=submission.submitted_mitre_ids,
        sigma_rule_yaml=submission.sigma_rule_yaml,
        ground_truth=case.ground_truth,
        case_logs=case.player_logs,
        elapsed_seconds=submission.elapsed_seconds,
        par_seconds=PAR_SECONDS.get(case_id, 600),
        yara_rule_text=submission.yara_rule_text,
        case_samples=case.samples,
    )

    log.info("Score: player=%s case=%s total=%.1f ioc=%.1f mitre=%.1f detect=%.1f",
             submission.player_name, case_id, breakdown.score_total,
             breakdown.score_ioc, breakdown.score_mitre, breakdown.score_detection)

    yara_detail: dict = {}
    if breakdown.yara_result is not None:
        yara_detail = {
            "yara_true_positives": breakdown.yara_result.true_positives,
            "yara_false_positives": breakdown.yara_result.false_positives,
            "yara_false_negatives": breakdown.yara_result.false_negatives,
        }

    truth_mitre_ids = {t.technique_id.lower() for t in case.ground_truth.mitre_chain}
    correct_mitre_ids = [
        mid for mid in submission.submitted_mitre_ids
        if mid.strip().lower() in truth_mitre_ids
    ]

    record = Submission(
        player_name=submission.player_name,
        case_id=case_id,
        score_total=breakdown.score_total,
        score_ioc=breakdown.score_ioc,
        score_mitre=breakdown.score_mitre,
        score_detection=breakdown.score_detection,
        score_speed_bonus=breakdown.score_speed_bonus,
        elapsed_seconds=submission.elapsed_seconds,
        mitre_correct_json=correct_mitre_ids,
        detail_json={
            "notes": breakdown.notes,
            "ioc_precision": breakdown.ioc_precision,
            "ioc_recall": breakdown.ioc_recall,
            "mitre_precision": breakdown.mitre_precision,
            "mitre_recall": breakdown.mitre_recall,
            "sigma_true_positives": breakdown.sigma_result.true_positives,
            "sigma_false_positives": breakdown.sigma_result.false_positives,
            "sigma_false_negatives": breakdown.sigma_result.false_negatives,
            **yara_detail,
        },
    )
    db.add(record)
    db.commit()

    return {
        "score_total": breakdown.score_total,
        "breakdown": {
            "ioc": breakdown.score_ioc,
            "mitre": breakdown.score_mitre,
            "detection": breakdown.score_detection,
            "speed_bonus": breakdown.score_speed_bonus,
        },
        "notes": breakdown.notes,
        "correct_answer": {
            "ips": case.ground_truth.ioc_ips,
            "usernames": case.ground_truth.ioc_usernames,
            "mitre_chain": [
                {"id": t.technique_id, "name": t.name, "tactic": t.tactic}
                for t in case.ground_truth.mitre_chain
            ],
        },
    }


@app.get("/leaderboard")
@limiter.limit(RATE_LIMIT_DEFAULT)
def leaderboard(
    request: Request,
    case_id: str | None = None,
    limit: int = 20,
    db: Session = Depends(get_session),
):
    limit = max(1, min(limit, 100))
    q = db.query(Submission)
    if case_id:
        q = q.filter(Submission.case_id == case_id)
    rows = q.order_by(desc(Submission.score_total)).limit(limit).all()
    return [
        {
            "player_name": r.player_name,
            "case_id": r.case_id,
            "score_total": r.score_total,
            "elapsed_seconds": r.elapsed_seconds,
            "submitted_at": r.submitted_at.isoformat(),
        }
        for r in rows
    ]


@app.get("/mitre/heatmap/{player_name}")
@limiter.limit(RATE_LIMIT_DEFAULT)
def mitre_heatmap(request: Request, player_name: str, db: Session = Depends(get_session)):
    if not _VALID_NAME.match(player_name):
        raise HTTPException(status_code=400, detail="Invalid player_name format")

    catalog: dict[str, dict] = {}
    for case in CASE_REGISTRY.values():
        for t in case.ground_truth.mitre_chain:
            if t.technique_id not in catalog:
                catalog[t.technique_id] = {
                    "technique_id": t.technique_id,
                    "name": t.name,
                    "tactic": t.tactic,
                    "times_correct": 0,
                    "cases": [],
                }
            if case.case_id not in catalog[t.technique_id]["cases"]:
                catalog[t.technique_id]["cases"].append(case.case_id)

    submissions = db.query(Submission).filter(Submission.player_name == player_name).all()
    for sub in submissions:
        for tid in (sub.mitre_correct_json or []):
            for key in catalog:
                if key.lower() == tid.strip().lower():
                    catalog[key]["times_correct"] += 1
                    break

    by_tactic: dict[str, list[dict]] = {}
    for entry in catalog.values():
        by_tactic.setdefault(entry["tactic"], []).append({
            "technique_id": entry["technique_id"],
            "name": entry["name"],
            "identified": entry["times_correct"] > 0,
            "times_correct": entry["times_correct"],
            "cases": entry["cases"],
        })

    total = len(catalog)
    identified = sum(1 for e in catalog.values() if e["times_correct"] > 0)
    return {
        "player_name": player_name,
        "total_techniques": total,
        "identified_count": identified,
        "coverage_pct": round(identified / total * 100, 1) if total else 0.0,
        "tactics": by_tactic,
    }
