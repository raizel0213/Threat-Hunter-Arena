"""
Environment-based configuration.
All values can be overridden via .env file or real environment variables.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the backend/ directory if it exists
load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "app" / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ---- Database ----
DATABASE_URL: str = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{DATA_DIR / 'arena.db'}"
)

# ---- CORS ----
# Comma-separated list of allowed origins. Use "*" only for local dev.
_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
ALLOWED_ORIGINS: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]

# ---- Rate limiting ----
RATE_LIMIT_SUBMIT: str = os.getenv("RATE_LIMIT_SUBMIT", "10/minute")  # per IP
RATE_LIMIT_DEFAULT: str = os.getenv("RATE_LIMIT_DEFAULT", "60/minute")

# ---- Input size limits ----
MAX_RULE_BYTES: int = int(os.getenv("MAX_RULE_BYTES", "32768"))   # 32 KB max rule size
MAX_PLAYER_NAME_LEN: int = int(os.getenv("MAX_PLAYER_NAME_LEN", "32"))
MAX_IOC_COUNT: int = int(os.getenv("MAX_IOC_COUNT", "20"))

# ---- YARA execution timeout ----
YARA_TIMEOUT_SECONDS: int = int(os.getenv("YARA_TIMEOUT_SECONDS", "5"))

# ---- Log format ----
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

# ---- Shared log-gen constants ----
COMMON_USERNAMES = [
    "jsmith", "amehta", "rkapoor", "svance", "tnguyen",
    "kpatel", "dwilson", "ltorres", "mchen", "ofernandez",
    "admin", "administrator", "root", "svc_backup", "svc_sql",
]

ATTACKER_USERNAMES_TRIED = [
    "admin", "administrator", "root", "test", "guest",
    "user", "oracle", "postgres", "ubuntu", "support",
]

INTERNAL_SUBNET = "10.42."
