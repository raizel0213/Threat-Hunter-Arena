"""
SQLite models via SQLAlchemy with safe column migration at startup.
"""
from datetime import datetime, timezone
import logging

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, JSON, text
from sqlalchemy.orm import declarative_base, sessionmaker

from app.core.config import DATABASE_URL

log = logging.getLogger(__name__)
Base = declarative_base()


class Submission(Base):
    __tablename__ = "submissions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    player_name = Column(String(32), nullable=False, index=True)
    case_id = Column(String(32), nullable=False, index=True)
    score_total = Column(Float, nullable=False)
    score_ioc = Column(Float, nullable=False)
    score_mitre = Column(Float, nullable=False)
    score_detection = Column(Float, nullable=False)
    score_speed_bonus = Column(Float, nullable=False)
    elapsed_seconds = Column(Float, nullable=False)
    detail_json = Column(JSON, nullable=True)
    mitre_correct_json = Column(JSON, nullable=True)
    submitted_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def _migrate(conn):
    """
    Safe additive migration: add any columns that exist in the ORM model
    but are missing from the live table (happens when upgrading an existing DB).
    SQLite doesn't support DROP/ALTER beyond ADD COLUMN, so we only add.
    """
    existing = {
        row[1]
        for row in conn.execute(text("PRAGMA table_info(submissions)")).fetchall()
    }
    desired = {c.key: c for c in Submission.__table__.columns}
    for col_name, col in desired.items():
        if col_name not in existing and col_name != "id":
            col_type = col.type.compile(engine.dialect)
            nullable = "" if col.nullable else " NOT NULL"
            try:
                conn.execute(text(f"ALTER TABLE submissions ADD COLUMN {col_name} {col_type}{nullable}"))
                log.info("Migration: added column submissions.%s", col_name)
            except Exception as e:
                log.warning("Migration skipped for %s: %s", col_name, e)


def init_db():
    Base.metadata.create_all(bind=engine)
    with engine.connect() as conn:
        _migrate(conn)
        conn.commit()
    log.info("Database initialised at %s", DATABASE_URL)


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
