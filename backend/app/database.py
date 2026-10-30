import logging
from sqlalchemy import create_engine, text, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.app.config import settings

logger = logging.getLogger(__name__)

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {},
)


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enforces SQLite foreign key constraints on every database connection."""
    if settings.database_url.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def upgrade_db_schema():
    """
    Safely upgrades existing SQLite tables by adding any missing columns and indexes.
    Guarantees backward compatibility with pre-existing database files and is idempotent
    across repeated application startups.
    """
    with engine.connect() as conn:
        # 1. Upgrade findings table if present
        try:
            res = conn.execute(text("PRAGMA table_info(findings)")).fetchall()
            existing_finding_cols = [row[1] for row in res]

            if "fingerprint" not in existing_finding_cols and "id" in existing_finding_cols:
                conn.execute(text("ALTER TABLE findings ADD COLUMN fingerprint VARCHAR(64)"))
                logger.info("Migrated schema: Added column 'fingerprint' to 'findings'.")
            if "created_at" not in existing_finding_cols and "id" in existing_finding_cols:
                conn.execute(text("ALTER TABLE findings ADD COLUMN created_at DATETIME"))
                logger.info("Migrated schema: Added column 'created_at' to 'findings'.")
            if "evidence_raw" not in existing_finding_cols and "id" in existing_finding_cols:
                conn.execute(text("ALTER TABLE findings ADD COLUMN evidence_raw TEXT"))
                logger.info("Migrated schema: Added column 'evidence_raw' to 'findings'.")
            if "secret_token" not in existing_finding_cols and "id" in existing_finding_cols:
                conn.execute(text("ALTER TABLE findings ADD COLUMN secret_token VARCHAR(256)"))
                logger.info("Migrated schema: Added column 'secret_token' to 'findings'.")

            # Ensure indexes exist
            if "fingerprint" in existing_finding_cols or "fingerprint" not in existing_finding_cols:
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_fingerprint ON findings (fingerprint)"))
            if "assessment_id" in existing_finding_cols:
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_assessment_id ON findings (assessment_id)"))
        except Exception as e:
            logger.warning("Notice during findings schema upgrade: %s", e)

        # 2. Upgrade assessments table if present
        try:
            res = conn.execute(text("PRAGMA table_info(assessments)")).fetchall()
            existing_assess_cols = [row[1] for row in res]

            if "score_breakdown" not in existing_assess_cols and "id" in existing_assess_cols:
                conn.execute(text("ALTER TABLE assessments ADD COLUMN score_breakdown JSON"))
                logger.info("Migrated schema: Added column 'score_breakdown' to 'assessments'.")
        except Exception as e:
            logger.warning("Notice during assessments schema upgrade: %s", e)

        conn.commit()


def init_db():
    from backend.app import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    upgrade_db_schema()
