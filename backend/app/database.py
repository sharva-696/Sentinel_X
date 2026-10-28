from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.app.config import settings

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {},
)

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
    Safely upgrades existing SQLite tables by adding any missing columns.
    Ensures backward compatibility with pre-existing database files.
    """
    with engine.connect() as conn:
        # Check findings table columns
        try:
            res = conn.execute(text("PRAGMA table_info(findings)")).fetchall()
            existing_finding_cols = [row[1] for row in res]

            if "fingerprint" not in existing_finding_cols and "id" in existing_finding_cols:
                conn.execute(text("ALTER TABLE findings ADD COLUMN fingerprint VARCHAR(64)"))
            if "created_at" not in existing_finding_cols and "id" in existing_finding_cols:
                conn.execute(text("ALTER TABLE findings ADD COLUMN created_at DATETIME"))
        except Exception:
            pass

        # Check assessments table columns
        try:
            res = conn.execute(text("PRAGMA table_info(assessments)")).fetchall()
            existing_assess_cols = [row[1] for row in res]

            if "score_breakdown" not in existing_assess_cols and "id" in existing_assess_cols:
                conn.execute(text("ALTER TABLE assessments ADD COLUMN score_breakdown JSON"))
        except Exception:
            pass

        conn.commit()


def init_db():
    from backend.app import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    upgrade_db_schema()
