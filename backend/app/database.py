import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker


# ============================================================
# Database Configuration
# ============================================================

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://cloudshield:cloudshield@localhost:5432/cloudshield",
)


# ============================================================
# Database Engine
# ============================================================

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)


# ============================================================
# Session Factory
# ============================================================

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# ============================================================
# Base Model
# ============================================================

Base = declarative_base()


# ============================================================
# Database Dependency
# ============================================================

def get_db():
    """
    Creates a database session for an API request
    and closes it when the request is finished.
    """

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()