from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import redis

from app.config import settings

# --- PostgreSQL setup ---
engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency: yields a DB session, closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- Redis setup ---
redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)


def get_redis():
    """FastAPI dependency: returns the shared Redis client."""
    return redis_client