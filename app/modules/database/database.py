import os
from contextlib import contextmanager
from dotenv import load_dotenv
from loguru import logger
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy_utils import database_exists, create_database

from app.modules.database.models.models import Base
import app.modules.database.models.models
import app.modules.database.models.context
import app.modules.database.models.findings

load_dotenv()

DATABASE_URL = f"postgresql+psycopg://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@localhost:5433/{os.getenv('DB')}"


engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

if not database_exists(engine.url):
    logger.info(f"Creating database...")
    create_database(engine.url)

logger.info(f"Creating tables...")
Base.metadata.create_all(engine)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


@contextmanager
def transaction():
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()