import os
from contextlib import contextmanager, asynccontextmanager
from dotenv import load_dotenv
from loguru import logger
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.ext.asyncio.session import AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy_utils import database_exists, create_database

from app.modules.database.models.models import Base
import app.modules.database.models.models
import app.modules.database.models.context
import app.modules.database.models.findings

load_dotenv()

DATABASE_URL = f"postgresql+psycopg://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@localhost:{os.getenv("DB_PORT")}/{os.getenv('DB')}"


engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

async_engine = create_async_engine(
    DATABASE_URL,
    echo=True
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

AsyncSessionLocal = sessionmaker(
    bind=async_engine, expire_on_commit=False, class_=AsyncSession
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


@asynccontextmanager
async def async_transaction():
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise