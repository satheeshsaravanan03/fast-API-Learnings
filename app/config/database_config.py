from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config.env_config import settings
from app.utils.logger_utils import log_info

DATABASE_URL = settings.database_url

engine = create_engine(
    DATABASE_URL,
    echo=True,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

log_info(context="DATABASE", message="Database connected successfully")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
