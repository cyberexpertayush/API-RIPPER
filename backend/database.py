"""
API RIPPER — Database Connection Manager
"""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
import logging

from backend.config import get_settings
from backend.models import Base

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Database connection and initialization manager"""

    def __init__(self, database_url: str = None):
        self.settings = get_settings()
        self.database_url = database_url or self.settings.DATABASE_URL
        self.engine = None
        self.SessionLocal = None

    def init_db(self):
        """Initialize database and create tables"""
        logger.info(f"Initializing database: {self.database_url}")

        if "sqlite" in self.database_url:
            self.engine = create_engine(
                self.database_url,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
                echo=self.settings.DATABASE_ECHO,
            )

            @event.listens_for(self.engine, "connect")
            def set_sqlite_pragma(dbapi_conn, connection_record):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()
        else:
            self.engine = create_engine(
                self.database_url,
                echo=self.settings.DATABASE_ECHO,
                pool_pre_ping=True,
            )

        self.SessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=self.engine
        )

        Base.metadata.create_all(bind=self.engine)
        logger.info("Database tables created successfully")
        return self

    def get_session(self) -> Session:
        if not self.SessionLocal:
            self.init_db()
        return self.SessionLocal()

    def close(self):
        if self.engine:
            self.engine.dispose()
            logger.info("Database connections closed")


# Global instance
_db_manager = None


def get_database_manager() -> DatabaseManager:
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager


def init_database():
    manager = get_database_manager()
    manager.init_db()
    return manager


def get_db() -> Session:
    """FastAPI dependency for database session"""
    manager = get_database_manager()
    db = manager.get_session()
    try:
        yield db
    finally:
        db.close()
