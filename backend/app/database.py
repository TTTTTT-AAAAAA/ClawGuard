from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from . import models
    from .security.password_utils import hash_password

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if not db.query(models.User).filter(models.User.username == "admin").first():
            db.add(models.User(username="admin", password_hash=hash_password("admin123"), role="admin"))
        if not db.query(models.User).filter(models.User.username == "student").first():
            db.add(models.User(username="student", password_hash=hash_password("student123"), role="student"))
        if not db.query(models.User).filter(models.User.username == "auditor").first():
            db.add(models.User(username="auditor", password_hash=hash_password("auditor123"), role="auditor"))
        db.commit()
    finally:
        db.close()

