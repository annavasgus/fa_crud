from sqlalchemy.orm import Session
from sqlalchemy import ForeignKey, create_engine, Column, Integer, String, Enum, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import enum
from cachetools import TTLCache, cached


# Создаем кэш с временем жизни 300 секунд и размером 100
cache = TTLCache(maxsize=100, ttl=300)

DATABASE_URL = "sqlite:///./fa_crud.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False,
        "timeout": 7
    },
    # echo=True,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
    )

Base = declarative_base()


class TaskStatus(enum.Enum):
    PENDING = "в ожидании"
    IN_PROGRESS = "в работе"
    COMPLETED = "завершено"


class TaskPriority(enum.Enum):
    LOW = "низкий"
    MEDIUM = "средний"
    HIGH = "высокий"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

    # Связь с задачами
    tasks = relationship("Task", back_populates="owner")


class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String)
    status = Column(Enum(TaskStatus))
    priority = Column(Enum(TaskPriority))  # Добавлено поле приоритета
    created_at = Column(DateTime, default=datetime.utcnow)
    owner_name = Column(Integer, ForeignKey('users.username'))  # Здесь определяем внешний ключ

    owner = relationship("User", back_populates="tasks")


def init_db():
    Base.metadata.create_all(bind=engine)


@cached(cache)
def get_user_by_id(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()

@cached(cache)
def get_tasks_by_user_id(db: Session, user_id: int):
    return db.query(Task).filter(Task.owner_id == user_id).all()
