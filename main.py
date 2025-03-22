from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
# from typing import List
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
import database


# Конфигурация JWT
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


app = FastAPI(description="CRUD задач для пользователей через JWT"

)

database.init_db()  # Инициализация базы данных


# Модели данных для API
class UserCreate(BaseModel):
    username: str
    password: str


class User(BaseModel):
    id: int
    username: str


class TaskCreate(BaseModel):
    title: str
    description: str
    status: database.TaskStatus
    priority: database.TaskPriority  # Добавлено поле приоритета


class Task(TaskCreate):
    id: int
    created_at: str


class TaskUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    status: database.TaskStatus | None = None
    priority: database.TaskPriority | None = None  # Добавлено поле приоритета


# Зависимость для получения сессии базы данных
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Хэширование паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# JWT функции
def create_access_token(data: dict, expires_delta=None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Получение текущего пользователя
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username  # Вернем имя пользователя для дальнейшего использования
    except JWTError:
        raise credentials_exception

# Регистрация пользователя
@app.post("/users/", response_model=User)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = database.User(username=user.username, hashed_password=get_password_hash(user.password))
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# Аутентификация пользователя и получение токена
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(database.User).filter(database.User.username == form_data.username).first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)

    return {"access_token": access_token, "token_type": "bearer"}


# CRUD операции:
@app.post("/tasks/")
def create_task(
    task: TaskCreate,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    """Создание задачи"""
    db_task = database.Task(**task.dict(), owner_id=current_user.id)  # Устанавливаем владельца задачи)
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task


@app.get("/tasks/")
def read_tasks(
    sort_by: str = None,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    """Получение списка задач с возможностью сортировки"""
    query = db.query(database.Task).filter(
        database.Task.owner_id == current_user.id
        ).all()

    if sort_by == "title":
        query = query.order_by(database.Task.title)
    elif sort_by == "status":
        query = query.order_by(database.Task.status)
    elif sort_by == "created_at":
        query = query.order_by(database.Task.created_at)

    return query.all()


@app.get("/tasks/top/{n}")  #, response_model=List[Task])
def read_top_tasks(
    n: int,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    """Получение списка топ n задач по приоритетам (высокий приоритет первым)"""
    return db.query(database.Task).filter(
        database.Task.owner_id == current_user.id
        ).order_by(
        database.Task.priority.desc()
        ).limit(n).all()


@app.get("/tasks/{task_id}")
def read_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    """Получение задачи по id"""
    task = db.query(database.Task).filter(
        database.Task.id == task_id,
        database.Task.owner_id == current_user.id
        ).first()
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@app.put("/tasks/{task_id}")
def update_task(
    task_id: int,
    task_update: TaskUpdate,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    """Обновление данных задачи по id"""
    task = db.query(database.Task).filter(
        database.Task.id == task_id,
        database.Task.owner_id == current_user.id
        ).first()

    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")

    for key, value in task_update.dict(exclude_unset=True).items():
        setattr(task, key, value)

    db.commit()
    db.refresh(task)

    return task


@app.delete("/tasks/{task_id}")  # response_model=dict)
def delete_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    """Удаление задачи по id"""
    task = db.query(database.Task).filter(
        database.Task.id == task_id,
        database.Task.owner_id == current_user.id
        ).first()

    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    db.delete(task)
    db.commit()

    return {"detail": "Task deleted successfully"}


# Новый маршрут для поиска задач по тексту
@app.get("/tasks/search/")  #, response_model=List[Task])
def search_tasks(
    query: str,
    db: Session = Depends(get_db)
):
    """Поиск текста в задачах"""
    tasks = db.query(database.Task).filter(
        (database.Task.title.ilike(f"%{query}%")) |
        (database.Task.description.ilike(f"%{query}%"))
    ).all()

    return tasks