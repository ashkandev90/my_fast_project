# main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.hash import bcrypt
from jose import JWTError, jwt
from typing import Optional, List

# ==================
# تنظیمات اولیه
# ==================
SECRET_KEY = "mysecret"  # حتماً در حالت واقعی یک کلید قوی و مخفی انتخاب کنید
ALGORITHM = "HS256"

app = FastAPI()

# ==================
# دیتابیس
# ==================
DATABASE_URL = "sqlite:///./test.db"  # دیتابیس SQLite کنار پروژه ساخته می‌شود
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ==================
# مدل دیتابیس
# ==================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    full_name = Column(String, default="")

Base.metadata.create_all(bind=engine)

# ==================
# مدل‌های Pydantic (درخواست و پاسخ)
# ==================
class UserCreate(BaseModel):
    username: str
    password: str
    full_name: Optional[str] = ""

class UserRead(BaseModel):
    id: int
    username: str
    full_name: str

    class Config:
        from_attributes = True

# برای احراز هویت JWT
class Token(BaseModel):
    access_token: str
    token_type: str

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ==================
# توابع کمکی
# ==================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def create_user(db: Session, user: UserCreate):
    hashed_password = bcrypt.hash(user.password)
    db_user = User(username=user.username, hashed_password=hashed_password, full_name=user.full_name)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, username: str, password: str):
    user = get_user_by_username(db, username)
    if not user:
        return False
    if not bcrypt.verify(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
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
    except JWTError:
        raise credentials_exception
    user = get_user_by_username(db, username=username)
    if user is None:
        raise credentials_exception
    return user

# ==================
# روت‌های API
# ==================

# ثبت‌نام
@app.post("/register", response_model=UserRead)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user_by_username(db, user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return create_user(db, user)

# ورود و دریافت JWT
@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# دریافت اطلاعات پروفایل کاربر جاری (نیاز به توکن)
@app.get("/profile", response_model=UserRead)
def read_profile(current_user: User = Depends(get_current_user)):
    return current_user

# مشاهده همه کاربران (مثلاً برای تست)
@app.get("/users", response_model=List[UserRead])
def read_users(db: Session = Depends(get_db)):
    return db.query(User).all()

# ویرایش پروفایل
@app.put("/profile", response_model=UserRead)
def update_profile(new_info: UserCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    user = db.query(User).filter(User.id == current_user.id).first()
    user.full_name = new_info.full_name
    db.commit()
    db.refresh(user)
    return user

# حذف کاربر جاری
@app.delete("/profile")
def delete_profile(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db.delete(current_user)
    db.commit()
    return {"msg": "deleted"}

# ==================
# اجرای سرور
# ==================
# اجرا با دستور زیر در ترمینال:
# uvicorn main:app --reload