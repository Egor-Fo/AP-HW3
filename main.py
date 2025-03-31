# main.py
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security.utils import get_authorization_scheme_param
from typing import Optional
from fastapi.responses import RedirectResponse, StreamingResponse
from pydantic import BaseModel, HttpUrl
from datetime import datetime, timedelta
import shortuuid
import redis
import io
import qrcode
from sqlalchemy import create_engine, Column, String, DateTime, Integer, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
import os
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

SECRET_KEY = "secret-key-for-jwt"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=60))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost/postgres")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

app = FastAPI()

# DB Setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Redis
cache = redis.Redis.from_url(REDIS_URL)


class User(Base):
    __tablename__ = 'users'

    id = Column(String, primary_key=True, default=lambda: shortuuid.uuid())
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

    links = relationship("Link", back_populates="owner")


class Link(Base):
    __tablename__ = 'links'

    short_code = Column(String, primary_key=True, unique=True, index=True)
    original_url = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    clicks = Column(Integer, default=0)
    last_accessed_at = Column(DateTime, nullable=True)
    owner_id = Column(String, ForeignKey('users.id'), nullable=True)

    owner = relationship("User", back_populates="links")


Base.metadata.create_all(bind=engine)


class LinkCreate(BaseModel):
    original_url: HttpUrl
    custom_alias: str | None = None
    expires_at: datetime | None = None


class LinkUpdate(BaseModel):
    new_original_url: HttpUrl


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Invalid authentication")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user


def get_current_user_optional(
    request: Request,
    db: Session = Depends(get_db)
) -> Optional[User]:
    auth = request.headers.get("Authorization")
    scheme, token = get_authorization_scheme_param(auth)
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            return None
        user = db.query(User).filter(User.username == username).first()
        return user
    except JWTError:
        return None


@app.post("/register")
def register(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if user:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = get_password_hash(form.password)
    new_user = User(username=form.username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"username": new_user.username}


@app.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = create_access_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}


# Create short link
@app.post('/links/shorten')
def create_link(link: LinkCreate, db: Session = Depends(get_db), current_user: Optional[User] = Depends(get_current_user_optional)):
    short_code = link.custom_alias if link.custom_alias else shortuuid.ShortUUID().random(length=6)

    existing_link = db.query(Link).filter_by(short_code=short_code).first()
    if existing_link:
        raise HTTPException(status_code=400, detail='Alias already exists.')

    db_link = Link(
        short_code=short_code,
        original_url=str(link.original_url),
        expires_at=link.expires_at,
        owner_id=current_user.id if current_user else None
    )
    db.add(db_link)
    db.commit()
    db.refresh(db_link)

    cache.set(short_code, str(link.original_url))

    return {'short_code': short_code}


# Redirect
@app.get('/{short_code}')
def redirect_to_original(short_code: str, db: Session = Depends(get_db)):
    cached_url = cache.get(short_code)
    if cached_url:
        url = cached_url.decode()
    else:
        link = db.query(Link).filter_by(short_code=short_code).first()
        if not link or (link.expires_at and link.expires_at < datetime.utcnow()):
            raise HTTPException(status_code=404, detail='Link not found or expired')

        url = link.original_url
        cache.set(short_code, url)

    db.query(Link).filter(Link.short_code == short_code).update({
        "clicks": Link.clicks + 1,
        "last_accessed_at": datetime.utcnow()
    })
    db.commit()

    return RedirectResponse(url)


# Stats
@app.get('/links/{short_code}/stats')
def link_stats(short_code: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    link = db.query(Link).filter_by(short_code=short_code).first()
    if not link:
        raise HTTPException(status_code=404, detail='Link not found')
    if link.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    return {
        "original_url": link.original_url,
        "created_at": link.created_at,
        "clicks": link.clicks,
        "last_accessed_at": link.last_accessed_at
    }


# Delete
@app.delete('/links/{short_code}')
def delete_link(short_code: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    link = db.query(Link).filter_by(short_code=short_code).first()
    if not link:
        raise HTTPException(status_code=404, detail='Link not found')
    if link.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    db.delete(link)
    db.commit()

    cache.delete(short_code)

    return {"detail": "Link deleted."}


# Update
@app.put('/links/{short_code}')
def update_link(short_code: str, link_update: LinkUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    link = db.query(Link).filter_by(short_code=short_code).first()
    if not link:
        raise HTTPException(status_code=404, detail='Link not found')
    if link.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    link.original_url = str(link_update.new_original_url)
    db.commit()

    cache.set(short_code, str(link_update.new_original_url))

    return {"detail": "Link updated."}


# Generate QR code
@app.get('/links/{short_code}/qrcode')
def generate_qr(short_code: str):
    qr = qrcode.make(f"http://yourdomain.com/{short_code}")
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=8000)