"""Config, database models and auth helpers."""
import os, time
import bcrypt, jwt
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime, func
from sqlalchemy.orm import declarative_base, sessionmaker

JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is required (see .env.example)")
DB_URL = os.environ.get("DATABASE_URL", "sqlite:///./ids.db")
engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(engine, expire_on_commit=False)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(200), unique=True, index=True, nullable=False)
    password_hash = Column(String(200), nullable=False)
    role = Column(String(20), default="viewer")  # admin | analyst | viewer

class Alert(Base):
    __tablename__ = "security_alerts"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, server_default=func.now(), index=True)
    src_ip = Column(String(64), index=True); dst_ip = Column(String(64))
    src_port = Column(Integer); dst_port = Column(Integer); protocol = Column(String(16))
    category = Column(String(60), index=True); severity = Column(String(16), index=True)
    confidence = Column(Float); method = Column(String(40)); description = Column(Text)
    action = Column(Text); source = Column(String(16))  # live | simulation
    status = Column(String(20), default="open", index=True)  # open | investigating | investigated
    assignee = Column(String(200)); notes = Column(Text, default="")

def hash_pw(p: str) -> str: return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
def check_pw(p: str, h: str) -> bool: return bcrypt.checkpw(p.encode(), h.encode())
def make_token(uid: int) -> str: return jwt.encode({"sub": str(uid), "exp": int(time.time()) + 8 * 3600}, JWT_SECRET, "HS256")
def read_token(t: str) -> int: return int(jwt.decode(t, JWT_SECRET, ["HS256"])["sub"])
