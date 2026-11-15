import json, os
from collections import Counter
from typing import Literal
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from .core import Base, engine, SessionLocal, User, Alert, hash_pw, check_pw, make_token, read_token
from .monitor import Monitor, list_interfaces

Base.metadata.create_all(engine)
app = FastAPI(title="AI-IDS")
app.add_middleware(CORSMiddleware, allow_origins=[os.environ.get("CORS_ORIGIN", "http://localhost:5173")], allow_methods=["*"], allow_headers=["*"])
SEV = ("critical", "high", "medium", "low", "informational")
sockets: set[WebSocket] = set()

def row(a: Alert):
    return {c.name: (str(getattr(a, c.name)) if c.name == "ts" else getattr(a, c.name)) for c in Alert.__table__.columns}

async def on_alerts(alerts, mode):
    with SessionLocal() as db:
        rows = [Alert(**a, source=mode) for a in alerts]
        db.add_all(rows); db.commit()
        out = [row(r) for r in rows]
    for ws in list(sockets):
        try:
            for r in out: await ws.send_text(json.dumps(r))
        except Exception: sockets.discard(ws)

monitor = Monitor(on_alerts)

def current(authorization: str = Header(default="")) -> User:
    try:
        uid = read_token(authorization.removeprefix("Bearer "))
    except Exception:
        raise HTTPException(401, "Not authenticated")
    with SessionLocal() as db:
        u = db.get(User, uid)
    if not u: raise HTTPException(401, "Not authenticated")
    return u

def need(*roles):
    def dep(u: User = Depends(current)):
        if u.role not in roles: raise HTTPException(403, "Insufficient role")
        return u
    return dep

class Creds(BaseModel):
    email: str = Field(min_length=3, max_length=200); password: str = Field(min_length=8, max_length=100)

@app.post("/api/auth/register", status_code=201)
def register(b: Creds):
    with SessionLocal() as db:
        if db.query(User).filter_by(email=b.email.lower()).first(): raise HTTPException(409, "Email already registered")
        role = "admin" if db.query(User).count() == 0 else "viewer"  # first user bootstraps as admin
        u = User(email=b.email.lower(), password_hash=hash_pw(b.password), role=role); db.add(u); db.commit()
        return {"token": make_token(u.id), "email": u.email, "role": u.role}

@app.post("/api/auth/login")
def login(b: Creds):
    with SessionLocal() as db:
        u = db.query(User).filter_by(email=b.email.lower()).first()
    if not u or not check_pw(b.password, u.password_hash): raise HTTPException(401, "Invalid email or password")
    return {"token": make_token(u.id), "email": u.email, "role": u.role}

@app.get("/api/auth/me")
def me(u: User = Depends(current)): return {"email": u.email, "role": u.role}

@app.get("/api/network/interfaces")
def interfaces(_: User = Depends(current)): return list_interfaces()

class StartBody(BaseModel):
    mode: Literal["live", "simulation"] = "simulation"; interface: str | None = None

@app.post("/api/network/monitor/start")
async def start(b: StartBody, _: User = Depends(need("admin"))):
    try: await monitor.start(b.mode, b.interface)
    except Exception as e: raise HTTPException(400, f"Could not start: {e}")
    return status()

@app.post("/api/network/monitor/stop")
async def stop(_: User = Depends(need("admin"))):
    await monitor.stop(); return status()

@app.get("/api/network/status")
def status(_: User = Depends(current)):
    return {"running": monitor.running, "mode": monitor.mode, "packets": monitor.packets, "error": monitor.error,
            "baselineReady": monitor.engine.model is not None}

@app.get("/api/detection/alerts")
def alerts(severity: str | None = None, q: str | None = None, status: str | None = None, limit: int = Query(50, le=200), offset: int = 0, _: User = Depends(current)):
    with SessionLocal() as db:
        qs = db.query(Alert)
        if severity: qs = qs.filter(Alert.severity == severity)
        if status: qs = qs.filter(Alert.status == status)
        if q: qs = qs.filter(Alert.src_ip.contains(q) | Alert.dst_ip.contains(q))
        return {"total": qs.count(), "items": [row(a) for a in qs.order_by(Alert.id.desc()).offset(offset).limit(limit)]}

class AlertPatch(BaseModel):
    status: Literal["open", "investigating", "investigated"] | None = None
    assignee: str | None = Field(None, max_length=200); notes: str | None = Field(None, max_length=5000)

@app.patch("/api/detection/alerts/{aid}")
def patch(aid: int, b: AlertPatch, _: User = Depends(need("admin", "analyst"))):
    with SessionLocal() as db:
        a = db.get(Alert, aid)
        if not a: raise HTTPException(404, "Not found")
        for k, v in b.model_dump(exclude_none=True).items(): setattr(a, k, v)
        db.commit(); return row(a)

@app.get("/api/detection/statistics")
def stats(_: User = Depends(current)):
    with SessionLocal() as db:
        al = db.query(Alert).all()
    return {"total": len(al), "bySeverity": Counter(a.severity for a in al), "byCategory": Counter(a.category for a in al),
            "topSources": Counter(a.src_ip for a in al).most_common(5)}

@app.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket, token: str = ""):
    try: read_token(token)
    except Exception: return await ws.close(code=4401)
    await ws.accept(); sockets.add(ws)
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect: sockets.discard(ws)
