import os, secrets
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc
from .db import Base, engine, get_db
from .models import User, PairCode, Device, Activity, DeviceEvent
from .schemas import RegisterIn, LoginIn, PairIn, TelemetryIn, ActivityIn, EventIn
from .security import hash_password, verify_password, make_access_token, decode_token, new_device_token, token_hash

Base.metadata.create_all(bind=engine)
app = FastAPI(title="FIRGY PHONE MONITOR API", version="1.0.0")
origins = os.getenv("CORS_ORIGINS", "http://localhost:8000").split(",")
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory="app/static"), name="static")

def current_user(authorization: str | None = Header(default=None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Login diperlukan")
    uid = decode_token(authorization[7:])
    user = db.get(User, uid) if uid else None
    if not user: raise HTTPException(401, "Token tidak valid atau kedaluwarsa")
    return user

def current_device(x_device_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    if not x_device_token: raise HTTPException(401, "Device token diperlukan")
    device = db.query(Device).filter_by(device_token_hash=token_hash(x_device_token), revoked=False).first()
    if not device: raise HTTPException(401, "Perangkat tidak dikenal atau sudah dicabut")
    return device

@app.get("/", response_class=HTMLResponse)
def home():
    with open("app/static/index.html", encoding="utf-8") as f: return f.read()

@app.get("/health")
def health(): return {"status":"ok"}

@app.post("/api/register")
def register(data: RegisterIn, db: Session = Depends(get_db)):
    email = data.email.lower()
    if db.query(User).filter_by(email=email).first(): raise HTTPException(409, "Email sudah terdaftar")
    user = User(email=email, password_hash=hash_password(data.password))
    db.add(user); db.commit(); db.refresh(user)
    return {"access_token": make_access_token(user.id), "token_type":"bearer", "email":user.email}

@app.post("/api/login")
def login(data: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=data.email.lower()).first()
    if not user or not verify_password(data.password, user.password_hash): raise HTTPException(401, "Email atau password salah")
    return {"access_token":make_access_token(user.id), "token_type":"bearer", "email":user.email}

@app.post("/api/pair-codes")
def create_pair_code(user: User = Depends(current_user), db: Session = Depends(get_db)):
    code = str(secrets.randbelow(900000) + 100000)
    row = PairCode(user_id=user.id, code=code, expires_at=datetime.now(timezone.utc)+timedelta(minutes=10))
    db.add(row); db.commit()
    return {"code":code, "expires_in_seconds":600, "instruction":"Masukkan kode ini di aplikasi Android milik Anda."}

@app.post("/api/pair")
def pair(data: PairIn, db: Session = Depends(get_db)):
    row = db.query(PairCode).filter_by(code=data.code, used=False).first()
    now = datetime.now(timezone.utc)
    if not row or row.expires_at.replace(tzinfo=timezone.utc) < now: raise HTTPException(400, "Kode pairing salah atau kedaluwarsa")
    token = new_device_token()
    device = Device(user_id=row.user_id, name=data.device_name[:100], device_token_hash=token_hash(token))
    row.used = True; db.add(device); db.commit(); db.refresh(device)
    return {"device_id":device.id, "device_token":token}

@app.post("/api/telemetry")
def telemetry(data: TelemetryIn, device: Device = Depends(current_device), db: Session = Depends(get_db)):
    device.battery = data.battery
    device.network = (data.network or "")[:80]
    if data.latitude is not None and data.longitude is not None:
        device.latitude, device.longitude = data.latitude, data.longitude
        device.location_at = datetime.now(timezone.utc)
    device.last_seen = datetime.now(timezone.utc)
    db.add(DeviceEvent(device_id=device.id, event_type="heartbeat", message="Status perangkat diperbarui"))
    db.commit()
    return {"ok":True}

@app.post("/api/activities")
def activity(data: ActivityIn, device: Device = Depends(current_device), db: Session = Depends(get_db)):
    db.add(Activity(device_id=device.id, package_name=data.package_name[:255], label=data.label[:255], duration_seconds=data.duration_seconds))
    device.last_seen = datetime.now(timezone.utc); db.commit()
    return {"ok":True}

@app.post("/api/events")
def event(data: EventIn, device: Device = Depends(current_device), db: Session = Depends(get_db)):
    db.add(DeviceEvent(device_id=device.id, event_type=data.event_type[:80], message=data.message[:1000]))
    device.last_seen = datetime.now(timezone.utc); db.commit()
    return {"ok":True}

@app.get("/api/dashboard")
def dashboard(user: User = Depends(current_user), db: Session = Depends(get_db)):
    devices = db.query(Device).filter_by(user_id=user.id, revoked=False).all()
    result=[]
    for d in devices:
        acts=db.query(Activity).filter_by(device_id=d.id).order_by(desc(Activity.recorded_at)).limit(100).all()
        events=db.query(DeviceEvent).filter_by(device_id=d.id).order_by(desc(DeviceEvent.created_at)).limit(50).all()
        result.append({
          "id":d.id,"name":d.name,"last_seen":d.last_seen.isoformat() if d.last_seen else None,
          "battery":d.battery,"network":d.network,"latitude":d.latitude,"longitude":d.longitude,
          "location_at":d.location_at.isoformat() if d.location_at else None,
          "activities":[{"package_name":a.package_name,"label":a.label,"duration_seconds":a.duration_seconds,"recorded_at":a.recorded_at.isoformat()} for a in acts],
          "events":[{"event_type":e.event_type,"message":e.message,"created_at":e.created_at.isoformat()} for e in events]
        })
    return {"devices":result}

@app.delete("/api/devices/{device_id}")
def revoke_device(device_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    d=db.query(Device).filter_by(id=device_id,user_id=user.id).first()
    if not d: raise HTTPException(404,"Perangkat tidak ditemukan")
    d.revoked=True; db.commit()
    return {"ok":True}
