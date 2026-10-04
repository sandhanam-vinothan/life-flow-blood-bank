"""LifeFlow - blood bank management API (FastAPI). Synthetic data only."""
import os, csv, io, hmac, hashlib, secrets, datetime as dt
import jwt
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session

DB = os.getenv("DATABASE_URL", "sqlite:///./lifeflow.db")
KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
engine = create_engine(DB, connect_args={"check_same_thread": False} if DB.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()
now = lambda: dt.datetime.utcnow()
GROUPS = ["A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"]
SHELF = {"red_cells": 35, "plasma": 365, "platelets": 5}  # shelf life in days
ROLES = ["admin", "staff", "hospital", "donor"]

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True); email = Column(String, unique=True, index=True)
    name = Column(String); pw = Column(String); role = Column(String); city = Column(String, default="")
    blood_group = Column(String, default=""); consent = Column(Boolean, default=False)
    active = Column(Boolean, default=True); approved = Column(Boolean, default=True)
    last_login = Column(DateTime); last_donation = Column(DateTime)
class Unit(Base):
    __tablename__ = "units"
    id = Column(Integer, primary_key=True); uid = Column(String, unique=True, index=True)
    group = Column(String, index=True); component = Column(String); donor_id = Column(Integer)
    status = Column(String, default="testing")  # testing|approved|reserved|issued|discarded|expired
    location = Column(String, default="Fridge-1"); collected = Column(DateTime, default=now)
    expiry = Column(DateTime); request_id = Column(Integer)
class Appt(Base):
    __tablename__ = "appts"
    id = Column(Integer, primary_key=True); donor_id = Column(Integer); centre = Column(String)
    slot = Column(DateTime); status = Column(String, default="booked")  # booked|cancelled|completed
class Req(Base):
    __tablename__ = "requests"
    id = Column(Integer, primary_key=True); hospital_id = Column(Integer); group = Column(String)
    component = Column(String); qty = Column(Integer); urgency = Column(String, default="routine")
    patient_ref = Column(String, default=""); status = Column(String, default="pending")
    created = Column(DateTime, default=now)
class Notif(Base):
    __tablename__ = "notifs"
    id = Column(Integer, primary_key=True); user_id = Column(Integer, index=True)
    msg = Column(String); created = Column(DateTime, default=now); read = Column(Boolean, default=False)
class Audit(Base):
    __tablename__ = "audit"
    id = Column(Integer, primary_key=True); user_id = Column(Integer); action = Column(String)
    detail = Column(String); at = Column(DateTime, default=now)

def hash_pw(p, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", p.encode(), salt.encode(), 200_000).hex()
def check_pw(p, h):
    return hmac.compare_digest(hash_pw(p, h.split("$")[0]), h)

app = FastAPI(title="LifeFlow")
oauth = OAuth2PasswordBearer(tokenUrl="/api/login")
def db():
    s = SessionLocal()
    try: yield s
    finally: s.close()
def log(s, uid, action, detail=""):
    s.add(Audit(user_id=uid, action=action, detail=detail)); s.commit()
def notify(s, uid, msg):
    s.add(Notif(user_id=uid, msg=msg)); s.commit()
def user(tok=Depends(oauth), s: Session = Depends(db)):
    try: uid = jwt.decode(tok, KEY, algorithms=["HS256"])["sub"]
    except Exception: raise HTTPException(401, "Session expired. Please log in again.")
    u = s.get(User, int(uid))
    if not u or not u.active: raise HTTPException(401, "Account inactive.")
    return u
def need(*roles):  # backend role-based permission
    def dep(u: User = Depends(user)):
        if u.role not in roles: raise HTTPException(403, "You do not have permission for this action.")
        return u
    return dep

class Reg(BaseModel):
    email: str; name: str; password: str; role: str = "donor"; city: str = ""
    blood_group: str = ""; consent: bool = False
class Login(BaseModel):
    email: str; password: str
class UnitIn(BaseModel):
    group: str; component: str; donor_id: int | None = None; location: str = "Fridge-1"
class ReqIn(BaseModel):
    group: str; component: str; qty: int; urgency: str = "routine"; patient_ref: str = ""
class ApptIn(BaseModel):
    centre: str; slot: dt.datetime

@app.post("/api/register")
def register(b: Reg, s: Session = Depends(db)):
    if b.role not in ("donor", "hospital", "staff"): raise HTTPException(400, "Invalid role.")
    if len(b.password) < 8: raise HTTPException(400, "Password must be at least 8 characters.")
    if s.query(User).filter_by(email=b.email.lower()).first(): raise HTTPException(400, "Email already registered.")
    u = User(email=b.email.lower(), name=b.name, pw=hash_pw(b.password), role=b.role, city=b.city,
             blood_group=b.blood_group, consent=b.consent, approved=(b.role == "donor"))
    s.add(u); s.commit(); log(s, u.id, "register", b.role)
    return {"ok": True, "message": "Registered." if u.approved else "Registered. An administrator must approve your organisation account."}

@app.post("/api/login")
def login(b: Login, s: Session = Depends(db)):
    u = s.query(User).filter_by(email=b.email.lower()).first()
    if not u or not check_pw(b.password, u.pw): raise HTTPException(401, "Incorrect email or password.")
    if not u.active or not u.approved: raise HTTPException(403, "Account is inactive or awaiting approval.")
    u.last_login = now(); s.commit(); log(s, u.id, "login")
    tok = jwt.encode({"sub": str(u.id), "exp": now() + dt.timedelta(hours=8)}, KEY, algorithm="HS256")
    return {"access_token": tok, "token_type": "bearer", "role": u.role, "name": u.name}

@app.get("/api/me")
def me(u: User = Depends(user)):
    return {"id": u.id, "name": u.name, "email": u.email, "role": u.role, "city": u.city, "blood_group": u.blood_group, "consent": u.consent}

# ---------- public ----------
@app.get("/api/public/availability")  # verified, in-date stock counts only (no donor data)
def availability(group: str = "", component: str = "", s: Session = Depends(db)):
    q = s.query(Unit.group, Unit.component, func.count()).filter(Unit.status == "approved", Unit.expiry > now())
    if group: q = q.filter(Unit.group == group)
    if component: q = q.filter(Unit.component == component)
    return [{"group": g, "component": c, "units": n} for g, c, n in q.group_by(Unit.group, Unit.component)]
@app.get("/api/public/centres")
def centres(city: str = "", s: Session = Depends(db)):
    q = s.query(User).filter(User.role == "staff", User.active == True, User.approved == True)
    if city: q = q.filter(User.city.ilike(f"%{city}%"))
    return [{"name": u.name, "city": u.city} for u in q]

# ---------- donor ----------
@app.post("/api/appointments")
def book(b: ApptIn, u: User = Depends(need("donor")), s: Session = Depends(db)):
    if b.slot < now(): raise HTTPException(400, "Choose a future time slot.")
    a = Appt(donor_id=u.id, centre=b.centre, slot=b.slot); s.add(a); s.commit()
    notify(s, u.id, f"Appointment confirmed at {b.centre} on {b.slot:%d %b %Y %H:%M}."); return {"id": a.id}
@app.get("/api/appointments")
def appts(u: User = Depends(user), s: Session = Depends(db)):
    q = s.query(Appt)
    if u.role == "donor": q = q.filter_by(donor_id=u.id)
    return [dict(id=a.id, donor_id=a.donor_id, centre=a.centre, slot=a.slot.isoformat(), status=a.status) for a in q.order_by(Appt.slot.desc())]
@app.post("/api/appointments/{aid}/{action}")
def appt_action(aid: int, action: str, u: User = Depends(user), s: Session = Depends(db)):
    a = s.get(Appt, aid)
    if not a or (u.role == "donor" and a.donor_id != u.id): raise HTTPException(404, "Appointment not found.")
    if action == "cancel": a.status = "cancelled"
    elif action == "complete" and u.role in ("staff", "admin"):
        a.status = "completed"; d = s.get(User, a.donor_id); d.last_donation = now()
    else: raise HTTPException(400, "Unsupported action.")
    s.commit(); log(s, u.id, f"appt_{action}", str(aid)); return {"ok": True}

# ---------- blood bank ----------
def unit_dict(x):
    return dict(id=x.id, uid=x.uid, group=x.group, component=x.component, status=x.status, location=x.location,
                collected=x.collected.isoformat(), expiry=x.expiry.isoformat(), expired=x.expiry < now())
@app.post("/api/units")
def collect(b: UnitIn, u: User = Depends(need("staff", "admin")), s: Session = Depends(db)):
    if b.group not in GROUPS or b.component not in SHELF: raise HTTPException(400, "Invalid blood group or component.")
    x = Unit(uid="LF-" + secrets.token_hex(4).upper(), group=b.group, component=b.component, donor_id=b.donor_id,
             location=b.location, expiry=now() + dt.timedelta(days=SHELF[b.component]))
    s.add(x); s.commit(); log(s, u.id, "collect", x.uid); return unit_dict(x)
@app.get("/api/units")
def units(status: str = "", u: User = Depends(need("staff", "admin")), s: Session = Depends(db)):
    q = s.query(Unit)
    if status: q = q.filter_by(status=status)
    return [unit_dict(x) for x in q.order_by(Unit.id.desc()).limit(300)]
@app.post("/api/units/{uid}/status/{new}")
def set_status(uid: str, new: str, u: User = Depends(need("staff")), s: Session = Depends(db)):
    x = s.query(Unit).filter_by(uid=uid).first()
    if not x: raise HTTPException(404, "Unit not found.")
    ok = {("testing", "approved"), ("testing", "discarded"), ("approved", "discarded"), ("reserved", "approved")}
    if (x.status, new) not in ok: raise HTTPException(400, f"Cannot move a unit from {x.status} to {new}.")
    x.status = new; s.commit(); log(s, u.id, "unit_status", f"{uid} -> {new}"); return unit_dict(x)
@app.get("/api/units/qr/{uid}")  # QR payload is just the opaque unit ID; no donor data exposed
def qr(uid: str, u: User = Depends(need("staff", "admin")), s: Session = Depends(db)):
    x = s.query(Unit).filter_by(uid=uid).first()
    if not x: raise HTTPException(404, "Unit not found.")
    trail = [dict(at=a.at.isoformat(), action=a.action, detail=a.detail) for a in s.query(Audit).filter(Audit.detail.like(f"%{uid}%"))]
    return {**unit_dict(x), "history": trail}

# ---------- hospital requests ----------
@app.post("/api/requests")
def create_req(b: ReqIn, u: User = Depends(need("hospital")), s: Session = Depends(db)):
    if b.group not in GROUPS or b.component not in SHELF or b.qty < 1: raise HTTPException(400, "Invalid request.")
    r = Req(hospital_id=u.id, group=b.group, component=b.component, qty=b.qty, urgency=b.urgency, patient_ref=b.patient_ref)
    s.add(r); s.commit(); log(s, u.id, "request", f"#{r.id} {b.urgency}")
    for st in s.query(User).filter_by(role="staff", active=True):
        notify(s, st.id, f"{b.urgency.upper()} request #{r.id}: {b.qty} x {b.group} {b.component}")
    if b.urgency == "emergency":  # only consenting, matching donors; contact details never shared
        for d in s.query(User).filter_by(role="donor", blood_group=b.group, consent=True, active=True):
            notify(s, d.id, f"Urgent need for {b.group} blood. If you are able and eligible, please book a donation.")
            # TODO: send email/SMS via provider here
    return {"id": r.id}
def req_dict(r, s):
    h = s.get(User, r.hospital_id)
    return dict(id=r.id, hospital=h.name if h else "", group=r.group, component=r.component, qty=r.qty,
                urgency=r.urgency, patient_ref=r.patient_ref, status=r.status, created=r.created.isoformat())
@app.get("/api/requests")
def reqs(u: User = Depends(need("hospital", "staff", "admin")), s: Session = Depends(db)):
    q = s.query(Req)
    if u.role == "hospital": q = q.filter_by(hospital_id=u.id)
    return [req_dict(r, s) for r in q.order_by(Req.id.desc()).limit(200)]
@app.post("/api/requests/{rid}/{action}")
def req_action(rid: int, action: str, u: User = Depends(need("staff")), s: Session = Depends(db)):
    r = s.get(Req, rid)
    if not r or r.status not in ("pending", "reserved"): raise HTTPException(400, "Request not found or already closed.")
    if action == "reject": r.status = "rejected"
    elif action == "reserve" and r.status == "pending":  # only tested+released, in-date units; oldest first
        free = s.query(Unit).filter(Unit.status == "approved", Unit.group == r.group, Unit.component == r.component,
                                    Unit.expiry > now()).order_by(Unit.expiry).limit(r.qty).with_for_update().all()
        if len(free) < r.qty: raise HTTPException(409, f"Only {len(free)} approved unit(s) available.")
        for x in free: x.status, x.request_id = "reserved", r.id
        r.status = "reserved"
    elif action == "issue" and r.status == "reserved":  # after clinical compatibility check by qualified staff
        for x in s.query(Unit).filter_by(request_id=r.id, status="reserved"): x.status = "issued"
        r.status = "issued"
    else: raise HTTPException(400, "Unsupported action.")
    s.commit(); log(s, u.id, f"request_{action}", f"#{rid}"); notify(s, r.hospital_id, f"Request #{rid} is now {r.status}.")
    return {"status": r.status}

# ---------- notifications, reports, admin ----------
@app.get("/api/notifications")
def notifs(u: User = Depends(user), s: Session = Depends(db)):
    return [dict(id=n.id, msg=n.msg, at=n.created.isoformat()) for n in s.query(Notif).filter_by(user_id=u.id).order_by(Notif.id.desc()).limit(50)]
@app.get("/api/reports/summary")
def summary(u: User = Depends(need("admin", "staff")), s: Session = Depends(db)):
    st = lambda *a: s.query(Unit).filter(Unit.status == "approved", Unit.expiry > now(), *a)
    stock = {g: st(Unit.group == g).count() for g in GROUPS}
    soon = st(Unit.expiry < now() + dt.timedelta(days=3)).count()
    return dict(donors=s.query(User).filter_by(role="donor").count(), hospitals=s.query(User).filter_by(role="hospital").count(),
                stock=stock, low=[g for g, n in stock.items() if n < 3], expiring_soon=soon,
                pending=s.query(Req).filter_by(status="pending").count(),
                emergencies=s.query(Req).filter(Req.urgency == "emergency", Req.status.in_(["pending", "reserved"])).count())
@app.get("/api/reports/inventory.csv")
def export(u: User = Depends(need("admin", "staff")), s: Session = Depends(db)):
    out = io.StringIO(); w = csv.writer(out); w.writerow(["uid", "group", "component", "status", "expiry"])
    for x in s.query(Unit): w.writerow([x.uid, x.group, x.component, x.status, x.expiry.date()])
    return StreamingResponse(iter([out.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=inventory.csv"})
@app.get("/api/users")
def users(u: User = Depends(need("admin")), s: Session = Depends(db)):
    return [dict(id=x.id, name=x.name, email=x.email, role=x.role, active=x.active, approved=x.approved,
                 last_login=x.last_login.isoformat() if x.last_login else "") for x in s.query(User)]
@app.post("/api/users/{uid}/{action}")
def user_action(uid: int, action: str, u: User = Depends(need("admin")), s: Session = Depends(db)):
    x = s.get(User, uid)
    if not x: raise HTTPException(404, "User not found.")
    if action == "approve": x.approved = True
    elif action == "toggle" and x.id != u.id: x.active = not x.active
    else: raise HTTPException(400, "Unsupported action.")
    s.commit(); log(s, u.id, f"user_{action}", str(uid)); return {"ok": True}
@app.get("/api/audit")
def audit(u: User = Depends(need("admin")), s: Session = Depends(db)):
    return [dict(at=a.at.isoformat(), user=a.user_id, action=a.action, detail=a.detail) for a in s.query(Audit).order_by(Audit.id.desc()).limit(200)]

def seed():
    Base.metadata.create_all(engine); s = SessionLocal()
    if s.query(User).count() == 0:
        for e, n, r, c, g in [("admin@lifeflow.test", "Admin", "admin", "Chennai", ""), ("staff@lifeflow.test", "City Blood Bank", "staff", "Chennai", ""),
                              ("hospital@lifeflow.test", "General Hospital", "hospital", "Chennai", ""), ("donor@lifeflow.test", "Asha Demo", "donor", "Chennai", "O+")]:
            s.add(User(email=e, name=n, pw=hash_pw("Passw0rd!"), role=r, city=c, blood_group=g, consent=(r == "donor")))
        s.commit()
        for i, g in enumerate(GROUPS * 2):
            s.add(Unit(uid=f"LF-DEMO{i:03d}", group=g, component="red_cells", status="approved", expiry=now() + dt.timedelta(days=5 + i * 3)))
        s.commit()
    s.close()
seed()
app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "..", "frontend"), html=True), name="ui")
