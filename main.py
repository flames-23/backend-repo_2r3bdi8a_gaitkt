import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from bson import ObjectId
import secrets
import hashlib
import hmac

from database import db, create_document
from schemas import Admin, Settings, Event, Photo, Subscriber, Message

# Simple PBKDF2 password hashing (bcrypt-equivalent strength)
PBKDF_ITERATIONS = 200_000


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF_ITERATIONS)
    return salt.hex() + ":" + dk.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split(":")
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
        test = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF_ITERATIONS)
        return hmac.compare_digest(expected, test)
    except Exception:
        return False


app = FastAPI(title="PixFlow 2025 API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static storage for uploads (in real prod you'd use S3)
UPLOAD_DIR = os.path.join(os.getcwd(), "uploads")
WATERMARKS_DIR = os.path.join(UPLOAD_DIR, "watermarks")
COVERS_DIR = os.path.join(UPLOAD_DIR, "covers")
PHOTOS_DIR = os.path.join(UPLOAD_DIR, "photos")
os.makedirs(WATERMARKS_DIR, exist_ok=True)
os.makedirs(COVERS_DIR, exist_ok=True)
os.makedirs(PHOTOS_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")


# Utility payloads
class LoginPayload(BaseModel):
    username: str
    password: str


class AdminSetupPayload(BaseModel):
    username: str
    email: str
    password: str


# Admin bootstrap: check if admin exists
@app.get("/api/admin/exists")
async def admin_exists():
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    exists = db["admin"].count_documents({}) > 0
    return {"exists": bool(exists)}


# Create initial single admin
@app.post("/api/admin/setup")
async def admin_setup(payload: AdminSetupPayload):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    if db["admin"].count_documents({}) > 0:
        raise HTTPException(status_code=400, detail="Admin already set up")
    hashed = hash_password(payload.password)
    admin = Admin(username=payload.username, email=payload.email, password_hash=hashed)
    _id = create_document("admin", admin)
    # Ensure default settings document exists
    if db["settings"].count_documents({}) == 0:
        default_settings = Settings()
        create_document("settings", default_settings)
    return {"ok": True, "id": _id}


# Login
@app.post("/api/admin/login")
async def admin_login(payload: LoginPayload):
    doc = db["admin"].find_one({"username": payload.username})
    if not doc or not verify_password(payload.password, doc.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"ok": True}


# Password reset using DB-backed token (15 min expiry)
@app.post("/api/admin/request-reset")
async def request_reset(email: str = Form(...)):
    doc = db["admin"].find_one({"email": email})
    if not doc:
        raise HTTPException(status_code=404, detail="Admin not found")
    token = secrets.token_urlsafe(24)
    db["reset_token"].insert_one({
        "email": email,
        "token": token,
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=15),
        "used": False,
    })
    # In production, email this link. For demo, return it.
    return {"reset_link": f"/reset?token={token}"}


@app.post("/api/admin/reset-password")
async def reset_password(token: str = Form(...), new_password: str = Form(...)):
    rec = db["reset_token"].find_one({"token": token, "used": False})
    if not rec:
        raise HTTPException(status_code=400, detail="Invalid token")
    if rec.get("expires_at") <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Token expired")
    hashed = hash_password(new_password)
    db["admin"].update_one({"email": rec["email"]}, {"$set": {"password_hash": hashed}})
    db["reset_token"].update_one({"_id": rec["_id"]}, {"$set": {"used": True}})
    return {"ok": True}


# Settings get/update
@app.get("/api/settings")
async def get_settings():
    s = db["settings"].find_one({})
    if not s:
        from schemas import Settings as SettingsModel
        s_obj = SettingsModel()
        create_document("settings", s_obj)
        s = db["settings"].find_one({})
    s["_id"] = str(s["_id"])
    return s


@app.post("/api/settings/monetization")
async def update_monetization(
    payments_enabled: bool = Form(...),
    price_per_photo: float = Form(...),
    revolut_id: Optional[str] = Form(None),
    ads_enabled: Optional[bool] = Form(None),
):
    s = db["settings"].find_one({}) or {}
    monetization = s.get("monetization", {})
    monetization.update({
        "payments_enabled": payments_enabled,
        "price_per_photo": price_per_photo,
        "revolut_id": revolut_id,
    })
    if ads_enabled is not None:
        ads = s.get("ads", {})
        ads.update({"enabled": ads_enabled})
        s["ads"] = ads
    s["monetization"] = monetization
    db["settings"].update_one({}, {"$set": s}, upsert=True)
    return {"ok": True}


@app.post("/api/settings/watermark")
async def update_watermark(
    enabled: bool = Form(...),
    opacity: int = Form(...),
    position: str = Form(...),
):
    s = db["settings"].find_one({}) or {}
    wm = s.get("watermark", {})
    wm.update({"enabled": enabled, "opacity": opacity, "position": position})
    s["watermark"] = wm
    db["settings"].update_one({}, {"$set": s}, upsert=True)
    return {"ok": True}


@app.post("/api/settings/background")
async def update_background(preset: Optional[str] = Form(None), blur: Optional[int] = Form(None)):
    s = db["settings"].find_one({}) or {}
    bg = s.get("background", {})
    if preset:
        bg.update({"preset": preset})
    if blur is not None:
        bg.update({"blur": blur})
    s["background"] = bg
    db["settings"].update_one({}, {"$set": s}, upsert=True)
    return {"ok": True}


# Event and photo management
@app.post("/api/events")
async def create_event(
    title: str = Form(...),
    description: Optional[str] = Form(None),
    date: str = Form(...),
    timer_days: int = Form(15),
    cover: UploadFile = File(...),
):
    # Save cover
    cover_name = f"cover_{int(datetime.now().timestamp())}_{cover.filename}"
    cover_path = os.path.join(COVERS_DIR, cover_name)
    with open(cover_path, "wb") as f:
        f.write(await cover.read())
    date_dt = datetime.fromisoformat(date)
    expires_at = date_dt.replace(tzinfo=timezone.utc) + timedelta(days=timer_days)
    ev = Event(
        title=title,
        description=description,
        date=date_dt,
        cover_url=f"/uploads/covers/{cover_name}",
        expires_at=expires_at,
    )
    ev_id = create_document("event", ev)
    return {"ok": True, "event_id": ev_id}


@app.get("/api/events")
async def list_events():
    now = datetime.now(timezone.utc)
    events = list(db["event"].find({"expires_at": {"$gt": now}}).sort("date", -1))
    for e in events:
        e["_id"] = str(e["_id"])
    return events


@app.get("/api/events/{event_id}")
async def get_event(event_id: str):
    doc = db["event"].find_one({"_id": ObjectId(event_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Event not found")
    doc["_id"] = str(doc["_id"])
    return doc


@app.post("/api/events/{event_id}/photos")
async def upload_photos(event_id: str, files: List[UploadFile] = File(...)):
    # Retrieve settings for watermark behavior
    s = db["settings"].find_one({}) or {}
    wm = (s.get("watermark") or {})
    monet = (s.get("monetization") or {})
    enabled = wm.get("enabled", True)
    soft_mode = wm.get("soft_gift_mode", False) or not monet.get("payments_enabled", False)
    opacity = 15 if soft_mode else wm.get("opacity", 35)

    watermarked_records = []

    # Load watermark logo if provided, else skip watermarking
    logo_path = None
    logo_url = wm.get("logo_url")
    if logo_url and logo_url.startswith("/uploads/"):
        logo_path = os.path.join(os.getcwd(), logo_url.lstrip("/"))

    for file in files:
        # Save original
        name = f"ph_{int(datetime.now().timestamp())}_{file.filename}"
        original_path = os.path.join(PHOTOS_DIR, name)
        with open(original_path, "wb") as f:
            f.write(await file.read())

        watermarked_path = original_path
        if enabled and logo_path:
            try:
                from PIL import Image, ImageEnhance  # lazy import to avoid startup failure if pillow missing
                base = Image.open(original_path).convert("RGBA")
                logo = Image.open(logo_path).convert("RGBA")
                # Adaptive size ~7% width
                w = max(1, int(base.width * 0.07))
                ratio = w / logo.width
                logo = logo.resize((w, int(logo.height * ratio)))
                # Apply opacity
                alpha = logo.split()[3]
                enhancer = ImageEnhance.Brightness(alpha)
                logo.putalpha(enhancer.enhance(opacity / 100))
                # Position
                margin = max(10, base.width // 100)
                positions = {
                    "top-left": (margin, margin),
                    "top-right": (base.width - logo.width - margin, margin),
                    "bottom-left": (margin, base.height - logo.height - margin),
                    "bottom-right": (base.width - logo.width - margin, base.height - logo.height - margin),
                }
                pos = positions.get(wm.get("position", "bottom-right"), positions["bottom-right"])
                composed = base.copy()
                composed.alpha_composite(logo, dest=pos)
                watermarked_name = f"wm_{name}"
                watermarked_path = os.path.join(PHOTOS_DIR, watermarked_name)
                composed.convert("RGB").save(watermarked_path, format="JPEG", quality=90)
            except Exception:
                watermarked_path = original_path
        rec = Photo(
            event_id=event_id,
            original_url=f"/uploads/photos/{name}",
            watermarked_url=f"/uploads/photos/{os.path.basename(watermarked_path)}",
        )
        create_document("photo", rec)
        watermarked_records.append({"original_url": rec.original_url, "watermarked_url": rec.watermarked_url})

    return {"ok": True, "count": len(watermarked_records), "photos": watermarked_records}


@app.get("/api/events/{event_id}/photos")
async def get_event_photos(event_id: str):
    photos = list(db["photo"].find({"event_id": event_id}))
    for p in photos:
        p["_id"] = str(p["_id"])
    return photos


@app.get("/")
async def root():
    return {"message": "PixFlow 2025 API running"}


# Diagnostics
@app.get("/test")
async def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": [],
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            collections = db.list_collection_names()
            response["collections"] = collections[:10]
            response["database"] = "✅ Connected & Working"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
