"""
PixFlow 2025 Database Schemas

Each Pydantic model below maps to a MongoDB collection using the lowercase
of the class name as the collection name.

- Admin          -> "admin"
- Settings       -> "settings"
- Event          -> "event"
- Photo          -> "photo"
- Subscriber     -> "subscriber"
- Message        -> "message"
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Literal
from datetime import datetime


class Admin(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    email: str = Field(...)
    password_hash: str = Field(..., description="BCrypt hash")
    created_at: Optional[datetime] = None


class WatermarkSettings(BaseModel):
    enabled: bool = True
    opacity: int = Field(35, ge=0, le=100)
    position: Literal["top-left", "top-right", "bottom-left", "bottom-right"] = "bottom-right"
    logo_url: Optional[str] = None
    soft_gift_mode: bool = False


class BackgroundSettings(BaseModel):
    preset: Literal["default", "night", "beach"] = "default"
    custom_url: Optional[str] = None
    blur: int = Field(10, ge=0, le=30)


class AdsSettings(BaseModel):
    enabled: bool = False
    placement: List[Literal["home", "event", "sidebar"]] = []
    asset_url: Optional[str] = None  # image or mp4


class MonetizationSettings(BaseModel):
    payments_enabled: bool = False
    price_per_photo: float = 2.99
    revolut_id: Optional[str] = None


class Settings(BaseModel):
    watermark: WatermarkSettings = WatermarkSettings()
    background: BackgroundSettings = BackgroundSettings()
    ads: AdsSettings = AdsSettings()
    monetization: MonetizationSettings = MonetizationSettings()


class Event(BaseModel):
    title: str
    description: Optional[str] = None
    date: datetime
    cover_url: str
    expires_at: datetime
    is_active: bool = True


class Photo(BaseModel):
    event_id: str
    original_url: str
    watermarked_url: str
    width: Optional[int] = None
    height: Optional[int] = None


class Subscriber(BaseModel):
    email: str


class Message(BaseModel):
    name: str
    email: str
    message: str
