from pydantic import BaseModel, EmailStr, Field
from typing import Optional

class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class PairIn(BaseModel):
    code: str
    device_name: str = "Android device"

class TelemetryIn(BaseModel):
    battery: Optional[int] = Field(default=None, ge=0, le=100)
    network: Optional[str] = None
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)

class ActivityIn(BaseModel):
    package_name: str
    label: str = ""
    duration_seconds: int = Field(ge=0, le=86400)

class EventIn(BaseModel):
    event_type: str
    message: str
