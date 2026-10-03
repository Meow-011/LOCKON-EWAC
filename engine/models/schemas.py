"""LOCKON EWAC — Pydantic Data Models"""
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
from typing import Optional


class MissionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    SYNCED = "SYNCED"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AccessPointData(BaseModel):
    """Represents a discovered WiFi access point"""
    bssid: str
    ssid: Optional[str] = None
    vendor: Optional[str] = None
    encryption: str = "UNKNOWN"
    cipher: Optional[str] = None
    auth_type: Optional[str] = None
    is_vulnerable: bool = False
    channel: Optional[int] = None


class ScanLogData(BaseModel):
    """Represents a single scan/sniff observation"""
    bssid: str
    rssi: int
    channel: Optional[int] = None
    frequency: Optional[int] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude: Optional[float] = None
    speed: Optional[float] = None
    hdop: Optional[float] = None
    satellites: Optional[int] = None
    timestamp: datetime = Field(default_factory=datetime.now)


class GPSFix(BaseModel):
    """Represents a GPS position fix"""
    latitude: float
    longitude: float
    altitude: Optional[float] = None
    speed: Optional[float] = None
    heading: Optional[float] = None
    hdop: Optional[float] = None
    satellites: int = 0
    fix_quality: int = 0
    timestamp: datetime = Field(default_factory=datetime.now)


class EngineStatusData(BaseModel):
    """Current engine status"""
    scanning: bool = False
    gps_locked: bool = False
    wifi_ready: bool = False
    total_aps: int = 0
    mission_id: Optional[str] = None
