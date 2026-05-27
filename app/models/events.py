from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class SecurityEvent(BaseModel):
    platform: str
    event_type: str
    severity: str
    risk_score: int


    source_entity: Optional[str] = None
    user: Optional[str] = None
    device: Optional[str] = None

    timestamp: datetime
    raw_data: dict