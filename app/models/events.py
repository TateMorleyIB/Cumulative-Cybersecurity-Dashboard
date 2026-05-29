from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class SecurityEvent(BaseModel):
    """
    Normalized security event model shared by dashboard integrations.

    Attributes:
        platform: Source platform that produced the event.
        event_type: Vendor-specific or normalized event type.
        severity: Human-readable severity label.
        risk_score: Numeric score for prioritization.
        source_entity: Optional source entity involved in the event.
        user: Optional user associated with the event.
        device: Optional device associated with the event.
        timestamp: Event occurrence time.
        raw_data: Original source payload retained for troubleshooting.
    """

    platform: str
    event_type: str
    severity: str
    risk_score: int

    source_entity: Optional[str] = None
    user: Optional[str] = None
    device: Optional[str] = None

    timestamp: datetime
    raw_data: dict
