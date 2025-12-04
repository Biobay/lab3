from . import db
from .models import SecurityEvent
from typing import Optional


def log_security_event(
    event_type: str,
    user_id: Optional[int] = None,
    message: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
):
    ev = SecurityEvent(
        user_id=user_id,
        event_type=event_type,
        message=message,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.session.add(ev)
    # caller should commit when appropriate to batch with other writes
    return ev
