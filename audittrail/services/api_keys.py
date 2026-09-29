"""API key generation and verification."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime

from audittrail.config import get_settings
from audittrail.models.api_key import ApiKey
from sqlalchemy.orm import Session


def _hash_key(raw_key: str) -> str:
    pepper = get_settings().api_key_pepper
    return hashlib.sha256(f"{pepper}:{raw_key}".encode()).hexdigest()


def generate_api_key(db: Session, name: str) -> tuple[str, ApiKey]:
    raw = f"at_{secrets.token_urlsafe(32)}"
    prefix = raw[:8]
    record = ApiKey(name=name, key_hash=_hash_key(raw), key_prefix=prefix)
    db.add(record)
    db.commit()
    db.refresh(record)
    return raw, record


def verify_api_key(db: Session, raw_key: str | None) -> ApiKey | None:
    if not raw_key or not raw_key.startswith("at_"):
        return None
    h = _hash_key(raw_key)
    record = db.query(ApiKey).filter(ApiKey.key_hash == h).first()
    if record:
        record.last_used_at = datetime.now(UTC)
        db.commit()
    return record
