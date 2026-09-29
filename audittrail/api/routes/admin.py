from audittrail.api.deps import DbSession
from audittrail.services.api_keys import generate_api_key
from fastapi import APIRouter

router = APIRouter(prefix="/v1/admin", tags=["admin"])


@router.post("/api-keys")
def create_api_key(name: str, db: DbSession) -> dict[str, str]:
    """Bootstrap endpoint — protect in production (e.g. internal network only)."""
    raw, record = generate_api_key(db, name)
    return {
        "id": str(record.id),
        "name": record.name,
        "api_key": raw,
        "prefix": record.key_prefix,
    }
