from audittrail.api.deps import DbSession, require_bootstrap_admin
from audittrail.services.api_keys import generate_api_key
from fastapi import APIRouter, Depends

router = APIRouter(prefix="/v1/admin", tags=["admin"])


@router.post("/api-keys")
def create_api_key(
    name: str,
    db: DbSession,
    _: None = Depends(require_bootstrap_admin),
) -> dict[str, str]:
    raw, record = generate_api_key(db, name)
    return {
        "id": str(record.id),
        "name": record.name,
        "api_key": raw,
        "prefix": record.key_prefix,
    }
