"""Add scan owner for tenant isolation

Revision ID: 002
Revises: 001
Create Date: 2026-03-29

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("owner_api_key_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_scans_owner_api_key_id",
        "scans",
        "api_keys",
        ["owner_api_key_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_scans_owner_api_key_id", "scans", ["owner_api_key_id"])


def downgrade() -> None:
    op.drop_index("ix_scans_owner_api_key_id", table_name="scans")
    op.drop_constraint("fk_scans_owner_api_key_id", "scans", type_="foreignkey")
    op.drop_column("scans", "owner_api_key_id")
