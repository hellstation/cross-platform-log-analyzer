"""add events.ingestion_id

Revision ID: 003
Revises: 002
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "events",
        sa.Column("ingestion_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_index("ix_events_ingestion_id", "events", ["ingestion_id"])


def downgrade() -> None:
    op.drop_index("ix_events_ingestion_id", table_name="events")
    op.drop_column("events", "ingestion_id")
