"""initial schema

Revision ID: 001
Revises:
Create Date: 2026-03-26
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("platform", sa.String(32), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("source_type", sa.String(64), nullable=True),
        sa.Column("event_id", sa.String(64), nullable=True),
        sa.Column("event_type", sa.String(128), nullable=True),
        sa.Column("username", sa.String(255), nullable=True),
        sa.Column("source_ip", sa.String(64), nullable=True),
        sa.Column("destination_ip", sa.String(64), nullable=True),
        sa.Column("process_name", sa.String(512), nullable=True),
        sa.Column("process_id", sa.Integer(), nullable=True),
        sa.Column("logon_type", sa.String(32), nullable=True),
        sa.Column("authentication_result", sa.String(32), nullable=True),
        sa.Column("severity", sa.String(32), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("raw_event", sa.Text(), nullable=True),
        sa.Column("event_fingerprint", sa.String(64), nullable=False),
        sa.Column("parse_errors", postgresql.JSONB(), nullable=False),
        sa.Column("extra", postgresql.JSONB(), nullable=False),
        sa.UniqueConstraint("event_fingerprint", name="uq_event_fingerprint"),
    )
    op.create_index("ix_events_timestamp", "events", ["timestamp"])
    op.create_index("ix_events_platform", "events", ["platform"])
    op.create_index("ix_events_event_id", "events", ["event_id"])
    op.create_index("ix_events_username", "events", ["username"])
    op.create_index("ix_events_source_ip", "events", ["source_ip"])

    op.create_table(
        "ingestions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("filename", sa.String(512), nullable=False),
        sa.Column("platform", sa.String(32), nullable=False),
        sa.Column("source_format", sa.String(64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("imported_count", sa.Integer(), nullable=False),
        sa.Column("skipped_count", sa.Integer(), nullable=False),
        sa.Column("error_count", sa.Integer(), nullable=False),
        sa.Column("errors_sample", postgresql.JSONB(), nullable=False),
    )

    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("platform", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("mitre_attack", postgresql.JSONB(), nullable=False),
        sa.Column("false_positive_notes", postgresql.JSONB(), nullable=False),
        sa.Column("recommendations", postgresql.JSONB(), nullable=False),
        sa.Column("event_ids", postgresql.JSONB(), nullable=False),
        sa.Column("hosts", postgresql.JSONB(), nullable=False),
        sa.Column("users", postgresql.JSONB(), nullable=False),
        sa.Column("source_ips", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("metadata", postgresql.JSONB(), nullable=False),
    )
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_status", "alerts", ["status"])

    op.create_table(
        "cases",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("alert_ids", postgresql.JSONB(), nullable=False),
        sa.Column("event_ids", postgresql.JSONB(), nullable=False),
    )

    op.create_table(
        "rule_stats",
        sa.Column("rule_id", sa.String(128), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("trigger_count", sa.Integer(), nullable=False),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("rule_stats")
    op.drop_table("cases")
    op.drop_table("alerts")
    op.drop_table("ingestions")
    op.drop_table("events")
