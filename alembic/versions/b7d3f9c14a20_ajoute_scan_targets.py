"""ajoute la table scan_targets (auto-scan)

Revision ID: b7d3f9c14a20
Revises: a1b2c3d4e5f6
Create Date: 2026-09-01
"""
from alembic import op
import sqlalchemy as sa

# identifiants de revision Alembic
revision = "b7d3f9c14a20"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scan_targets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("target_type", sa.String(length=20), nullable=False),
        sa.Column("reference", sa.String(length=500), nullable=False),
        sa.Column("scanners", sa.String(length=200), nullable=False),
        sa.Column("schedule", sa.String(length=100), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default="1", nullable=False),
        sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=20), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name="uq_scan_targets_name"),
    )
    op.create_index(op.f("ix_scan_targets_id"), "scan_targets", ["id"], unique=False)


def downgrade():
    op.drop_index(op.f("ix_scan_targets_id"), table_name="scan_targets")
    op.drop_table("scan_targets")
