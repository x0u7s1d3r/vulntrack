"""cache explication IA sur les findings (etape 19)

Revision ID: c4e8a1f20b93
Revises: b7d3f9c14a20
Create Date: 2026-09-07
"""
from alembic import op
import sqlalchemy as sa

# identifiants de revision Alembic
revision = "c4e8a1f20b93"
down_revision = "b7d3f9c14a20"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "findings",
        sa.Column("ai_explanation", sa.Text(), nullable=True),
    )


def downgrade():
    op.drop_column("findings", "ai_explanation")
