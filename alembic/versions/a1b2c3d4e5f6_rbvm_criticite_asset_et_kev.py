"""RBVM : criticite des assets et drapeau KEV

Revision ID: a1b2c3d4e5f6
Revises: bf6cb0806e1d
Create Date: 2026-08-24 09:10:00.000000

Ajoute le contexte metier (criticite d'un asset) et le signal de menace KEV
(CISA Known Exploited Vulnerabilities), tous deux indispensables au score de
risque composite (Risk-Based Vulnerability Management).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'bf6cb0806e1d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # server_default : les lignes existantes recoivent une valeur sans NULL,
    # indispensable pour une colonne NOT NULL ajoutee a une table peuplee.
    op.add_column(
        'assets',
        sa.Column('criticality', sa.String(length=20), nullable=False,
                  server_default='medium'),
    )
    op.add_column(
        'findings',
        sa.Column('kev', sa.Boolean(), nullable=False, server_default='0'),
    )
    op.create_index(op.f('ix_findings_kev'), 'findings', ['kev'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_findings_kev'), table_name='findings')
    op.drop_column('findings', 'kev')
    op.drop_column('assets', 'criticality')
