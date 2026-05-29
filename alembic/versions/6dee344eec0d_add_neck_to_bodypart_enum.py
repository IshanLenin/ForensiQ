"""add neck to bodypart enum

Revision ID: 6dee344eec0d
Revises: 7be43ddd6782
Create Date: 2026-03-23 21:41:06.577118

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6dee344eec0d'
down_revision: Union[str, Sequence[str], None] = '7be43ddd6782'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("ALTER TYPE bodypart ADD VALUE IF NOT EXISTS 'NECK';")


def downgrade() -> None:
    """Downgrade schema."""
    pass
