"""Add URL-based (black-box) scan mode columns.

Written defensively rather than as plain ``op.add_column`` calls, because
0001 builds its schema from the *current* declarative metadata
(``Base.metadata.create_all``) rather than a frozen snapshot — see that
revision's docstring. That means a brand-new database already gets these
columns from 0001 alone, once they exist on the ORM models, while a database
that was migrated before this revision existed does not. Checking what is
already there before adding anything makes this revision correct in both
cases, and safe to apply more than once.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002_url_scan_mode"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def _existing_columns(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    return {col["name"] for col in inspector.get_columns(table_name)}


def upgrade() -> None:
    project_columns = _existing_columns("projects")
    with op.batch_alter_table("projects") as batch:
        if "scan_mode" not in project_columns:
            batch.add_column(
                sa.Column("scan_mode", sa.String(length=16), nullable=False, server_default="source")
            )
        if "target_authorized" not in project_columns:
            batch.add_column(
                sa.Column("target_authorized", sa.Boolean(), nullable=False, server_default=sa.false())
            )
        if "authorization_method" not in project_columns:
            batch.add_column(sa.Column("authorization_method", sa.String(length=32), nullable=True))
        if "authorization_token" not in project_columns:
            batch.add_column(sa.Column("authorization_token", sa.String(length=64), nullable=True))
        if "authorization_confirmed_at" not in project_columns:
            batch.add_column(
                sa.Column("authorization_confirmed_at", sa.DateTime(timezone=True), nullable=True)
            )
        if "scope_config" not in project_columns:
            batch.add_column(sa.Column("scope_config", postgresql.JSONB(), nullable=True))

    endpoint_columns = _existing_columns("endpoints")
    with op.batch_alter_table("endpoints") as batch:
        if "discovered_via" not in endpoint_columns:
            batch.add_column(
                sa.Column("discovered_via", sa.String(length=16), nullable=False, server_default="source")
            )


def downgrade() -> None:
    with op.batch_alter_table("endpoints") as batch:
        batch.drop_column("discovered_via")
    with op.batch_alter_table("projects") as batch:
        batch.drop_column("scope_config")
        batch.drop_column("authorization_confirmed_at")
        batch.drop_column("authorization_token")
        batch.drop_column("authorization_method")
        batch.drop_column("target_authorized")
        batch.drop_column("scan_mode")
