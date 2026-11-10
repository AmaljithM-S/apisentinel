"""Initial APISentinel schema.

The initial revision is created from the declarative metadata rather than a
hand-transcribed column list. This guarantees the migrated schema and the ORM
models can never drift apart on a fresh install, which is the single most
common source of "works on my machine" database bugs. Subsequent revisions are
normal incremental Alembic operations.
"""

from alembic import op

from app.db.base import Base
from app.db import models  # noqa: F401  (registers metadata)

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
