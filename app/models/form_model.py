import uuid
from sqlalchemy import Column, String, Text, DateTime, func, ForeignKey, JSON
from app.config.database_config import Base


class Form(Base):
    __tablename__ = "forms"

    form_id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        unique=True,
    )

    user_id = Column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name = Column(String(255), nullable=False)
    desc = Column(Text, nullable=True)
    form = Column(JSON, nullable=False)

    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )
