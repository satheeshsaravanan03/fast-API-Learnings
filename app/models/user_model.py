import uuid
from sqlalchemy import Column, String, Text, DateTime, func, Integer, Boolean
from app.config.database_config import Base
from app.constants.utils import ROLES
class User(Base):
    __tablename__ = "users"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        unique=True,
    )

    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False, unique=True, index=True)
    password = Column(String(255), nullable=True)  # Nullable - set after email verification
    country = Column(String(45), nullable=False)
    profile_url = Column(String(500), nullable=True)
    about = Column(Text, nullable=True)
    user_role = Column(Integer, nullable=False, default=ROLES.USER)

    # Email verification fields
    is_verified = Column(Boolean, nullable=False, default=False)

    # Temporary password fields
    is_temp_password = Column(Boolean, nullable=False, default=False)
    temp_password_created_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )