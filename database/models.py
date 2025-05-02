from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from .database import Base
import uuid
import datetime


def gen_uuid():
    return str(uuid.uuid4())


class Client(Base):
    __tablename__ = "clients"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(String(64), unique=True, nullable=False)
    client_secret = Column(String(256), nullable=False)
    redirect_uris = Column(String(1024), nullable=False)  # JSON数组存储
    is_confidential = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


class AuthorizationCode(Base):
    __tablename__ = "authorization_codes"

    code = Column(String(128), primary_key=True)
    client_id = Column(UUID, ForeignKey("clients.id"), nullable=False)
    user_id = Column(UUID, ForeignKey("users.id"), nullable=False)
    redirect_uri = Column(String(512), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    scope = Column(String(256))


class Token(Base):
    __tablename__ = "tokens"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    access_token = Column(String(512), unique=True, nullable=False)
    refresh_token = Column(String(512), unique=True)
    token_type = Column(String(32), default="bearer")
    expires_at = Column(DateTime, nullable=False)
    scope = Column(String(256))
    client_id = Column(UUID, ForeignKey("clients.id"), nullable=False)
    user_id = Column(UUID, ForeignKey("users.id"), nullable=False)
    revoked = Column(Boolean, default=False)
