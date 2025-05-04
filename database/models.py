from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import UUID
from .database import Base
from datetime import datetime, timezone
import uuid


def gen_uuid():
    return str(uuid.uuid4())


class Client(Base):
    __tablename__ = "clients"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(String(64), unique=True, nullable=False)
    client_secret = Column(String(256), nullable=False)
    redirect_uris = Column(String(1024), nullable=False)
    is_confidential = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    identify = Column(String(64))
    created_at = Column(DateTime, default=datetime.now(timezone.utc))


class AuthorizationCode(Base):
    __tablename__ = "authorization_codes"

    code = Column(String(128), primary_key=True)
    client_id = Column(UUID, ForeignKey("clients.id"), nullable=False)
    redirect_uri = Column(String(512), nullable=False)
    user_account = Column(String(256), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    scope = Column(String(256))

    @staticmethod
    def create_code(
        db: Session,
        code: str,
        client_id: str,
        redirect_uri: str,
        expires_at: datetime,
    ):
        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            expires_at=expires_at,
        )
        db.add(auth_code)
        db.commit()
        db.refresh(auth_code)
        return auth_code

    @staticmethod
    def validate_code(db: Session, code: str):
        current_time = datetime.now(timezone.utc)
        auth_code = (
            db.query(AuthorizationCode)
            .filter(
                AuthorizationCode.code == code,
                AuthorizationCode.used == False,
                AuthorizationCode.expires_at > current_time,
            )
            .first()
        )
        if auth_code:
            auth_code.used = True
            db.commit()
            db.refresh(auth_code)
        return auth_code
