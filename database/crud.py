from sqlalchemy.orm import Session
from .models import Client, AuthorizationCode
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
import secrets


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class ClientService:
    @staticmethod
    def verify_client(db: Session, client_id: str, redirect_uri: str):
        client = db.query(Client).filter(Client.client_id == client_id).first()
        if not client:
            return False
        return client.redirect_uris == redirect_uri


class AuthCodeService:
    @staticmethod
    def create_code(db: Session, client_id: str, user_id: str, redirect_uri: str):
        code = secrets.token_urlsafe(64)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            expires_at=expires_at,
        )
        db.add(auth_code)
        db.commit()
        return code

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
        return auth_code
