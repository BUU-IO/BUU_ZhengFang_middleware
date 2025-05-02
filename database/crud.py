from sqlalchemy.orm import Session
from .models import Client, AuthorizationCode, Token
from datetime import datetime, timedelta
from passlib.context import CryptContext
import secrets


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class ClientService:
    @staticmethod
    def verify_client(db: Session, client_id: str, redirect_uri: str):
        client = db.query(Client).filter(Client.client_id == client_id).first()
        if not client:
            return False
        return redirect_uri in client.redirect_uris


class AuthCodeService:
    @staticmethod
    def create_code(db: Session, client_id: str, user_id: str, redirect_uri: str):
        code = secrets.token_urlsafe(64)
        expires_at = datetime.utcnow() + timedelta(minutes=5)
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
        return (
            db.query(AuthorizationCode)
            .filter(
                AuthorizationCode.code == code,
                AuthorizationCode.expires_at > datetime.utcnow(),
                AuthorizationCode.used == False,
            )
            .first()
        )


class TokenService:
    @staticmethod
    def create_token(
        db: Session, user_id: str, client_id: str, expires_minutes: int = 30
    ):
        access_token = secrets.token_urlsafe(128)
        refresh_token = secrets.token_urlsafe(128)
        expires_at = datetime.utcnow() + timedelta(minutes=expires_minutes)

        token = Token(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at,
            user_id=user_id,
            client_id=client_id,
        )
        db.add(token)
        db.commit()
        return token
