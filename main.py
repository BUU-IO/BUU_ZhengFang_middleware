from fastapi import FastAPI, Request, Depends, HTTPException, status, Form
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2AuthorizationCodeBearer
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from datetime import datetime, timedelta
from LOGIN import Account
from typing import Optional
from concurrent.futures import ThreadPoolExecutor
from .database.database import get_db
from .database.crud import ClientService, AuthCodeService, TokenService
import asyncio
import secrets


# 应用初始化
app = FastAPI()
executor = ThreadPoolExecutor(max_workers=10)

# 会话中间件
app.add_middleware(SessionMiddleware, secret_key="your-secret-key-here")

# OAuth2 配置
OAUTH2_SCHEME = OAuth2AuthorizationCodeBearer(
    authorizationUrl="/authorize",
    tokenUrl="/token",
)

# JWT 配置
SECRET_KEY = "your-jwt-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# 存储授权码和状态（生产环境应使用持久化存储）
authorization_codes = {}


# 辅助函数：生成CSRF令牌
def generate_csrf_token():
    return secrets.token_urlsafe(32)


# 辅助函数
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# 登录页
@app.get("/login")
async def login_page(
    request: Request, client_id: str, redirect_uri: str, state: Optional[str] = None
):
    return {"message": "请提交登录表单", "client_id": client_id}


# 登录处理
@app.post("/login")
async def handle_login(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    state: Optional[str] = Form(None),
    identify: str = Form(...),
    csrf_token: str = Form(...),
):
    # 验证会话中的授权参数
    auth_params = request.session.get("auth_params")
    if not auth_params:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "未授权的访问")

    # 验证CSRF令牌
    session_csrf = request.session.get("csrf_token")
    if not secrets.compare_digest(csrf_token, session_csrf):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF令牌验证失败")

    # 清除已使用的CSRF令牌
    del request.session["csrf_token"]
    # 异步执行同步登录验证
    loop = asyncio.get_event_loop()
    account = Account(username, password, identify)
    status_code = await loop.run_in_executor(executor, account.login)

    if status_code != 200:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "登录失败")

    # 生成授权码
    auth_code = secrets.token_urlsafe(32)
    authorization_codes[auth_code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "user": username,
        "expires": datetime.utcnow() + timedelta(minutes=5),
    }

    # 构造重定向URL
    params = f"code={auth_code}&state={state}" if state else f"code={auth_code}"
    return RedirectResponse(f"{redirect_uri}?{params}")


# 授权端点
@app.get("/authorize")
async def authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    db: Session = Depends(get_db),
):
    # 验证客户端
    if not ClientService.verify_client(db, client_id, redirect_uri):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "无效客户端")

    # 存储会话参数
    request.session["auth_params"] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
    }
    return RedirectResponse("/login")


@app.post("/token")
async def get_token(code: str = Form(...), db: Session = Depends(get_db)):
    # 验证授权码
    auth_code = AuthCodeService.validate_code(db, code)
    if not auth_code:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "无效授权码")

    # 标记授权码已使用
    auth_code.used = True
    db.commit()

    # 生成访问令牌
    token = TokenService.create_token(
        db, user_id=auth_code.user_id, client_id=auth_code.client_id
    )

    return {
        "access_token": token.access_token,
        "refresh_token": token.refresh_token,
        "expires_in": 3600,
    }
