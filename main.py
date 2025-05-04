from fastapi import FastAPI, Request, Depends, HTTPException, status, Form
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.security import OAuth2AuthorizationCodeBearer
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from jose import jwt, JWTError, ExpiredSignatureError
from datetime import datetime, timedelta, timezone
from LOGIN import Account
from typing import Optional
from concurrent.futures import ThreadPoolExecutor
from database.database import get_db
from database.crud import ClientService, AuthCodeService
import asyncio
import secrets
import json


# 应用初始化
app = FastAPI()
executor = ThreadPoolExecutor(max_workers=10)
key_json = json.load(open("config.json", "r", encoding="utf-8"))

# 会话中间件
app.add_middleware(SessionMiddleware, secret_key=key_json["secret_key"])

# OAuth2 配置
OAUTH2_SCHEME = OAuth2AuthorizationCodeBearer(
    authorizationUrl="/authorize",
    tokenUrl="/token",
)   

# JWT 配置
SECRET_KEY = key_json["jwt_key"]
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# 生成CSRF令牌
def generate_csrf_token():
    return secrets.token_urlsafe(32)


# 创建一个access_token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# 登录处理
@app.post("/login")
async def handle_login(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    identify: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),  # 注入数据库会话
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
    # 将实际登录账号存储在会话
    request.session["authenticated_user"] = username

    # 生成并存储授权码到数据库
    auth_code = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    AuthCodeService.create_code(
        db,
        code=auth_code,
        client_id=client_id,
        redirect_uri=redirect_uri,
        user_account=username,  # 新增字段存储实际账号
        expires_at=expires_at,
    )

    # 构造重定向URL
    redirect_url = auth_params["redirect_uri"]
    params = []
    if auth_code:
        params.append(f"code={auth_code}")
    if auth_params["state"]:
        params.append(f"state={auth_params['state']}")

    # 清理会话
    del request.session["auth_params"]
    del request.session["csrf_token"]

    return RedirectResponse(
        url=f"{redirect_url}?{'&'.join(params)}", status_code=status.HTTP_303_SEE_OTHER
    )


# 授权端点
@app.get("/authorize")
async def authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    state: Optional[str] = None,
    db: Session = Depends(get_db),
):
    # 验证客户端
    if not ClientService.verify_client(db, client_id, redirect_uri):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "无效客户端")

    # 生成并存储CSRF令牌
    csrf_token = secrets.token_urlsafe(32)
    request.session["auth_params"] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
    }
    request.session["csrf_token"] = csrf_token

    # 重定向到Next.js登录页面
    return RedirectResponse(url="/login")


@app.get("/auth/params")
async def get_auth_params(request: Request):
    """给前端获取授权参数的端点"""
    auth_params = request.session.get("auth_params")
    csrf_token = request.session.get("csrf_token")

    if not auth_params or not csrf_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="会话无效或已过期"
        )

    return JSONResponse(
        {
            "client_id": auth_params["client_id"],
            "redirect_uri": auth_params["redirect_uri"],
            "state": auth_params["state"],
            "csrf_token": csrf_token,
        }
    )


@app.post("/token")
async def get_token(code: str = Form(...), db: Session = Depends(get_db)):
    # 验证授权码
    auth_code = AuthCodeService.validate_code(db, code)
    if not auth_code:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "无效授权码")

    # 生成JWT访问令牌
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": auth_code.user_account},  # 从授权码获取实际用户账号
        expires_delta=access_token_expires,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": access_token_expires.seconds,
    }


@app.get("/user_info")
async def get_user_info(token: str = Depends(OAUTH2_SCHEME)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无效的访问令牌",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # 解码JWT令牌
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "令牌已过期")
    except JWTError:
        raise credentials_exception

    return {"username": username}
