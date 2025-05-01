from fastapi import FastAPI, Form
import base64
from typing import Annotated
from concurrent.futures import ThreadPoolExecutor
import asyncio
from LOGIN import Account
from pydantic import BaseModel

app = FastAPI()
executor = ThreadPoolExecutor(max_workers=10)  # 根据服务器配置调整


class AuthForm(BaseModel):
    flowKey: str
    username: str
    password: str
    identify: str


@app.post("/login_auth")
async def login_endpoint(data: Annotated[AuthForm, Form()]):
    # 解密数据

    """登录接口"""
    account = Account(
        name=data.username, password=data.password, identify=data.identify
    )

    try:
        # 在独立线程中执行同步IO操作
        loop = asyncio.get_event_loop()
        status_code = await loop.run_in_executor(executor, account.login)

        return {
            "status": "success" if status_code == 200 else "error",
            "code": status_code,
            "username": data.username,
            "name": account.name,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
