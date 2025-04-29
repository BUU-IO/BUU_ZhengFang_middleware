from fastapi import FastAPI, Form
from concurrent.futures import ThreadPoolExecutor
import asyncio
from LOGIN import Account

app = FastAPI()
executor = ThreadPoolExecutor(max_workers=10)  # 根据服务器配置调整


@app.post("/zhengfang_login")
async def login_endpoint(
    username: str = Form(), password: str = Form(), identify: int = Form()
):
    """登录接口"""
    account = Account(name=username, password=password, identify=identify)

    try:
        # 在独立线程中执行同步IO操作
        loop = asyncio.get_event_loop()
        status_code = await loop.run_in_executor(executor, account.login)

        return {
            "status": "success" if status_code == 200 else "error",
            "code": status_code,
            "username": username,
            "name": account.name,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
