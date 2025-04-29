# -*- coding: UTF-8 -*-
import binascii
import time
import os
import tempfile
import uuid
import OCR_CODE
from bs4 import BeautifulSoup
import requests
import rsa


class BUU:
    DOMAIN = "jwxt.buu.edu.cn"
    MainURL = "https://jwxt.buu.edu.cn/default2.aspx"
    InitHeader = {
        "Host": "jwxt.buu.edu.cn",
        "Connection": "keep-alive",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 NetType/WIFI MicroMessenger/7.0.20.1781(0x6700143B) WindowsWechat(0x63090c11) XWEB/11581 Flue",
    }
    CheckCodeURL = "https://jwxt.buu.edu.cn/"
    CheckCodeHeader = ""
    PlanCourageURL = "https://jwxt.buu.edu.cn/xsxk.aspx"
    xsmain = "https://jwxt.buu.edu.cn/xs_main.aspx?xh="
    GetCodeKeyURL = "https://jwxt.buu.edu.cn/ajaxRequest/Handler1.ashx"


# Account为登录用的账户
class Account:
    def __init__(self, name=None, password=None, identify=0):
        identify_list = ["部门", "教师", "学生"]
        self.session = requests.Session()
        self.soup = None
        self.POSTDate = {
            "__LASTFOCUS": "",
            "__VIEWSTATE": "随机码",
            "__VIEWSTATEGENERATOR": "9BD98A7D",
            "__EVENTTARGET": "",
            "__EVENTARGUMENT": "",
            "txtUserName": "",
            "TextBox2": "",
            "txtSecretCode": "-1",
            "RadioButtonList1": identify_list[identify],
            "Button1": "登录",
            "txtKeyExponent": "010001",
            "txtKeyModulus": "随机码",
        }
        self.username = name
        self.password = password
        self.POSTDate["txtUserName"] = name
        self.POSTDate["TextBox2"] = password
        self.name = ""

    def __refresh_code(self):
        imgs = self.soup.find_all("img")
        useimg = ""
        for img in imgs:
            if img.get("id") == "icode":
                useimg = img.get("src")
        # 联大的登录需要带header和cookies
        image_response = self.session.get(
            BUU.CheckCodeURL + useimg,
            cookies=self.session.cookies.get_dict(),
            headers=BUU.InitHeader,
            stream=True,
        )
        image = image_response.content
        img_dir = tempfile.gettempdir()  # 获取系统临时目录
        filename = f"code_{uuid.uuid4()}.jpg"  # 生成唯一文件名
        img_path = os.path.join(img_dir, filename)
        try:
            with open(img_path, "wb") as code_jpg:
                code_jpg.write(image)
        except IOError:
            print(IOError)
        finally:
            return img_path  # 返回临时文件的完整路径

    def __get_check_code_ocr(self):
        img_path = self.__refresh_code()
        code = OCR_CODE.run(img_path, dir_now=os.getcwd())
        # 识别完成后删除临时文件
        try:
            os.remove(img_path)
        except Exception as e:
            print(f"Failed to delete temp file {img_path}: {e}")
        self.POSTDate["txtSecretCode"] = code

    # 登录进入主页
    def login(self, max_retries=5):
        for try_time in range(max_retries):
            # 获取初始页面
            init_response = self.session.get(BUU.MainURL, headers=BUU.InitHeader)
            if not init_response.ok:
                continue
            self.soup = BeautifulSoup(init_response.text, "lxml")

            # 更新动态参数
            self.POSTDate["__VIEWSTATE"] = self.soup.find(
                "input", {"name": "__VIEWSTATE"}
            )["value"]
            self.POSTDate["txtKeyModulus"] = self.soup.find(
                "input", {"name": "txtKeyModulus"}
            )["value"]

            # 加密密码
            exponent = int(self.POSTDate["txtKeyExponent"], 16)
            modulus = int(self.POSTDate["txtKeyModulus"], 16)
            rsa_pubkey = rsa.PublicKey(modulus, exponent)
            encrypted_pass = rsa.encrypt(self.password.encode(), rsa_pubkey)
            self.POSTDate["TextBox2"] = binascii.b2a_hex(encrypted_pass).decode()

            # 获取新验证码
            self.__get_check_code_ocr()

            # 发送登录请求
            self.session.post(BUU.MainURL, data=self.POSTDate, headers=BUU.InitHeader)

            # 验证登录结果
            check_response = self.session.get(
                BUU.xsmain + self.username, headers=BUU.InitHeader
            )
            check_soup = BeautifulSoup(check_response.text, "lxml")
            if check_soup.find("title").text == "正方教务管理系统":
                self.name = check_soup.find("span", id="xhxm").text[:-2]
                print(time.strftime("%Y-%m-%d %H:%M:%S ") + self.name + "登录成功！")
                return 200
            print(f"登录失败，正在重试（{try_time + 1}/{max_retries}）...")
            time.sleep(1)  # 避免频繁请求

        return 402


class Encrypt(object):
    def __init__(self, e, m):
        self.e = e
        self.m = m

    def encrypt(self, message):
        mm = int(self.m, 16)
        ee = int(self.e, 16)
        rsa_pubkey = rsa.PublicKey(mm, ee)
        crypto = self._encrypt(message.encode(), rsa_pubkey)
        return crypto.hex()

    def _pad_for_encryption(self, message, target_length):
        message = message[::-1]
        msglength = len(message)

        padding = b""
        padding_length = target_length - msglength - 3

        for i in range(padding_length):
            padding += b"\x00"

        return b"".join([b"\x00\x00", padding, b"\x00", message])

    def _encrypt(self, message, pub_key):
        keylength = rsa.common.byte_size(pub_key.n)
        padded = self._pad_for_encryption(message, keylength)

        payload = rsa.transform.bytes2int(padded)
        encrypted = rsa.core.encrypt_int(payload, pub_key.e, pub_key.n)
        block = rsa.transform.int2bytes(encrypted, keylength)

        return block


if __name__ == "__main__":
    account = Account()
    account.login()
