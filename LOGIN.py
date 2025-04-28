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
    def __init__(self, name=None, password=None):
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
            "RadioButtonList1": "学生",
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
                print(useimg)
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
        print("###Identify checkCode")
        code = OCR_CODE.run(img_path, dir_now=os.getcwd())
        # 识别完成后删除临时文件
        try:
            os.remove(img_path)
        except Exception as e:
            print(f"Failed to delete temp file {img_path}: {e}")
        self.POSTDate["txtSecretCode"] = code

    # 登录进入主页
    def login(self):
        print("#Begin to login")
        # print("##Get init page")
        while True:
            init_response = self.session.get(url=BUU.MainURL, headers=BUU.InitHeader)
            if init_response.ok:
                print("##GET login page succeed!")
                break
        self.soup = BeautifulSoup(init_response.text, "lxml")
        self.POSTDate["__VIEWSTATE"] = self.soup.find(
            "input", attrs={"name": "__VIEWSTATE"}
        )["value"]
        self.POSTDate["txtKeyModulus"] = self.soup.find(
            "input", attrs={"name": "txtKeyModulus"}
        )["value"]
        # print("###GET StateCode:", self.POSTDate["__VIEWSTATE"])  # 随机码
        # print("###GET txtKeyModulus:", self.POSTDate["txtKeyModulus"])  # KeyModulus
        # print("###GET checkCode")
        message = self.POSTDate["TextBox2"]
        # print("message":message)
        exponent = int(self.POSTDate["txtKeyExponent"], 16)
        modulus = int(self.POSTDate["txtKeyModulus"], 16)
        rsa_pubkey = rsa.PublicKey(modulus, exponent)
        # print("rsa_pubkey:"rsa_pubkey)
        passwd = rsa.encrypt(message.encode("utf-8"), rsa_pubkey)
        # print("passwd:"passwd)
        passwd = binascii.b2a_hex(passwd).decode("ascii")
        self.POSTDate["TextBox2"] = passwd
        self.__get_check_code_ocr()
        print("##POST login")
        try_time = 0
        login_response = self.session.post(
            BUU.MainURL, data=self.POSTDate, headers=BUU.InitHeader
        )
        while try_time < 5:
            login_response = self.session.get(
                BUU.xsmain + self.username, headers=BUU.InitHeader
            )
            # 进入主页
            self.soup = BeautifulSoup(login_response.text, "lxml")
            if login_response.ok and self.soup.find("title").text == "正方教务管理系统":
                print("#Login：" + self.soup.find("title").text)
                self.name = self.soup.find("span", id="xhxm").text[0:-2]
                print("#姓名：", self.name)
                print("\033[1;36m 登录成功 \033[0m")
                return 200
            else:
                try_time += 1
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
