# -*- coding: utf-8 -*-
import os
import json
import time
import base64
import requests
import ddddocr

from datetime import datetime
from selenium import webdriver
from selenium.webdriver.common.by import By
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

print("============= 图书馆预约脚本 =============")

TOKEN_FILE = "token.txt"
IV = b"ZZWBKJ_ZHIHUAWEI"

# ================= Token 工具 =================

def save_token(token: str):
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        f.write(token)
    print("[+] Authorization 已保存")

def load_token() -> str | None:
    if not os.path.exists(TOKEN_FILE):
        return None
    with open(TOKEN_FILE, "r", encoding="utf-8") as f:
        token = f.read().strip()
    print("[+] 已加载本地 Authorization")
    return token

def check_token_valid(session: requests.Session, date: str) -> bool:
    url = "https://zwyy.nyist.edu.cn/v4/space/pick"
    data = {
        "premisesIds": "1",
        "categoryIds": [],
        "storeyIds": [],
        "boutiqueIds": [],
        "date": date
    }
    r = session.post(url, json=data)
    if r.status_code == 200 and r.json().get("code") == 0:
        print("[+] Authorization 有效")
        return True
    print("[-] Authorization 已失效")
    return False

# ================= AES =================

def gen_key(day: str) -> bytes:
    day = day.replace("-", "")
    return (day + day[::-1]).encode()

def aes_encrypt(data: dict, day: str) -> str:
    key = gen_key(day)
    plaintext = json.dumps(data, separators=(",", ":")).encode()
    cipher = AES.new(key, AES.MODE_CBC, IV)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return base64.b64encode(ciphertext).decode()

# ================= 主流程 =================

session = requests.Session()
formatted_date = datetime.now().strftime("%Y-%m-%d")

session.headers.update({
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
    "X-Requested-With": "XMLHttpRequest",
    "Origin": "https://zwyy.nyist.edu.cn",
    "Referer": "https://zwyy.nyist.edu.cn/h5/index.html",
    "Accept-Language": "zh-CN,zh;q=0.9"
})

# ===== 1. 尝试使用本地 token =====

token = load_token()
if token:
    session.headers["Authorization"] = token
    if not check_token_valid(session, formatted_date):
        token = None

# ===== 2. token 无效 → Selenium 登录 =====

if not token:
    username = input("用户名：")
    password = input("密码：")

    ocr = ddddocr.DdddOcr()
    driver = webdriver.Chrome()
    driver.get(
        "https://cas.nyist.edu.cn/cas/login"
        "?service=http%3A%2F%2Fzwyy.nyist.edu.cn%2Fv4%2Flogin%2Fcas"
    )

    driver.find_element(By.ID, "username").send_keys(username)
    driver.find_element(By.ID, "password").send_keys(password)

    driver.find_element(By.ID, "captcha_img").screenshot("captcha.png")
    with open("captcha.png", "rb") as f:
        captcha = ocr.classification(f.read())

    driver.find_element(By.ID, "captcha").send_keys(captcha)
    driver.find_element(By.XPATH, '//input[@value="登录"]').click()

    time.sleep(8)

    token = driver.execute_script(
        "return window.sessionStorage.getItem('token');"
    )

    if not token:
        print("[-] 登录失败，未获取 token")
        driver.quit()
        exit(1)

    token = "bearer" + token
    session.headers["Authorization"] = token

    driver.quit()
    save_token(token)

# ================== 选楼层 ==================

url = "https://zwyy.nyist.edu.cn/v4/space/pick"
data = {
    "premisesIds": "1",
    "categoryIds": [],
    "storeyIds": [],
    "boutiqueIds": [],
    "date": formatted_date
}

resp = session.post(url, json=data)
areas = resp.json()["data"]["area"]

for area in areas:
    print(f"ID:{area['id']}  楼层:{area['nameMerge']}")

areas_id = input("请输入楼层ID：")

# ================== 时间段 ==================

segment = session.post(
    "https://zwyy.nyist.edu.cn/v4/Space/map",
    json={"id": areas_id}
).json()["data"]["date"]["list"][0]["times"][0]["id"]

print("segment:", segment)

# ================== 座位 ==================

seat_list = session.post(
    "https://zwyy.nyist.edu.cn/v4/Space/seat",
    json={
        "id": areas_id,
        "day": formatted_date,
        "label_id": [],
        "start_time": "00:00",
        "end_time": "21:30",
        "begdate": "",
        "enddate": ""
    }
).json()["data"]["list"]

for seat in seat_list:
    if seat["status_name"] == "空闲":
        print(f"座位:{seat['name']}  ID:{seat['id']}")

seat_id = input("请输入座位ID：")

# ================== 提交预约 ==================

data4 = {
    "seat_id": seat_id,
    "segment": segment,
    "day": formatted_date,
    "start_time": "",
    "end_time": ""
}

aesjson = {"aesjson": aes_encrypt(data4, formatted_date)}

result = session.post(
    "https://zwyy.nyist.edu.cn/v4/space/confirm",
    json=aesjson
)

print("预约结果：", result.text)
