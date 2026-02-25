import json
import base64
import hmac
import hashlib
import time
import requests
from urllib.parse import quote
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA


# ===== 配置 =====
PUBLIC_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvDvSR4un/yG8uRUxdAVz25lYC+a7F3ZIt3RthhKRrhvoHChe5QnqdUfKOGXCxj/8UJbCoGea5ZPvd1SO/pIutrLCzw2ccTMbSQcQzivinhx8bG21jfyE7BBikbOQh1HY9KiddnLoAaFpjY8qv91lbrdYuTUh1Sq+IAmJAKElANH75O6upx2JqRP/jvdz7Y16uq25MndFux8ZUS/IIboY71eGCqun43bz2oz9oOSR2hxNjBk0uza8T62GpHZ+JoxfbTDDiUfxKiXfDUmzecT4NebZbLmtdjkh18kvti+Y1P0riDLqEnUDKpiGO4ujGXqt9SpI7F22fcCOMUUYv5sz5QIDAQAB
-----END PUBLIC KEY-----"""

HMAC_KEY = '58A12AE97D807A7B26556A7101850AFC'  # HMAC签名密钥
LOGIN_API = 'https://passportapi.bjx.com.cn/api/v1/login/pwd/web'


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """PKCS7填充"""
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding


def aes_encrypt(plaintext: str) -> tuple[str, str]:
    """
    AES加密，CBC模式，PKCS7填充
    返回: (加密后的数据, key的hex字符串)
    """
    key = get_random_bytes(16)  # 16字节随机key
    iv = key  # IV等于key

    # PKCS7填充
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_bytes = plaintext.encode('utf-8')
    padded_data = pkcs7_pad(plaintext_bytes, AES.block_size)

    encrypted = cipher.encrypt(padded_data)

    # 返回加密数据和key(hex格式)
    return base64.b64encode(encrypted).decode('utf-8'), key.hex()


def rsa_encrypt(data: str, public_pem: str) -> str:
    """
    RSA加密，使用公钥，PKCS1_V1_5方式
    """
    # 加载公钥
    key = RSA.import_key(public_pem)
    cipher = PKCS1_v1_5.new(key)

    # 加密
    encrypted = cipher.encrypt(data.encode('utf-8'))

    # Base64编码
    return base64.b64encode(encrypted).decode('utf-8')


def create_hmac_sha256_signature(data: str, key: str) -> str:
    """
    HMAC-SHA256签名，返回Base64字符串
    """
    signature = hmac.new(
        key.encode('utf-8'),
        data.encode('utf-8'),
        hashlib.sha256
    ).digest()
    return base64.b64encode(signature).decode('utf-8')


def sort_data(data):
    """
    递归排序对象（模拟JavaScript的sortData）
    """
    if isinstance(data, dict):
        # 按键名排序
        sorted_keys = sorted(data.keys())
        return {k: sort_data(data[k]) for k in sorted_keys}
    elif isinstance(data, list):
        return [sort_data(item) for item in data]
    else:
        return data


def obj_to_string(data: dict) -> str:
    """
    将字典转换为URL编码的字符串（按键名排序）
    """
    # 先递归排序
    sorted_data = sort_data(data)

    # 过滤掉空值的字段
    filtered_data = {k: v for k, v in sorted_data.items() if v != '' and v is not None}

    # 按键名字母顺序排序
    sorted_keys = sorted(filtered_data.keys())
    # 拼接成 key=value&key=value 格式
    parts = []
    for k in sorted_keys:
        v = filtered_data[k]
        # 如果值是字典（data字段），需要JSON序列化并URL编码
        if isinstance(v, dict):
            v = json.dumps(v, separators=(',', ':'))
        parts.append(f"{k}={quote(str(v), safe='')}")
    return '&'.join(parts)


def build_login_params(username: str, password: str) -> dict:
    """
    构建登录参数
    """
    # 1. 加密用户名密码
    t = {
        "userName": username,
        "password": password,
        "returnUrl": ""
    }
    # 先JSON.stringify
    plaintext = json.dumps(t, separators=(',', ':'))
    # print('plaintext:', plaintext)
    # AES加密
    aka_params, key_hex = aes_encrypt(plaintext)
    # print('aka_params:', aka_params)
    # print('key_hex:', key_hex)
    # RSA加密key
    secret_key = rsa_encrypt(key_hex, PUBLIC_PEM)
    # print('secret_key:', secret_key)
    # 2. 构建请求体
    data = {
        "akaParams": aka_params,
        "secretKey": secret_key
    }

    # 3. 构建完整参数（不含sign）
    params = {
        "os": "1",
        "ba": "",
        "bp": "",
        "eqp": "8ae1c9d3-a76e-4e0f-8a7e-3cb3c3727ce9",  # 设备ID，需要动态生成或从cookie获取
        "apiVersion": "1.0.0",
        "clientId": "hr.pc.myhr",
        "clientSecret": "",
        "signVersion": "1.0.0",
        "ver": "1.0.3",
        "ts": int(time.time() * 1000),
        "data": data
    }

    # 4. 生成sign
    # 先将params转为objToString格式
    obj_str = obj_to_string(params)
    # print('obj_str:', obj_str)
    # obj_str = 'apiVersion=1.0.0&clientId=hr.pc.myhr&data=%7B%22akaParams%22%3A%22bjFTn8e6mOvoRfTzI%2FMb5FZR%2FEFt2uKRPUdylvGjJReeiytQ2IBn4rz2OI2go2Qw%2FIZdvk%2Banv0UDC0dj0oYhg%3D%3D%22%2C%22secretKey%22%3A%22ZazgTPQLHQJXaD4sX8HHd8kBdRn8%2F8touc%2BZVkpky52hhXqqMJVTTz%2F13vG1liX3x8hV%2FmXRbdk2VMgkHdaZsfmTswwWGmDTg5zYKsh0VmiG7%2B%2F5aBR1JyLeHGg%2BL0n7Wb26g5q%2FWdt6KGGk4GrvbTGYfWczBLn%2BP3SljNNKB1ozO7BaJ1UuNPXPvNFJZOhjXEhBPwTRikzauHJoeuIWKZUQGQjLPG7GCqU2BioIq1ICcvghbO4iALKAnynWFiZukoNYq4PFG7LzxCoExIrS3dwfpe3zmHI6NrmL0fd6nd7Sg%2FOoxC%2FY9yAikX9JzcFUh4R3qRnk8A1CGVuT7k28sA%3D%3D%22%7D&eqp=8ae1c9d3-a76e-4e0f-8a7e-3cb3c3727ce9&os=1&signVersion=1.0.0&ts=1771763761817&ver=1.0.3'
    # print('obj_str:', obj_str)
    sign = create_hmac_sha256_signature(obj_str, HMAC_KEY)

    # 5. 添加sign
    params["sign"] = sign

    return params


def login(username: str, password: str) -> requests.Session:
    """
    登录函数，返回session
    """
    session = requests.Session()

    headers = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Content-Type': 'application/json',
        'Origin': 'https://passport.bjx.com.cn',
        'Referer': 'https://passport.bjx.com.cn/',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
        'X-Requested-With': 'XMLHttpRequest',
    }

    # 构建登录参数
    login_params = build_login_params(username, password)

    # 发送登录请求
    response = session.post(LOGIN_API, headers=headers, json=login_params)

    print(f"登录响应: {response.status_code}")
    print(f"响应内容: {response.text}")
    print(f"登陆后的session：: {session.cookies.get_dict()}")

    return session


# ===== 测试登录 =====
if __name__ == '__main__':
    username = 'xxxxx'
    password = 'xxxxx'

    # 先调试输出参数
    params = build_login_params(username, password)
    obj_str = obj_to_string(params)
    session = login(username, password)
