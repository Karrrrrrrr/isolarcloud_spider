from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import get_random_bytes

import json
import time
from random import choice
import requests
import binascii

import base64

url_safe_b64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkecphb6vgsBx4LJknKKes-eyj7-RKQ3fikF5B67EObZ3t4moFZyMGuuJPiadYdaxvRqtxyblIlVM7omAasROtKRhtgKwwRxo2a6878qBhTgUVlsqugpI_7ZC9RmO2Rpmr8WzDeAapGANfHN5bVr7G7GYGwIrjvyxMrAVit_oM4wIDAQAB"
std_b64 = url_safe_b64.replace('_', '/').replace('-', '+')
der_data = base64.b64decode(std_b64)


def encrypt_with_der_public_key(message: str, public_key: bytes = der_data) -> bytes:
    """使用 RSA 公钥加密"""
    pub_key = serialization.load_der_public_key(
        public_key,
        backend=default_backend()
    )
    encrypted = pub_key.encrypt(
        message.encode(),
        padding.PKCS1v15()  # 使用 PKCS#1 v1.5 填充（和 JSEncrypt 默认一致）
    )
    return base64.b64encode(encrypted)


def encrypt_with_public_key(message: str, public_key: str) -> bytes:
    """使用 RSA 公钥加密"""
    pub_key = serialization.load_pem_public_key(
        public_key.encode(),
        backend=default_backend()
    )
    encrypted = pub_key.encrypt(
        message.encode(),
        padding.PKCS1v15()  # 使用 PKCS#1 v1.5 填充（和 JSEncrypt 默认一致）
    )
    return encrypted


def decrypt_with_private_key(encrypted: bytes, private_key: str) -> str:
    """使用 RSA 私钥解密"""
    priv_key = serialization.load_pem_private_key(
        private_key.encode(),
        password=None,
        backend=default_backend()
    )
    decrypted = priv_key.decrypt(
        encrypted,
        padding.PKCS1v15()  # 使用 PKCS#1 v1.5 填充
    )
    return decrypted.decode()





# 加密
def encrypt_with_public_key2(message, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_v1_5.new(key)
    return cipher.encrypt(message.encode())


# 解密
def decrypt_with_private_key2(encrypted, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_v1_5.new(key)
    return cipher.decrypt(encrypted, sentinel=None).decode()


def rsa_encrypt(plaintext: str, public_key_pem: str) -> str:
    """
    使用 RSA 公钥加密数据，返回 Base64 编码的加密结果（172位）
    """
    # 1. 加载公钥
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )

    # 2. 使用 PKCS1v15 填充加密（和 JSEncrypt 默认一致）
    encrypted_bytes = public_key.encrypt(
        plaintext.encode(),
        padding.PKCS1v15()
    )

    # 3. 转为 Base64（172 位字符串）
    encrypted_base64 = base64.b64encode(encrypted_bytes).decode()
    return encrypted_base64


# token = '598226_5e600a629684477f9a8d8bc78843c3ce'
token = '598226_f5571f9385fb450a9c429019258d8171'


def random_word(n):
    ch = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(choice(ch) for _ in range(n))


def decrypt_hex(ciphertext_hex: str, key: str, iv: bytes = None, mode=AES.MODE_CBC) -> str:
    """
    AES 解密十六进制字符串

    Args:
        ciphertext_hex (str): 16进制加密数据
        key (str): 密钥（16/24/32字节，对应 AES-128/AES-192/AES-256）
        iv (bytes, optional): 初始化向量（CBC模式需要，16字节）
        mode: AES 模式（默认 CBC）

    Returns:
        str: 解密后的明文
    """
    # 1. 转换 Hex 字符串为 bytes
    ciphertext = binascii.unhexlify(ciphertext_hex)

    # 2. 确保 key 是 bytes（如果传入的是字符串，可以 encode）
    if isinstance(key, str):
        key = key.encode('utf-8')

    # 3. 检查 key 长度（16/24/32 字节）
    if len(key) not in [16, 24, 32]:
        raise ValueError("AES 密钥必须是 16(AES-128)、24(AES-192) 或 32(AES-256) 字节")

    # 4. 初始化 AES 解密器
    if mode == AES.MODE_CBC:
        if iv is None:
            # 如果没有提供 IV，默认取前 16 字节（某些实现会这样）
            iv = ciphertext[:16]
            ciphertext = ciphertext[16:]
        cipher = AES.new(key, mode, iv)
    elif mode == AES.MODE_ECB:
        cipher = AES.new(key, mode)
    else:
        raise ValueError("不支持的 AES 模式")

    # 5. 解密并移除 PKCS7 填充
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)

    # 6. 返回字符串
    return decrypted.decode('utf-8')


def encrypt_hex(data: str, key: str, iv: bytes = None) -> str:
    """
    AES 加密数据并返回 16 进制字符串

    Args:
        data (str): 要加密的明文
        key (str): 密钥（16/24/32字节，对应 AES-128/AES-192/AES-256）
        iv (bytes, optional): 初始化向量（16字节），默认随机生成

    Returns:
        str: 16 进制格式的加密数据（IV + 密文）
    """
    # 1. 确保 key 是 bytes（如果传入字符串，转为 bytes）
    if isinstance(key, str):
        key = key.encode('utf-8')

    # 2. 检查 key 长度（16/24/32 字节）
    if len(key) not in [16, 24, 32]:
        raise ValueError("AES 密钥必须是 16(AES-128)、24(AES-192) 或 32(AES-256) 字节")
    # 3. 生成随机 IV（如果未提供）
    if iv is None:
        iv = get_random_bytes(16)  # AES 块大小=16字节

    # 4. 初始化 AES 加密器（CBC 模式）
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # 5. 加密并添加 PKCS7 填充
    encrypted = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))

    # 6. 返回 IV + 密文的 16 进制字符串
    return (iv + encrypted).hex()



class AesUtils:
    @staticmethod
    def encrypt_hex(plaintext: str, key: str) -> str:
        """
        模拟 JS 的 encryptHex 函数
        - 输入: 明文字符串和密钥字符串
        - 输出: 16进制密文字符串(不带IV，因为是ECB模式)
        """
        # 1. 处理密钥(UTF-8编码，自动补全到有效长度)
        key_bytes = AesUtils._process_key(key)

        # 2. 处理明文(如果是对象转为JSON字符串)
        plaintext_bytes = AesUtils._process_plaintext(plaintext)

        # 3. AES-ECB加密
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext_bytes, AES.block_size))

        # 4. 返回16进制字符串(对应JS的.ciphertext.toString())
        return ciphertext.hex()

    @staticmethod
    def decrypt_hex(ciphertext_hex: str, key: str) -> str:
        """
        模拟 JS 的 decryptHex 函数
        - 输入: 16进制密文字符串和密钥字符串
        - 输出: 解密后的明文
        """
        # 1. 处理密钥
        key_bytes = AesUtils._process_key(key)

        # 2. 16进制转bytes
        ciphertext = binascii.unhexlify(ciphertext_hex)

        # 3. AES-ECB解密
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)

        # 4. 返回UTF-8字符串
        return decrypted.decode('utf-8')

    @staticmethod
    def _process_key(key: str) -> bytes:
        """处理密钥：UTF-8编码，并补全到有效长度(16/24/32字节)"""
        key_bytes = key.encode('utf-8')
        key_len = len(key_bytes)

        # 自动补全到有效的AES密钥长度
        if key_len < 16:
            return key_bytes.ljust(16, b'\0')
        elif 16 < key_len < 24:
            return key_bytes.ljust(24, b'\0')
        elif 24 < key_len < 32:
            return key_bytes.ljust(32, b'\0')
        elif key_len > 32:
            return key_bytes[:32]
        return key_bytes

    @staticmethod
    def _process_plaintext(plaintext) -> bytes:
        """处理明文：如果是对象转为JSON字符串"""
        if isinstance(plaintext, dict):
            import json
            plaintext = json.dumps(plaintext)
        return str(plaintext).encode('utf-8')



def micro(url, data=None):
    nonce = random_word(32)
    random_key = 'web' + random_word(29)

    headers = {
        'x-random-secret-key': encrypt_with_der_public_key(random_key).decode(),
        'x-limit-obj': encrypt_with_der_public_key(token.split('_')[0]).decode(),
        'x-access-key': '9grzgbmxdsp3arfmmgq347xjbza4ysps',
        'x-client-tz': 'GMT%2B8',
        'content-type': 'text/plain;charset=UTF-8',
        'Sys_code': '200',
        # 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
        # 'x-sign-code': '0',
        # '_vc': '2025040801',
        # '_browser_brand': 'chrome',
        # '_browser_version': '135.0.0.0',
        # '_global_new_web': '1',
        # '_pl': 'js',
    }

    data = data or {}

    data['api_key_param'] = {
        'timestamp': int(time.time() * 1000),
        'nonce': nonce,
    }
    data['sys_code'] = 200
    data['token'] = token
    data['appkey'] = "B0455FBE7AA0328DB57B59AA729F05D8"
    s = json.dumps(data, ensure_ascii=0, separators=(',', ':'))

    data = AesUtils.encrypt_hex(s, random_key)
    resp = requests.post('https://gateway.isolarcloud.com' + url, headers=headers,
                         data=data)

    res = AesUtils.decrypt_hex(resp.text, random_key)
    return json.loads(res)
