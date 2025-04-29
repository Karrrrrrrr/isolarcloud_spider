# 阳光云电站逆向爬虫
## 安装依赖
```shell
pip install pycryptodome
```

## 公钥
```python
url_safe_b64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkecphb6vgsBx4LJknKKes-eyj7-RKQ3fikF5B67EObZ3t4moFZyMGuuJPiadYdaxvRqtxyblIlVM7omAasROtKRhtgKwwRxo2a6878qBhTgUVlsqugpI_7ZC9RmO2Rpmr8WzDeAapGANfHN5bVr7G7GYGwIrjvyxMrAVit_oM4wIDAQAB"
std_b64 = url_safe_b64.replace('_', '/').replace('-', '+')
der_data = base64.b64decode(std_b64)
```

## 请求加密

1. 在发起请求之前构造一个json请求体 data
2. 设置请求体和headers的数据
```python
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
data['api_key_param'] = {
    'timestamp': int(time.time() * 1000),
    'nonce': nonce,
}
data['sys_code'] = 200
data['token'] = token
data['appkey'] = "B0455FBE7AA0328DB57B59AA729F05D8"
```
其中 x-access-key, appkey, sys_code都是常量
3. 把data转为json然后使用Aes算法使用上面生成的random_key加密为字符串参数
4. 发送请求


## 解密

```python
# data是加密之后的十六进制字符串, 不是json
resp = requests.post('https://gateway.isolarcloud.com' + url, headers=headers, data=data)
res = AesUtils.decrypt_hex(resp.text, random_key)
```