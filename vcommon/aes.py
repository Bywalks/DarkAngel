import os
import sys
import base64
from Crypto.Cipher import AES
from urllib.parse import unquote

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vconfig.config import *

# Author：bywalks
# Blog：http://www.bywalks.com
# Github：https://github.com/bywalks

'''
采用AES对称加密算法
'''

# str不是16的倍数那就补足为16的倍数
def add_to_16(value):
    value = str(value)
    while len(value) % 16 != 0:
        value += '\x00'
    return str.encode(value)  # 返回bytes

#加密方法
def encrypt_data(text):
    # 秘钥
    key = KEY
    # 初始化加密器
    aes = AES.new(add_to_16(key), AES.MODE_ECB)
    #先进行aes加密
    encrypt_aes = aes.encrypt(add_to_16(text))
    #用base64转成字符串形式
    encrypted_text = str(base64.encodebytes(encrypt_aes), encoding='utf-8')  # 执行加密并转码返回bytes
    return encrypted_text

#解密方法
def decrypt_data(text):
    # 秘钥
    key = KEY
    # 初始化加密器
    aes = AES.new(add_to_16(key), AES.MODE_ECB)
    #优先逆向解密base64成bytes
    base64_decrypted = base64.decodebytes(text.encode(encoding='utf-8'))
    #执行解密密并转码返回str
    decrypted_text = str(aes.decrypt(base64_decrypted),encoding='utf-8').replace('\x00','')
    return decrypted_text