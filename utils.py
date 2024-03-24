import hashlib
import os
import string
from random import random


# 生成指定长度的随机字符串，包括字母和数字
def generate_random_key(length):
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


# 对密码进行加盐哈希处理
def hash_salt_password(password, salt=None):
    if salt is None:
        salt = os.urandom(128)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations=1000).hex()
