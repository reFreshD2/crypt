import os
import re
import time

from pyserpent import serpent
import camellia
import matplotlib.pyplot as plt
from Crypto.Cipher import AES
from pygost.gost3412 import *
from twofish import Twofish

key = os.urandom(32)
iv = os.urandom(16)


class AESCrypt:
    crypt = AES.new(key, AES.MODE_CBC, iv)
    name = "AES"

    def __init__(self):
        pass

    def encrypt(self, data):
        encrypted_data = b''
        for i in range(0, len(data), 16):
            st = data[i:i + 16]
            if len(st) < 16:
                st = st + b' ' * (16 - len(st))
            encrypted_data += self.crypt.encrypt(st)
        return encrypted_data

    def decrypt(self, data):
        decrypted_data = b''
        for i in range(0, len(data), 16):
            st = data[i:i + 16]
            if len(st) < 16:
                st = st + b' ' * (16 - len(st))
            decrypted_data += self.crypt.decrypt(st)
        return decrypted_data


class SerpentCrypt:
    name = "Serpent"
    crypt = serpent.Serpent(key)

    def __init__(self):
        pass

    def encrypt(self, data):
        encrypted_data = b''
        for i in range(0, len(data), 16):
            st = data[i:i + 16]
            if len(st) < 16:
                st = st + b' ' * (16 - len(st))
            encrypted_data += self.crypt.encrypt(st)
        return encrypted_data

    def decrypt(self, data):
        decrypted_data = b''
        for i in range(0, len(data), 16):
            st = data[i:i + 16]
            if len(st) < 16:
                st = st + b' ' * (16 - len(st))
            decrypted_data += self.crypt.decrypt(st)
        return decrypted_data


class TwofishCrypt:
    name = "Twofish"
    crypt = Twofish(key)

    def __init__(self):
        pass

    def encrypt(self, data):
        encrypted_data = b''
        for i in range(0, len(data), 16):
            st = data[i:i + 16]
            if len(st) < 16:
                st = st + b' ' * (16 - len(st))
            encrypted_data += self.crypt.encrypt(st)
        return encrypted_data

    def decrypt(self, data):
        decrypted_data = b''
        for i in range(0, len(data), 16):
            st = data[i:i + 16]
            if len(st) < 16:
                st = st + b' ' * (16 - len(st))
            decrypted_data += self.crypt.decrypt(st)
        return decrypted_data


class CamelliaCrypt:
    name = "Camellia"
    crypt = camellia.CamelliaCipher(key=key, IV=iv, mode=camellia.MODE_CBC)

    def __init__(self):
        pass

    def encrypt(self, data):
        encrypted_data = b''
        for i in range(0, len(data), 16):
            st = data[i:i + 16]
            if len(st) < 16:
                st = st + b' ' * (16 - len(st))
            encrypted_data += self.crypt.encrypt(st)
        return encrypted_data

    def decrypt(self, data):
        decrypted_data = b''
        for i in range(0, len(data), 16):
            st = data[i:i + 16]
            if len(st) < 16:
                st = st + b' ' * (16 - len(st))
            decrypted_data += self.crypt.decrypt(st)
        return decrypted_data


class KuznechikCrypt:
    name = "Kuznechik"
    crypt = GOST3412Kuznechik(key)

    def __init__(self):
        pass

    def encrypt(self, data):
        encrypted_data = b''
        for i in range(0, len(data), 16):
            st = data[i:i + 16]
            if len(st) < 16:
                st = st + b' ' * (16 - len(st))
            encrypted_data += self.crypt.encrypt(st)
        return encrypted_data

    def decrypt(self, data):
        decrypted_data = b''
        for i in range(0, len(data), 16):
            st = data[i:i + 16]
            if len(st) < 16:
                st = st + b' ' * (16 - len(st))
            decrypted_data += self.crypt.decrypt(st)
        return decrypted_data


def getName(crypts):
    result = ''
    if len(crypts) == 1:
        return crypts[0].name
    for elem in crypts:
        result += elem.name + '+'
    return result[:len(result) - 1]


def readFile(filename):
    with open(filename, 'rb') as file:
        return file.read()


def expr_encrypt(crypts, file):
    name = file
    start = time.time()
    for crypt in reversed(crypts):
        data = readFile(name)
        encrypted = crypt.encrypt(data)
        name = crypt.name + "_" + name
        with open(name, 'wb') as newFile:
            newFile.write(encrypted)
    return time.time() - start


def getEncryptedFile(crypts, step, file):
    name = file
    i = 0
    while i <= step:
        name = crypts[i].name + "_" + name
        i += 1
    return name


def expr_decrypt(crypts, file):
    step = 0
    start = time.time()
    filename = getEncryptedFile(crypts, step, file)
    for crypt in crypts:
        if step > 0:
            filename = "decrypted_" + name
        name = getEncryptedFile(crypts, step, file)
        step += 1
        data = readFile(filename)
        decrypted = crypt.decrypt(data)
        with open("decrypted_" + name, 'wb') as newFile:
            newFile.write(decrypted)
    return time.time() - start


crypts = [
    [AESCrypt()],
    [SerpentCrypt()],
    [TwofishCrypt()],
    [CamelliaCrypt()],
    [KuznechikCrypt()],
    [AESCrypt(), TwofishCrypt()],
    [AESCrypt(), TwofishCrypt(), SerpentCrypt()],
    [SerpentCrypt(), AESCrypt()],
    [SerpentCrypt(), TwofishCrypt(), AESCrypt()],
    [TwofishCrypt(), SerpentCrypt()],
    [CamelliaCrypt(), KuznechikCrypt()],
    [KuznechikCrypt(), TwofishCrypt()],
    [CamelliaCrypt(), SerpentCrypt()],
    [KuznechikCrypt(), AESCrypt()],
    [KuznechikCrypt(), SerpentCrypt(), CamelliaCrypt()]
]
filenames = ['256kb.txt', '512kb.txt', '1mb.txt', '5mb.txt']

avgEncryptTime = []
for filename in filenames:
    avgTime = 0
    fig, ax = plt.subplots()
    for crypt in crypts:
        timeCrypt = expr_encrypt(crypt, filename)
        avgTime += timeCrypt
        ax.barh(getName(crypt), timeCrypt)
    avgEncryptTime.append(avgTime / len(crypts))
    plt.title('Encoding file:' + re.match(r'(.*?)\.', filename).group(1))
    plt.show()

avgDecryptTime = []
for filename in filenames:
    avgTime = 0
    fig, ax = plt.subplots()
    for crypt in crypts:
        timeCrypt = expr_decrypt(crypt, filename)
        avgTime += timeCrypt
        ax.barh(getName(crypt), timeCrypt)
    avgDecryptTime.append(avgTime / len(crypts))
    plt.title('Decoding file:' + re.match(r'(.*?)\.', filename).group(1))
    plt.show()

fig, ax = plt.subplots()
for i in range(0, len(filenames), 1):
    ax.bar(re.match(r'(.*?)\.', filenames[i]).group(1), avgEncryptTime[i])
plt.title('Average encrypting time')
plt.show()

fig, ax = plt.subplots()
for i in range(0, len(filenames), 1):
    ax.bar(re.match(r'(.*?)\.', filenames[i]).group(1), avgDecryptTime[i])
plt.title('Average decrypting time')
plt.show()

