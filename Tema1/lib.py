import socket
import pyaes
import os

from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
import rsa
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
import random
from hashlib import sha512

public_client = "public_client.pem"
public_merch = "public_merch.pem"

block_size = 128


def send_msg(port, message):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Socket successfully created")

    s.bind(('', port))
    print("socket binded to %s" % port)
    s.listen(5)
    print("socket is listening")

    while True:
        c, addr = s.accept()
        print('Got connection from', addr)
        c.send(message)
        c.close()
        s.close()
        break
    pass


def recv(port):
    s = socket.socket()

    s.connect(('127.0.0.1', port))

    msg = (s.recv(port))
    s.close()
    return msg


def encrypt_aes(plaintext):
    aes_session_key = os.urandom(32)

    cipher = AES.new(aes_session_key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, block_size)), aes_session_key


def encrypt_rsa(key, plaintext):
    encryptor = PKCS1_v1_5.new(key)
    return encryptor.encrypt(plaintext)


def decrypt_rsa(key, criptotext):
    sentinel = Random.new().read(256)
    decrypter = PKCS1_v1_5.new(key)
    return decrypter.decrypt(criptotext, sentinel)


def rsa_sign(msg, rsa_key_pair):
    hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
    signature = pow(hash, rsa_key_pair.d, rsa_key_pair.n)
    return signature


def rsa_verify(msg, signature, key_pair):
    hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
    hashFromSignature = pow(signature, key_pair.e, key_pair.n)
    return hash == hashFromSignature
