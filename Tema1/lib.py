import socket
import pyaes
import os
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
import rsa
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
import random

pkc = str(RSA.generate(2048).public_key().exportKey())[30:-27].encode()
pkm, private_rsa_m = rsa.newkeys(2048)


def send_msg(port, message):
    s = socket.socket()
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

    pass


def recv(port):
    s = socket.socket()

    s.connect(('127.0.0.1', port))

    msg = (s.recv(1024))
    s.close()
    return msg


def encrypt_aes(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def encrypt_rsa(key, plaintext):
    encrypted = rsa.encrypt(key, plaintext)
    return encrypted
