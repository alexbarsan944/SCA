import socket
import os
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad, pad
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
import rsa
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
import random
from hashlib import sha512

host = 'localhost'
port_merchant = 12345
port_pg = 12346

public_client = "public_client.pem"
public_merch = "public_merch.pem"

block_size = 128


def send_msg(sd, message):
    msg_len = "{0:b}".format(len(message)).encode()
    msg_len = b'0' * (block_size - len(msg_len)) + msg_len
    sd.sendall(msg_len)
    sd.sendall(message)


def recv_msg(conn):
    msg_len = int(conn.recv(block_size).decode(), 2)
    msg = conn.recv(msg_len)
    return msg


def encrypt_aes(plaintext):
    key = os.urandom(32)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, block_size)), key


def decrypt_aes(key, criptotext):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(criptotext), block_size)


def encrypt_rsa(key, plaintext):
    encryptor = PKCS1_v1_5.new(key)
    return encryptor.encrypt(plaintext)


def decrypt_rsa(key, criptotext):
    decrypter = PKCS1_v1_5.new(key)
    sentinel = Random.new().read(256)
    return decrypter.decrypt(criptotext, sentinel)


def rsa_sign(msg, key_pair):
    hash = SHA256.new()
    hash.update(msg)
    signer = PKCS115_SigScheme(key_pair)
    signature = signer.sign(hash)
    return signature


def rsa_verify(msg, signature, pubKey):
    h = SHA256.new(msg)
    verifier = PKCS115_SigScheme(pubKey)
    try:
        verifier.verify(h, signature)
        return "valid."
    except:
        return "invalid."
