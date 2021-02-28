from lib import *
import rsa_key_generate

mesaj = b'123456789-1005'

pub_kc = RSA.import_key(open(public_client, 'r').read())
pub_km = RSA.import_key(open(public_merch, 'r').read())
priv_kc = RSA.import_key(open("private_client.pem", 'r').read())

# criptare aes a cheii publice a clientului
encrypted_PKC, aes_session_key = encrypt_aes(pub_kc.exportKey())

# criptare rsa a cheii de sesiune

priv_km = RSA.import_key(open('private_merch.pem', 'r').read())
encrypted_sk = encrypt_rsa(pub_km, aes_session_key)

# todo send key to merc

send_msg(12345, encrypted_PKC + encrypted_sk)
print(aes_session_key)
