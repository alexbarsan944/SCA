from lib import *

pub_kc = RSA.import_key(open(public_client, 'r').read())
pub_km = RSA.import_key(open(public_merch, 'r').read())
priv_km = RSA.import_key(open("private_merch.pem", 'r').read())

sid = random.randint(100, 1000)

signature = rsa_sign("{0:b}".format(sid).encode(), priv_km)
# verify = rsa_verify("{0:b}".format(sid).encode(), signature, pkm)

# receive {pub_kc}pub_km

client_msg = recv(12345)
encrypted_PKC = client_msg[:-128]
encrypted_sk = client_msg[-128:]


print(decrypt_rsa(priv_km, encrypted_sk))
