from lib import *

sid = random.randint(100, 1000)

signature = rsa_sign("{0:b}".format(sid).encode(), priv_km)
# verify = rsa_verify("{0:b}".format(sid).encode(), signature, pkm)

client_msg = recv(12345)
print(client_msg)
print(len(str(client_msg)))
