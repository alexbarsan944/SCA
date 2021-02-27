from lib import *

aes_session_key = os.urandom(16)
mesaj = b'123456789-1005'

# criptare aes a cheii publice a clientului
encrypted_PKC = encrypt_aes(aes_session_key, pkc)

# criptare r sa a cheii de sesiune
encrypted = encrypt_rsa(pkm, aes_session_key)

print(aes_session_key == rsa.decrypt(encrypted, private_rsa_m))
