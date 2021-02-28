from lib import *

aes_session_key = os.urandom(32)
mesaj = b'123456789-1005'

# criptare aes a cheii publice a clientului
encrypted_PKC = encrypt_aes(aes_session_key, pub_kc.exportKey())

# criptare rsa a cheii de sesiune
encrypted = encrypt_rsa(pub_km, aes_session_key)
# todo send key to merc

print('len encrypted_PKC', len(str(encrypted_PKC).encode()))
print('len encrypted', len(str(encrypted).encode()))

send_msg(12345, encrypted_PKC)
