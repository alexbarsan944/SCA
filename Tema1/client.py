from lib import *

mesaj = b'123456789-1005'

pub_kc = RSA.import_key(open(public_client, 'r').read())
pub_km = RSA.import_key(open(public_merch, 'r').read())
priv_kc = RSA.import_key(open("private_client.pem", 'r').read())

# SETUP SUB-PROTOCOL
# criptare aes a cheii publice a clientului
encrypted_PKC, aes_sk = encrypt_aes(pub_kc.exportKey())

# criptare rsa a cheii de sesiune
encrypted_sk = encrypt_rsa(pub_km, aes_sk)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port_merchant))

# send encrypted keys to merchant
send_msg(s, encrypted_PKC + encrypted_sk)

# get encrypted sid and signature from merchant
msg_merc = recv_msg(s)

encrypted_sk2 = msg_merc[-128:]
encrypted_sid = msg_merc[:-128]

# decrypt session key from merchant
aes_sk2 = decrypt_rsa(priv_kc, encrypted_sk2)
# decrypt signature concatenation from merchant
sid_concat = decrypt_aes(aes_sk2, encrypted_sid)
# obtain each part of the concatenation
sid = sid_concat[:7]
sid_sign = sid_concat[7:]

# verify the received signature
print(rsa_verify(sid, sid_sign, pub_km))
