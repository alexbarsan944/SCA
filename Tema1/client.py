from lib import *

# connect to merchant
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port_merchant))

card_number = b'1111 2222 3333 4444'  # len 19
card_exp = b'11/22'  # len 5
c_code = str(random.randint(100, 1000)).encode()  # len 3
amount = str(random.randint(100, 1000)).encode()  # len 3
nc = str(random.randint(100, 1000)).encode()  # len 3  --- client nonce
merchant_name = b'merchant name'
order_desc = b'order desc'  # len 10

pub_kc = RSA.import_key(open(public_client, 'r').read())
pub_km = RSA.import_key(open(public_merch, 'r').read())
pub_kpg = RSA.import_key(open(public_pg, 'r').read())
priv_kc = RSA.import_key(open("private_client.pem", 'r').read())

# SETUP SUB-PROTOCOL
# criptare aes a cheii publice a clientului
encrypted_PKC, aes_sk = encrypt_aes(pub_kc.exportKey())

# criptare rsa a cheii de sesiune
encrypted_sk = encrypt_rsa(pub_km, aes_sk)

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
signature_flag = rsa_verify(sid, sid_sign, pub_km)
print("SignM(sid) is", signature_flag)

# send the validity of the signature to the merchant
send_msg(s, signature_flag.encode())

if signature_flag == "invalid":
    exit(1)

# EXCHANGE SUB-PROTOCOL
PM = card_number + card_exp + c_code + sid + amount + pub_kc.export_key() + nc + merchant_name
# len(PM) = 324

signature_subject = order_desc + sid + amount + nc
sign_client = rsa_sign(signature_subject, priv_kc)

PO = order_desc + sid + amount + nc + sign_client
# len(PO) = 151

PMPO = PM + PO

# hybrid encryption
encrypted_PMPO, aes_sk3 = encrypt_aes(PMPO)
encrypted_sk3 = encrypt_rsa(pub_km, aes_sk3)

# send message to merchant
send_msg(s, encrypted_PMPO + encrypted_sk3)

check = recv_msg(s)
if check != b'ok':
    print("Merchant could not verify [PM]")
    exit(2)
print("Merchant verified [PM]")

check = recv_msg(s)
if check != b'ok':
    print("Merchant could not verify [PO]")
    exit(3)
print("Merchant verified [PO]")

check = recv_msg(s)
if check != b'ok':
    print('Invalid signature [PG - MERC]')
    exit(4)
print("Valid signature [PG -MERC]")

# get message from merchant
last_encrypted_message = recv_msg(s)
encrypted_sk6 = last_encrypted_message[-128:]
last_encrypted = last_encrypted_message[:-128]

# decrypt message
aes_sk6 = decrypt_rsa(priv_kc, encrypted_sk6)
last_message = decrypt_aes(aes_sk6, last_encrypted)

# de-concatenate messaeg
response, last_message = last_message[:2], last_message[2:]
sid2, last_message = last_message[:7], last_message[7:]
sign_pg = last_message

if response != b'ok':
    print("CONNECTION TIMEOUT")
    exit(5)
elif sid2 != sid:
    print("INVALID SID")
    exit(6)
elif rsa_verify(response + sid2 + amount + nc, sign_pg, pub_kpg)!='valid':
    print("INVALID SIGNATURE")
    exit(7)
print("CONNECTION ACCEPTED")

