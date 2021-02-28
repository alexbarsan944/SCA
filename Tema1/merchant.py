from lib import *
import rsa_key_generate

pub_km = RSA.import_key(open(public_merch, 'r').read())
priv_km = RSA.import_key(open("private_merch.pem", 'r').read())

sid = random.randint(0, 100)

sid_sign = rsa_sign("{0:b}".format(sid).encode(), priv_km)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port_merchant))
    s.listen(1)
    conn, addr = s.accept()

    with conn:
        # SETUP SUB-PROTOCOL
        print('Connected by', addr)
        client_msg = recv_msg(conn)

        encrypted_sk = client_msg[-128:]
        encrypted_PKC = client_msg[:-128]

        # decrypt message from client and obtain keys
        aes_sk = decrypt_rsa(priv_km, encrypted_sk)
        pub_kc = RSA.import_key(decrypt_aes(aes_sk, encrypted_PKC))

        # concatenate sid and rsa signature of sid
        sid_concat = "{0:07b}".format(sid).encode() + sid_sign

        # encrypt sid and signature
        encrypted_sid, aes_sk2 = encrypt_aes(sid_concat)
        encrypted_sk2 = encrypt_rsa(pub_kc, aes_sk2)

        # send sid and signature to client
        send_msg(conn, encrypted_sid + encrypted_sk2)
