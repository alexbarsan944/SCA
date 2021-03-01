import rsa_key_generate
from lib import *

rsa_key_generate.print_msg()

pub_kpg = RSA.import_key(open(public_pg, 'r').read())
pub_km = RSA.import_key(open(public_merch, 'r').read())
priv_kpg = RSA.import_key(open("private_pg.pem", 'r').read())
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port_pg))
    s.listen(1)
    conn_merchant, addr = s.accept()

    with conn_merchant:
        # SETUP SUB-PROTOCOL
        print('conn_merchant by', addr)

        # receive message from merchant
        merchant_message = recv_msg(conn_merchant)
        encrypted_message = merchant_message[:-128]
        encrypted_sk4 = merchant_message[-128:]

        # decrypt message
        aes_sk4 = decrypt_rsa(priv_kpg, encrypted_sk4)
        message = decrypt_aes(aes_sk4, encrypted_message)

        # de-concatenate PM
        PM = message[:324]
        card_number, PM = PM[:19], PM[19:]
        card_exp, PM = PM[:5], PM[5:]
        c_code, PM = PM[:3], PM[3:]
        sid, PM = PM[:7], PM[7:]
        amount, PM = PM[:3], PM[3:]
        pub_kc, PM = PM[:271], PM[271:]
        nc, PM = PM[:3], PM[3:]
        merchant_name = PM
        merchant_sign = message[324:]

        # verify sign
        sign_flag = rsa_verify(sid + pub_kc + amount, merchant_sign, pub_km)
        if sign_flag != 'valid':
            print("Invalid signature")
            send_msg(conn_merchant, b'not ok')
            exit(1)
        print("Valid signature")
        send_msg(conn_merchant, b'ok')

        # encrypt and send message to merchant
        response = b'ok'  # len 2
        sign_pg = rsa_sign(response + sid + amount + nc, priv_kpg)

        pg_message = response + sid + sign_pg
        pg_encrypted, aes_sk5 = encrypt_aes(pg_message)
        encrypted_sk5 = encrypt_rsa(pub_km, aes_sk5)

        send_msg(conn_merchant, pg_encrypted + encrypted_sk5)

        # receive response
        verified = recv_msg(conn_merchant)
        if verified != b'ok':
            print('Invalid signature [MERC]')
            exit(2)
        print("Valid signature [MERC]")
