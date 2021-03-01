from lib import *

pub_kpg = RSA.import_key(open(public_pg, 'r').read())
pub_km = RSA.import_key(open(public_merch, 'r').read())
priv_km = RSA.import_key(open("private_merch.pem", 'r').read())

sid = random.randint(0, 100)

sid_sign = rsa_sign("{0:07b}".format(sid).encode(), priv_km)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port_merchant))
    s.listen(1)
    conn_client, addr = s.accept()

    with conn_client:
        # SETUP SUB-PROTOCOL
        print('conn_client by', addr)
        client_msg = recv_msg(conn_client)

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
        send_msg(conn_client, encrypted_sid + encrypted_sk2)

        # receive the validity from the client
        signature_flag = recv_msg(conn_client).decode()
        print("SignM(sid) is", signature_flag)
        if signature_flag == "invalid":
            exit(1)

        # EXCHANGE SUB-PROTOCOL
        # receive message from client
        client_msg2 = recv_msg(conn_client)
        encrypted_PMPO = client_msg2[:-128]
        encrypted_sk3 = client_msg2[-128:]

        # decrypt message from client and de-concatenate it
        aes_sk3 = decrypt_rsa(priv_km, encrypted_sk3)
        PMPO = decrypt_aes(aes_sk3, encrypted_PMPO)
        PM = PMPO[:324]
        PO = PMPO[324:]

        card_number, PM = PM[:19], PM[19:]
        card_exp, PM = PM[:5], PM[5:]
        c_code, PM = PM[:3], PM[3:]
        sid2, PM = PM[:7], PM[7:]
        amount, PM = PM[:3], PM[3:]
        pub_kc2, PM = PM[:271], PM[271:]
        nc, PM = PM[:3], PM[3:]
        merchant_name = PM
        # verify data
        if int(sid2, 2) != sid:
            print("[PM] Different session id")
            send_msg(conn_client, b'not ok')
            exit(2)
        elif pub_kc2 != pub_kc.export_key():
            print("[PM] Different client public key")
            send_msg(conn_client, b'not ok')
            exit(2)
        else:
            print("[PM] Valid data")
            send_msg(conn_client, b'ok')

        order_desc, PO = PO[:10], PO[10:]
        sid3, PO = PO[:7], PO[7:]
        amount2, PO = PO[:3], PO[3:]
        nc2, PO = PO[:3], PO[3:]
        sign_client = PO
        signature_subject = order_desc + sid3 + amount2 + nc2

        # verify data
        if int(sid3, 2) != sid:
            print("[PO] Different session id")
            send_msg(conn_client, b'not ok')
            exit(3)
        elif amount != amount2:
            print("[PO] Different amount")
            send_msg(conn_client, b'not ok')
            exit(3)
        elif nc != nc2:
            print("[PO] Different client nonce")
            send_msg(conn_client, b'not ok')
            exit(3)
        elif rsa_verify(signature_subject, sign_client, RSA.import_key(pub_kc2)) != 'valid':
            print("[PO] Invalid signature")
            send_msg(conn_client, b'not ok')
            exit(3)
        else:
            print("[PO] Verified data")
            send_msg(conn_client, B'ok')

        # connect to the PG
        s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s1.connect((host, port_pg))

        PM = PMPO[:324]
        merchant_sign = rsa_sign(sid2 + pub_kc.export_key() + amount, priv_km)
        encrypted_message, aes_sk4 = encrypt_aes(PM + merchant_sign)
        encrypted_sk4 = encrypt_rsa(pub_kpg, aes_sk4)

        send_msg(s1, encrypted_message + encrypted_sk4)
        # get validation from PG
        valid = recv_msg(s1)
        if valid != b'ok':
            print("Invalid signature [PG]")
            exit(4)
        print("Valid signature [PG]")

        # get encrypted message from PG
        pg_encrypted_message = recv_msg(s1)
        pg_encrypted = pg_encrypted_message[:-128]
        encrypted_sk5 = pg_encrypted_message[-128:]

        aes_sk5 = decrypt_rsa(priv_km, encrypted_sk5)
        pg_message = decrypt_aes(aes_sk5, pg_encrypted)

        response, pg_message = pg_message[:2], pg_message[2:]
        sid_pg, pg_message = pg_message[:7], pg_message[7:]
        sign_pg = pg_message

        if response != b'ok':
            print('CONNECTION TIMEOUT')
            exit(5)
        print("CONNECTION ACCEPTED... verifying PG signature")

        check = rsa_verify(response + sid_pg + amount + nc, sign_pg, pub_kpg)
        if check != 'valid':
            print("PG signature invalid")
            send_msg(conn_client, b'not ok')
            send_msg(s1, b'not ok')
            exit(6)
        print("PG signature valid")
        send_msg(conn_client, b'ok')
        send_msg(s1, b'ok')

        last_message = decrypt_aes(aes_sk5, pg_encrypted)
        last_encrypted, aes_sk6 = encrypt_aes(last_message)
        encrypted_sk6 = encrypt_rsa(pub_kc, aes_sk6)

        send_msg(conn_client, last_encrypted + encrypted_sk6)
