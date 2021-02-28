from Crypto.PublicKey import RSA

priv_kc = RSA.generate(1024)
pub_kc = priv_kc.publickey()

with open('private_client.pem', 'w') as pr:
    pr.write(priv_kc.export_key().decode())
with open('public_client.pem', 'w') as pu:
    pu.write(pub_kc.export_key().decode())

priv_km = RSA.generate(1024)
pub_km = priv_km.publickey()

with open('private_merch.pem', 'w') as pr:
    pr.write(priv_km.export_key().decode())
with open('public_merch.pem', 'w') as pu:
    pu.write(pub_km.export_key().decode())