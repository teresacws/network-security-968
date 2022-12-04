# -*- coding: utf-8 -*-
"""
Created on Thu Aug 25 01:35:57 2022

@author: teres
"""


import rsa
import hashlib
import pem
# import random
# import string

def generate_keys():
    (pubKey, privKey) = rsa.newkeys(1024)
    with open('Alice/pubkey.pem', 'wb') as f:
        f.write(pubKey.save_pkcs1('PEM'))

    with open('Alice/privkey.pem', 'wb') as f:
        f.write(privKey.save_pkcs1('PEM'))
        
    # characters = string.ascii_letters + string.digits # get random password pf length 8 with letters, digits, and symbols
    # K = ''.join(random.choice(characters) for i in range(128))
    # with open('keys/Bobsk','w') as f:
    #     f.write(K)

generate_keys()
certs = pem.parse_file("Alice/pubkey.pem")
certs[0] = str(certs[0]).replace('-----BEGIN RSA PUBLIC KEY-----', '')
certs[0] = str(certs[0]).replace('-----END RSA PUBLIC KEY-----', '')

strcerts=str(certs[0])
strcerts=strcerts[1:]
strcerts=strcerts[:-1]
strcerts=strcerts[:-1]

hpubKey = hashlib.sha1(strcerts.encode()).hexdigest()

# hex_hpubKey=hpubKey.hexdigest()
# bi_hpubKey=hpubKey.digest()
# print(hex_hpubKey)
# print(bi_hpubKey)
with open('Bob/fingerprint.pem', 'w') as f:
    f.write(str(hpubKey))