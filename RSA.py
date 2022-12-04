# -*- coding: utf-8 -*-
"""
Created on Tue Aug 23 23:23:34 2022

@author: teres

reference: https://basseltech.com/watch?v=txz8wYLITGk&i=1
"""

import rsa

def generate_keys():
    (pubKey, privKey) = rsa.newkeys(1024)
    with open('Alice/pubkey.pem', 'wb') as f:
        f.write(pubKey.save_pkcs1('PEM'))

    with open('Alice/privkey.pem', 'wb') as f:
        f.write(privKey.save_pkcs1('PEM'))

def load_keys():
    with open('Alice/pubkey.pem', 'rb') as f:
        pubKey = rsa.PublicKey.load_pkcs1(f.read())

    with open('Alice/privkey.pem', 'rb') as f:
        privKey = rsa.PrivateKey.load_pkcs1(f.read())

    return pubKey, privKey

def encrypt(msg, key):
    return rsa.encrypt(msg.encode('ascii'), key)

def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        error = False
        return error

def sign_sha1(msg, key):
    return rsa.sign(msg.encode('ascii'), key, 'SHA-1')

def verify_sha1(msg, signature, key):
    try:
        return rsa.verify(msg.encode('ascii'), signature, key) == 'SHA-1'
    except:
        return False

# generate_keys()
# pubKey, privKey = load_keys()

# message = 'asdf'
# ciphertext = encrypt(message, pubKey)

# signature = sign_sha1(message, privKey)

# plaintext = decrypt(ciphertext, privKey)

# print(f'Cipher text: {ciphertext}')
# print(f'Signature: {signature}')

# if plaintext:
#     print(f'Plain text: {plaintext}')
# else:
#     print('Could not decrypt the message.')

# if verify_sha1(plaintext, signature, pubKey):
#     print('Signature verified!')
# else:
#     print('Could not verify the message signature.')