from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA as SHA1

from .helpers import *


class RsaKeyHolder(object):
    def __init__(self, rsa_components):
        self.key = RSA.construct(rsa_components)
        self.size_bytes = self.key.size_in_bytes()

    def public_key_op(self, data):
        pt = hex_to_int(data)
        ct = self.key._encrypt(pt)
        return int_to_hex(ct, self.size_bytes)

    def private_key_op(self, data):
        ct = hex_to_int(data)
        pt = int(self.key._decrypt(ct))
        return int_to_hex(pt, self.size_bytes)

    def encrypt_oaep(self, data):
        cipher = PKCS1_OAEP.new(self.key)
        ct = cipher.encrypt(data)

        return bytes_to_hex(ct)
    
    def sign_pkcs1(self, data):
        payload = bytearray(data)
        h = SHA1.new(payload)
        s = pkcs1_15.new(self.key).sign(h)
        return bytes_to_hex(s)

    def verify_pkcs1(self, data, signature):
        payload = bytearray(data)
        h = SHA1.new(payload)
        s = bytes(signature)
        return pkcs1_15.new(self.key).verify(h, s)

    def sign_with_message_recovery(self, to_embed, ad):
        to_hash = bytearray(to_embed + ad)
        h = SHA1.new(to_hash).digest()
        payload = [0x6A] + to_embed + bytes_to_hex(h) + [0xBC]
        s = self.private_key_op(payload)

        # Convert the signature in integer to compute min(s, n-s)
        s = bytes_to_int(s)
        s = int_to_hex(min(s, self.key.n - s), self.size_bytes)

        return s

    def verify_with_message_recovery(self, signature, ad):
        payload = self.public_key_op(signature)
        # Global Platform specifies that we receive min(s, n-s)
        if payload[-1] != 0xBC:
            payload = hex_to_int(payload)
            payload = self.key.n - payload
            payload = int_to_hex(payload, self.size_bytes)

        if payload[0] != 0x6A or payload[-1] != 0xBC:
            return False, None

        recover_data = payload[1:-21]
        h1 = SHA1.new(bytearray(recover_data+ad)).digest()
        h2 = bytearray(payload[-21:-1])

        return h1 == h2, recover_data
