from Crypto.Random import random
from pytlv.TLV import *
from .helpers import *


class CRT(object):
    # Supported tags
    crt_tag = ['B4', 'B8']
    key_usage_tag = '95'
    crypto_mech_tag = '80'
    key_tag = 'D1'
    iv_tag = '91'
    tlv = TLV(crt_tag + [key_usage_tag + key_tag + iv_tag])

    def __init__(self, tag, key_use, key_len=16, iv_len=0):
        self.tag = hex(tag).split('x')[1]
        self.key_use = hex(key_use).split('x')[1]
        self.key = ''
        for _ in range(key_len):
            k = hex(random.getrandbits(8)).split('x')[1]
            if len(k) == 1:
                k += '0'
            self.key += k
        self.iv = ''
        for _ in range(iv_len):
            k = hex(random.getrandbits(8)).split('x')[1]
            if len(k) == 1:
                k += '0'
            self.iv += k

    def get_bytes(self):
        body = self.tlv.build({self.key_usage_tag: self.key_use, self.key_tag: self.key, self.iv_tag: self.iv})
        crt = self.tlv.build({self.tag: body})

        return int_to_hex(int(crt, 16), len(crt)//2)
    
    def get_key(self):
        if self.key == '':
            return []
        return int_to_hex(int(self.key, 16), len(self.key)//2)
    
    def get_iv(self):
        if self.iv == '':
            return []
        return int_to_hex(int(self.iv, 16), len(self.iv)//2)
