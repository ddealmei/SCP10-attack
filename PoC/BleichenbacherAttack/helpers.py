from functools import reduce
from math import gcd
import time


class Timer(object):
    def __init__(self):
        self.total_time = 0
        self.started = False
        self.tic = 0

    def start(self):
        if self.started:
            print("Already started")
        else:
            self.started = True
            self.tic = time.time()

    def get_time(self):
        if self.started:
            return time.time() - self.tic
        else:
            return self.total_time
    
    def stop(self):
        if not self.started:
            print("Weird to stop a timer which has not started...")
        else:
            self.total_time += (time.time() - self.tic)
            self.tic = time.time()
            self.started = False
        return self.total_time
        

def lcm_list(l):
    return reduce(lambda a, b: a*b // gcd(a, b), l)


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def mod_inv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def ceil_div(a: int, b: int) -> int:
    """
    http://stackoverflow.com/a/17511341
    """
    return -(-a // b)


def floor_div(a: int, b: int) -> int:
    return a // b


def remove_pkcsv15_padding(data):
    data = bytearray(data)
    index_m = data.find(0x00, 10)

    return int.from_bytes(data[index_m+1:], byteorder='big')


# Quick and dirty. We only consider RSA-1024 with SHA-1 digest, since it is the only available parameters
def encode_pkcs1_15(h):
    em = 0x0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003021300906052b0e03021a05000414 << 160
    return em + h
