#!/usr/bin/env python3

from multiprocessing import Manager, Pool
import sys


def remove_pkcsv15_padding(data):
    data = bytearray(data)
    index_m = data.find(0x00, 10)

    return int.from_bytes(data[index_m+1:], byteorder='big')


def egcd(x1, x2):
    if x1 == 0:
        return x2, 0, 1
    else:
        g, y, x = egcd(x2 % x1, x1)
        return g, x - (x2 // x1) * y, y


def mod_inv(x, m):
    g, x, y = egcd(x, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def compare_encryption(m, ev):
    c_test = pow(m, e, n)
    if c_test == c:
        result = (m * mod_inv(s, n)) % n
        if not forgery:
            result = m.to_bytes(128, byteorder='big')
            result = remove_pkcsv15_padding(result)
        print("\t[+] Result of the attack: {}".format(hex(result)))
        ev.set()


n = int(sys.argv[1], 16)
e = int(sys.argv[2], 16)
c = int(sys.argv[3], 16)
s = int(sys.argv[4], 16)
a = int(sys.argv[5], 16)
b = int(sys.argv[6], 16)
forgery = bool(int(sys.argv[7]))

pool = Pool()
event = Manager().Event()
pool.starmap_async(compare_encryption, [(i, event) for i in range(a, b)])
pool.close()
event.wait()  # We'll block here until a worker calls `event.set()`
pool.terminate()  # Terminate all processes in the Pool
