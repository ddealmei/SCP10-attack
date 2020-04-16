#!/usr/bin/env sage

from time import time
import sys
from subprocess import run, PIPE

def matrix2str(M):
    s = '['
    for line in M:
        s += '['
        for i in line:
            s += str(i) + " "
        s += ']'
    s += ']'
    return s

def str2matrix(s):
    s = s.replace('\n', '')[1:-1]
    M = []
    open_index, close_index = 0, 0
    while True:
        try:
            open_index = s.index('[', close_index)
            close_index = s.index(']', open_index)
            v = s[open_index + 1:close_index].split(',')
            M.append([int(x) for x in v])
        except:
            return M

def pascal_matrix(size):
    P = Matrix(ZZ, size)
    for i in range(size):
        for j in range(i + 1):
            P[i, j] = binomial(i, j)
    return P

def size_reduce_pair(B, k, l, Mu):
    r = round(Mu[k, l])
    B[k] = B[k] - r * B[l]
    for j in range(l + 1):
        Mu[k, j] = Mu[k, j] - r * Mu[l, j]
    # Mu[k, l] = Mu[k, l] - r

def size_reduction(B):
    # Get [u_{i,j}]
    _, Mu = B.gram_schmidt()
    # Go through all line starting with the second
    for k in range(1, B.nrows()):
        # Size-reduce according to all previous lines
        for l in range(k - 1, -1, -1):
            # if abs(Mu[k, l]) > 0.5:
            size_reduce_pair(B, k, l, Mu)


class Coppersmith(object):

    def __init__(self, n, e, c, prefix):
        P.<x> = PolynomialRing(Zmod(n))
        self.pol = (prefix + x) ^ e - c
        self.d = self.pol.degree()
        self.modulus = n
        self.tic = 0

        # Tweak those
        beta = 1
        epsilon = 0.05
        self.h = 7
        self.X = pow(2, 296)
        # self.X = ceil(n ** ((beta ** 2 / self.d) - epsilon))  # optimized value

    def run(self):
        self.tic = time()
        roots, toc = self.coppersmith_howgrave_univariate_rounding_chaining()
        if roots != []:
            print("\t[+] Attack successful in {} seconds.".format(toc))
            print("\t[+] Plaintext: ")
            for r in roots:
                r_hex = hex(r)
                if not 'D30100' in r_hex.upper():
                    r_hex = hex(r + self.X)
                print("\t\t* " + r_hex)

    def get_potential_roots(self, v, pol, n, t=0):
        x = pol.parent().gen()
        # transform shortest vector in polynomial
        new_pol = 0
        for ii in range(n):
            new_pol += x ** ii * v[ii] / self.X ** ii
        potential_roots = new_pol.roots()

        # test roots
        roots = []
        for root in potential_roots:
            if root[0].is_integer() and root[0] < self.modulus and root[0] != 0:
                roots.append(ZZ(root[0]) + self.X * t)
        return roots

    def coppersmith_howgrave_univariate_rounding_chaining(self):
        # check
        if not self.pol.is_monic():
            raise ArithmeticError("Polynomial must be monic.")

        # init
        n = self.d * self.h + 1
        c = pow(1.5, n)

        # change ring of pol and x
        polZ = self.pol.change_ring(ZZ)
        x = polZ.parent().gen()

        gg = []
        for ii in range(self.h):
            for jj in range(self.d):
                gg.append((x * self.X) ** jj * self.modulus ** (self.h - ii) * polZ(x * self.X) ** ii)
        gg.append(polZ(x * self.X) ** self.h)

        # construct lattice B
        BB = Matrix(ZZ, n)
        for ii in range(n):
            for jj in range(ii + 1):
                BB[ii, jj] = gg[ii][jj]

        size_reduction(BB)
        BB_tilde = copy(BB)

        # Rounding
        min_elt = pow(self.X, n - 1)
        k = int(log(min_elt / c, 2))
        for ii in range(n):
            for jj in range(ii + 1):
                BB_tilde[ii, jj] = (BB_tilde[ii, jj] >> k)

        # LLL to recover the unimodular transformation U to apply to BB_tilde in order to get its LLL-reduction
        BB_str = matrix2str(BB_tilde)
        p = run(['fplll', '-m', 'fast', '-of', 'uk'], capture_output=True, input=BB_str, encoding='ascii')
        U = Matrix(str2matrix(p.stdout))

        # Apply the same transformation to obtain a reduce BB
        B = U * BB
        roots = self.get_potential_roots(B[0], polZ, n)
        if roots != []:
            toc = time() - self.tic
            return roots, toc

        # Init some parameters
        P = pascal_matrix(n)
        P = P * P  # We increase by two at each step
        c = pow(n, 5 / 2) * pow(1.5, n)
        t = 1
        while self.X * t < round(pow(self.modulus, 1 / self.d)):
            B = B * P
            # size_reduction(B) # Not needed since it is already approximately reduced (heuristic)
            B_tilde = copy(B)

            # Rounding
            min_elt = (pow(self.modulus, (n - 1) * (self.h + 1) / n) * pow(self.X, n - 1)) / B[0].norm()  # Close enough
            k = int(log(min_elt / c, 2))
            for ii in range(n):
                for jj in range(n):
                    B_tilde[ii, jj] = (B_tilde[ii, jj] >> k)

            # LLL to recover the unimodular transformation U to apply to BB_tilde in order to get its LLL-reduction
            B_str = matrix2str(B_tilde)
            p = run(['fplll', '-m', 'fast', '-of', 'uk'], stdout=PIPE, input=B_str, encoding='ascii')
            U = Matrix(str2matrix(p.stdout))

            # Apply the same transformation to obtain a reduce B
            B = U * B

            # transform shortest vector in polynomial
            roots = self.get_potential_roots(B[0], polZ, n)
            if roots != []:
                return roots

            t += 2

max_x_len = 37
prefix = int("0x0002" + 'FF'*(128-max_x_len-2) + '00'*max_x_len, 16)
attack = Coppersmith(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), prefix) # (n, e, c)
attack.run()