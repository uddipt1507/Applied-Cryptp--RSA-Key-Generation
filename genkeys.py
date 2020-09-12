#!/usr/bin/python3
import sys
import random
import math
import os


def gPrime(keySize):
    while True:
        num = random.SystemRandom().randrange(2 ** (keySize - 1), 2 ** (keySize))
        if isPrime(num):
            return num


def are_relatively_prime(a, b):
    for n in range(2, min(a, b) + 1):
        if a % n == b % n == 0:
            return False
    return True


def isPrime(num):
    if num != int(num):
        return False
    num = int(num)
    if num == 0 or num == 1 or num == 4 or num == 6 or num == 8 or num == 9:
        return False

    if num == 2 or num == 3 or num == 5 or num == 7:
        return True
    s = 0
    d = num - 1
    lowPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
                 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
                 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241,
                 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
                 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449,
                 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569,
                 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
                 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
                 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907,
                 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

    if num in lowPrimes:
        return True
    for prime in lowPrimes:
        if (num % prime == 0):
            return False

    def even_odd(num):
        if (
                number % 2 == 0):
            return True
        else:
            return False

    while d % 2 == 0:
        s = 0
        d >>= 1
        s += 1
    for i in range(6):
        a = random.SystemRandom().randrange(2, num)
        if checkComposite(a, d, num, i, s):
            return False
    return True


def checkComposite(a, d, n, i, s):
    if (n <= 1):
        return False
    if (n <= 3):
        return False
    if (n % 2 == 0 or n % 3 == 0):
        return True

    if pow(a, d, n) == 1:
        return False
    for i in range(s):
        if pow(a, 2 ** i * d, n) == n - 1:
            return False

    return True

def gcd(a, b):
   while a != 0:
      a, b = b % a, a
   return b

def modInverse(a, m):
    if math.gcd(a, m) != 1:
        return None
    l1, l2, l3 = 1, 0, a
    m1, m2, m3 = 0, 1, m
    while m3 != 0:
        q = l3 // m3
        m1, m2, m3, l1, l2, l3 = (l1 - q * m1), (l2 - q * m2), (l3 - q * m3), m1, m2, m3
    return l1 % m

def gKeys():
    keySize = 1024
    p = gPrime(keySize)
    q = gPrime(keySize)
    num = p * q
    while True:
        e = random.SystemRandom().randrange(2 ** (keySize - 1), 2 ** (keySize))
        if math.gcd(e, (p - 1) * (q - 1)) == 1:
            break

    d = modInverse(e, (p - 1) * (q - 1))
    publicKey = (num, e)
    privateKey = (num, d)
    return publicKey, privateKey


def make_key_pair(length):
    if length < 4:
        raise ValueError('cannot generate a key of length less '
                         'than 4 (got {!r})'.format(length))

    n_min = 1 << (length - 1)
    n_max = (1 << length) - 1

    start = 1 << (length // 2 - 1)
    stop = 1 << (length // 2 + 1)
    primes = gPrime(start, stop)

    while primes:
        p = random.choice(primes)
        primes.remove(p)
        q_candidates = [q for q in primes
                        if n_min <= p * q <= n_max]
        if q_candidates:
            q = random.choice(q_candidates)
            break
    else:
        raise AssertionError("cannot find 'p' and 'q' for a key of "
                             "length={!r}".format(length))

    stop = (p - 1) * (q - 1)
    for e in range(3, stop, 2):
        if are_relatively_prime(e, stop):
            break
    else:
        raise AssertionError("cannot find 'e' with p={!r} "
                             "and q={!r}".format(p, q))

    for d in range(3, stop, 2):
        if d * e % stop == 1:
            break
    else:
        raise AssertionError("cannot find 'd' with p={!r}, q={!r} "
                             "and e={!r}".format(p, q, e))

    return PublicKey(p * q, e), PrivateKey(p * q, d)



def generateFiles(publicKey, privateKey):
    if os.path.exists('%s_.pub' % (user)) or os.path.exists('%s_.prv' % (user)):
        sys.exit('WARNING: The file %s_pubkey.txt or %s_privkey.txt already exists! Use a different name or delete these files and re-run this program.' % (user, user))
    f = open(user + ".pub", "w")
    f.write("Public key (N,e)" + "\n")
    f.write("N: " + str(publicKey[0]) + "\n")
    f.write("e: " + str(publicKey[1]) + "\n")
    f.close()

    f1 = open(user + ".prv", "w")
    f1.write("Private key (N,d)" + "\n")
    f1.write("N: " + str(privateKey[0]) + "\n")
    f1.write("d: " + str(privateKey[1]) + "\n")
    f1.close()


if __name__ == "__main__":
    user = sys.argv[1]
    publicKey, privateKey = gKeys()
    generateFiles(publicKey, privateKey)
