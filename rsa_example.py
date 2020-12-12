#!/usr/bin/env python3.8

"""
Filename: rsa_example.py
Author: Jakob Schaffarczyk
Date: 12.12.2020
Version: 1.0
Contact: jakobs@js-on.de
"""

# Include required modules
"""
sys:
    provides access to some objects used or maintained by the
    interpreter and to functions that interact strongly with the interpreter.

libnum:
    library for some numbers functions:
    - working with primes (generating, primality tests)
    - common maths (gcd, lcm, modulo inverse, Jacobi symbol, sqrt)
    - elliptic curve cryptography functions

Crypto:
    collection of cryptographic modules implementing various algorithms
    and protocols
"""

import sys
import libnum
import Crypto.Util.number
from Crypto import Random

# output script usage
def help():
    print("Usage: ./rsa_example.py <bitsize: int> <factor a: int> <factor b: int>")
    exit(1)

# check if all arguments were set
if len(sys.argv) != 4:
    help()

# store arguments as integer value,
# output error if block fails
try:
    bitsize = int(sys.argv[1])
    a = int(sys.argv[2])
    b = int(sys.argv[3])
except ValueError:
    print("Arguments must be of type int.")
    help()


### ENCRYPTION ###
# private key
p = Crypto.Util.number.getPrime(bitsize, randfunc=Crypto.Random.get_random_bytes)

# public key
q = Crypto.Util.number.getPrime(bitsize, randfunc=Crypto.Random.get_random_bytes)

# product of p and q
n = p * q

# encryption key
e = 65537

print(f"Private key: {p}")
print(f"Public key:  {q}")
print(f"Product n:   {n}")
print(f"Enc. Key:    {e}")
print()
print(f"1. Factor a: {a}")
print(f"2. Factor b: {b}")

# encrypt factor a
enc_a = pow(a, e, n)

# encrypt factor b
enc_b = pow(b, e, n)

print(f"Encrypted a: {enc_a}")
print(f"Encrypted b: {enc_b}")


### MULTIPLICATION
# multiply encrypted a and encrypted b
# % is the modulus operator in Python
enc_prod_ab = (enc_a * enc_b) % n

print()
print(f"Enc. Prod.:  {enc_prod_ab}")


### DECRYPTION
# calculate phi from p and q
phi = (p - 1) * (q - 1)

# calculate decryption key by using inverse modulus
d = libnum.invmod(e, phi)

# decrypt encrypted product
dec_prod_ab = pow(enc_prod_ab, d, n)

print()
print(f"phi(p, q):   {phi}")
print(f"Dec. Key:    {d}")
print()
print(f"Dec. Prod.:  {dec_prod_ab}")

exit(0)