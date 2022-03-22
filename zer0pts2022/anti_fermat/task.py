from Crypto.Util.number import isPrime, getStrongPrime
from gmpy2 import next_prime
# from secret import flag

# Anti-Fermat Key Generation
p = getStrongPrime(1024)
q = next_prime(p ^ ((1<<1024)-1))
n = p * q
e = 65537

# Encryption
# m = int.from_bytes(flag, 'big')
# assert m < n
# c = pow(m, e, n)
print(p,q)
y = q-(2**1024-1 - p)
print(y.bit_length(),y)
print('n = {}'.format(hex(n)))
# print('c = {}'.format(hex(c)))
