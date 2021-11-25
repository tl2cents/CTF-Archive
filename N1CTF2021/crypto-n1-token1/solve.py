from Crypto.Util.number import *
f=open("/home/sage/Desktop/Extra Learning/CTF/比赛/N1CTF2021/crypto-n1-token1/output.txt","r")
# f=open("./output.txt","r")
n = int(f.readline()[4:])
tokens = [int(f.readline().split(": ")[1]) for _ in range(920)]
x2 = [power_mod(x, 2, n) for x in tokens]
c2=45826812852445545573935979277992443457076371872089648644915475778319093098825670699151487782654163657210516482531915639455166133358119343973980849423144111072114848219032243215219360482938562035117641611780636775341778802057146053472950017702818869239750207365020007621660815809140827723451995480125236607450
c2inv = 52983076548811446642078416561526103296256117483454486324354864860934507167817419284299797979785979560318778718382121118437029467788929084290109421055494194638653398930615132561955251638059730256502250470596999508030459148548384745026728889238876530368915312995370308785841757845456662731412090368303339076885
X = [v * c2inv % n for v in x2]

primes = []
for p in sieve_base:
    for x in X:
        if int(x) % p == 0:
            primes.append(p)
            break
print(len(primes))

SZ = 920
mat = [[0] * SZ for _ in range(SZ)]
# mat[i][j] : number of factor primes[i] in X[j]
 
for i in range(920):
    v = int(X[i])
    for j in range(920):
        while v % primes[j] == 0:
            v //= primes[j]
            mat[j][i] += 1
    
M = Matrix(GF(2), mat)
basis_ = M.right_kernel().basis()
 
# Part 1 : find c
xmult = Integer(1)
Xmult = Integer(1)
cnt = 0
for i in range(920):
    cc = basis_[0][i]
    if int(cc) == 1:
        xmult = xmult * Integer(tokens[i])
        Xmult = Xmult * Integer(X[i])
        cnt += 1
 
print(cnt)
v = Xmult.nth_root(2, truncate_mode=True)[0]
xmult = xmult % n 
c_cnt = (xmult * inverse(int(v % n), n)) % n 
c = (c_cnt * inverse(power_mod(c2, (cnt - 1) // 2, n), n)) % n 

# Part 2 : find some sqrt of 1
xmult = Integer(1)
Xmult = Integer(1)
 
cnt = 0
for i in range(920):
    cc = basis_[1][i]
    if int(cc) == 1:
        xmult = xmult * Integer(tokens[i])
        Xmult = Xmult * Integer(X[i])
        cnt += 1
 
print(cnt)
v = Xmult.nth_root(2, truncate_mode=True)[0]
xmult = xmult % n 
c_cnt = (xmult * inverse(int(v % n), n)) % n 
sq1 = (c_cnt * inverse(power_mod(c2, cnt // 2, n), n)) % n 
 
print(n)
p = GCD(sq1+1, n)
q = GCD(sq1-1, n)
assert p != 1 and q != 1 and p * q == n
 
for u in [1, -1]:
    for v in [1, -1]:
        cc = crt(u, v, p, q)
        c_real = (c * cc) % n
        phi = (p - 1) * (q - 1)
        d = inverse(65537, phi)
        print(long_to_bytes(power_mod(c_real, d, n)))
# n1ctf{b9e7d419-0df8-438a-9120-efdf3ddf155f}

# def build_basis(oracle_inputs,p,d=30):
#     """
#     Returns a basis using the HNP game parameters and inputs to our oracle
#     """
#     basis_vectors = []
#     for i in range(d):
#         p_vector = [0] * (d+1)
#         p_vector[i] = p
#         basis_vectors.append(p_vector)
#     basis_vectors.append(list(oracle_inputs) + [QQ(1)/QQ(p)])
#     return Matrix(QQ, basis_vectors)

# M = build_basis(x2[:50],n,50)
# T = M.LLL()
# c2inv=T[1][-1]*n%n
# c2=inverse(c2inv, n)
# print(c2)
