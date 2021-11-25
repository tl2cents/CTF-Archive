from Crypto.Util.number import bytes_to_long, getPrime

f = open('flag.txt', 'rb')
flag = f.read()
f.close()
m = bytes_to_long(flag)
p = getPrime(512)
q = getPrime(512)
n = p * q
e1 = 65536
e2 = 270270
c1 = pow(m, e1, n)
c2 = pow(m, e2, n)
f = open('message.txt', 'w')
f.write('n=' + str(n) + '\n')
f.write('c1=' + str(c1) + '\n')
f.write('c2=' + str(c2) + '\n')
f.close()
