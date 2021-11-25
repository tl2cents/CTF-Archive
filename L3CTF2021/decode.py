from base64 import b64decode
from hashlib import md5,sha1
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

xor_key="5B 93 B6 26 11 BA 6C 4D C7 E0 22 74 7D 07 D8 9A 33 2E 8E C1 E9 54 44 E8 9F 7B FA 0E 55 A2 B0 35 0B C9 66 5C C1 EF 1C 83 77 16 D2 A9 2D 3D 88 D0 E3 63 3E F7 99 8A F4 1D 4F B1 AA 44 05 D8 60 6B"
xor_key=xor_key.replace(" ","")
xor_key=bytes.fromhex(xor_key)

enc="55 85 0E 9E EF 17 08 20 66 17 B0 7F A1 C3 D5 D0 C4 4C 3E F7 4D 7A B0 2E B2 2F C6 4A 18 E9 0B E9"
key =0x935b
enc=enc.replace(" ","")
enc=bytes.fromhex(enc)
print(strxor(enc,xor_key[:32]))
print(enc)