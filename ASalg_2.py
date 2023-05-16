from fastecdsa import keys, curve
from fastecdsa.point import Point
import os
import hashlib
import random

class User:
    def __init__(self, name=None):
        self.name = name
        self.private_key, self.public_key = self.generate_key_pair()
        self.r = int.from_bytes(os.urandom(32), byteorder='big')

    def generate_key_pair(self):
        private_key = int.from_bytes(os.urandom(32), byteorder='big')
        public_key = private_key * curve.secp256k1.G
        return private_key, public_key

    def generate_pre_signature(self, x, message, Y, r):
        R_p = r * curve.secp256k1.G
        data = R_p.x.to_bytes(32, 'big') + self.public_key.x.to_bytes(32, 'big') + str(message).encode()
        e = hashlib.sha256(data).digest()
        e_int = int.from_bytes(e, byteorder='big')
        s_p = (r + e_int * x) % curve.secp256k1.q
        return R_p, s_p

    def verify_pre_signature(self, X, message, R_p, s_p):
        data = R_p.x.to_bytes(32, 'big') + X.x.to_bytes(32, 'big') + str(message).encode()
        e = hashlib.sha256(data).digest()
        e_int = int.from_bytes(e, byteorder='big')
        lhs = s_p * curve.secp256k1.G
        rhs = R_p + e_int * X
        return lhs == rhs

    def generate_signature(self, s_p, R_p, y, Y):
        s = (s_p - y) % curve.secp256k1.q
        R = R_p + y * Y
        return R, s

    def learn_secret(self, s_p, s):
        y = (s_p - s) % curve.secp256k1.q
        return y

def main():
    requester = User()
    signer = User()

    message = random.randint(1000, 9999)

    R_p, s_p = signer.generate_pre_signature(signer.private_key, message, requester.public_key, signer.r)
    print("预签名: (R_p.x: {}, R_p.y: {}, s_p: {})".format(R_p.x, R_p.y, s_p))

    valid_pre_signature = requester.verify_pre_signature(signer.public_key, message, R_p, s_p)
    print("有效预签名:", valid_pre_signature)

    signature = requester.generate_signature(s_p, R_p, requester.private_key, requester.public_key)
    print("签名: (R.x: {}, R.y: {}, s: {})".format(signature[0].x, signature[0].y, signature[1]))

    y_learned = requester.learn_secret(s_p, signature[1])
    print("学到的秘密 (y):", y_learned)
    print("原始秘密 (y) 与学到的秘密匹配:", requester.private_key == y_learned)

if __name__ == "__main__":
    main()
