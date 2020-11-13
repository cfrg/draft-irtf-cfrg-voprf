#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import random
import hashlib
import binascii

from hash_to_field import I2OSP, OS2IP, expand_message_xmd, hash_to_field

try:
    from sagelib.suite_p256 import p256_sswu_ro, p256_order, p256_p, p256_F, p256_A, p256_B
    from sagelib.suite_p384 import p384_sswu_ro, p384_order, p384_p, p384_F, p384_A, p384_B
    from sagelib.suite_p521 import p521_sswu_ro, p521_order, p521_p, p521_F, p521_A, p521_B
    from sagelib.common import sgn0
    from sagelib.ristretto_decaf import Ed25519Point, Ed448GoldilocksPoint
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

if sys.version_info[0] == 3:
    xrange = range
    _as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")
    _strxor = lambda str1, str2: bytes( s1 ^ s2 for (s1, s2) in zip(str1, str2) )
else:
    _as_bytes = lambda x: x
    _strxor = lambda str1, str2: ''.join( chr(ord(s1) ^ ord(s2)) for (s1, s2) in zip(str1, str2) )

# Fix a seed so all test vectors are deterministic
FIXED_SEED = "oprf".encode('utf-8')
random.seed(int.from_bytes(hashlib.sha256(FIXED_SEED).digest(), 'big'))

class Group(object):
    def __init__(self, name):
        self.name = name

    def generator(self):
        return None

    def identity(self):
        return 0

    def order(self):
        return 0

    def serialize(self, element):
        return None

    def deserialize(self, encoded):
        return None

    def serialize_scalar(self, scalar):
        pass

    def element_byte_length(self):
        pass

    def scalar_byte_length(self):
        pass

    def hash_to_group(self, x):
        return None

    def hash_to_scalar(self, x):
        return None

    def random_scalar(self):
        return random.randint(1, self.order() - 1)

    def key_gen(self):
        skS = ZZ(self.random_scalar())
        pkS = self.generator() * skS
        return skS, pkS

    def __str__(self):
        return self.name

class GroupNISTCurve(Group):
    def __init__(self, name, suite, F, A, B, p, order, gx, gy, L, H, expand, k):
        Group.__init__(self, name)
        self.F = F
        EC = EllipticCurve(F, [F(A), F(B)])
        self.curve = EC
        self.gx = gx
        self.gy = gy
        self.p = p
        self.a = A
        self.b = B
        self.group_order = order
        self.h2c_suite = suite
        self.G = EC(F(gx), F(gy))
        self.m = F.degree()
        self.L = L
        self.k = k
        self.H = H
        self.expand = expand
        self.field_bytes_length = int(ceil(len(self.p.bits()) / 8))

    def generator(self):
        return self.G

    def order(self):
        return self.group_order

    def identity(self):
        return self.curve(0)

    def serialize(self, element):
        x, y = element[0], element[1]
        sgn = sgn0(y)
        byte = 2 if sgn == 0 else 3
        return I2OSP(byte, 1) + I2OSP(x, self.field_bytes_length)

   # this is using point compression
    def deserialize(self, encoded):
        # 0x02 | 0x03 || x
        pve = encoded[0] == 0x02
        nve = encoded[0] == 0x03
        assert(pve or nve)
        assert(len(encoded) % 2 != 0)
        element_length = (len(encoded) - 1) / 2
        x = OS2IP(encoded[1:])
        y2 = x^3 + self.a*x + self.b
        y = y2.sqrt()
        parity = 0 if pve else 1
        if sgn0(y) != parity:
            y = -y
        return self.curve(self.F(x), self.F(y))

    def serialize_scalar(self, scalar):
        return I2OSP(scalar % self.order(), self.scalar_byte_length())

    def element_byte_length(self):
        return int(1 + self.field_bytes_length)

    def scalar_byte_length(self):
        return int(self.field_bytes_length)

    def hash_to_group(self, msg, dst):
        self.h2c_suite.dst = dst
        return self.h2c_suite(msg)

    def hash_to_scalar(self, msg, dst=""):
        return hash_to_field(msg, 1, dst, self.order(), self.m, self.L, self.expand, self.H, self.k)[0][0]

class GroupP256(GroupNISTCurve):
    def __init__(self):
        # See FIPS 186-3, section D.2.3
        gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
        gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
        GroupNISTCurve.__init__(self, "P256_XMD:SHA-256_SSWU_RO_", p256_sswu_ro, p256_F, p256_A, p256_B, p256_p, p256_order, gx, gy, 48, hashlib.sha256, expand_message_xmd, 128)

class GroupP384(GroupNISTCurve):
    def __init__(self):
        # See FIPS 186-3, section D.2.4
        gx = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
        gy = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
        GroupNISTCurve.__init__(self, "P384_XMD:SHA-512_SSWU_RO_", p384_sswu_ro, p384_F, p384_A, p384_B, p384_p, p384_order, gx, gy, 72, hashlib.sha512, expand_message_xmd, 192)

class GroupP521(GroupNISTCurve):
    def __init__(self):
        # See FIPS 186-3, section D.2.5
        gx = 0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66
        gy = 0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650
        GroupNISTCurve.__init__(self, "P521_XMD:SHA-512_SSWU_RO_", p521_sswu_ro, p521_F, p521_A, p521_B, p521_p, p521_order, gx, gy, 98, hashlib.sha512, expand_message_xmd, 256)

class GroupRistretto255(Group):
    def __init__(self):
        Group.__init__(self, "ristretto255")
        self.k = 128
        self.L = 48
        self.field_bytes_length = 32

    def generator(self):
        return Ed25519Point().base()

    def order(self):
        return Ed25519Point().order

    def identity(self):
        return Ed25519Point().identity()

    def serialize(self, element):
        return element.encode()

    def deserialize(self, encoded):
        return Ed25519Point().decode(encoded)

    def serialize_scalar(self, scalar):
        return I2OSP(scalar % self.order(), self.scalar_byte_length())[::-1]

    def element_byte_length(self):
        return self.field_bytes_length

    def scalar_byte_length(self):
        return self.field_bytes_length

    def hash_to_group(self, msg, dst):
        return Ed25519Point().hash_to_group(msg, dst)

    def hash_to_scalar(self, msg, dst=""):
        return hash_to_field(msg, 1, dst, self.order(), 1, self.L, expand_message_xmd, hashlib.sha512, self.k)[0][0]

class GroupDecaf448(Group):
    def __init__(self):
        Group.__init__(self, "decaf448")
        self.k = 224
        self.L = 84
        self.field_bytes_length = 56

    def generator(self):
        return Ed448GoldilocksPoint().base()

    def order(self):
        return Ed448GoldilocksPoint().order

    def identity(self):
        return Ed448GoldilocksPoint().identity()

    def serialize(self, element):
        return element.encode()

    def deserialize(self, encoded):
        return Ed448GoldilocksPoint().decode(encoded)

    def serialize_scalar(self, scalar):
        return I2OSP(scalar % self.order(), self.scalar_byte_length())[::-1]

    def element_byte_length(self):
        return self.field_bytes_length

    def scalar_byte_length(self):
        return self.field_bytes_length

    def hash_to_group(self, msg, dst):
        return Ed448GoldilocksPoint().hash_to_group(msg, dst)

    def hash_to_scalar(self, msg, dst=""):
        return hash_to_field(msg, 1, dst, self.order(), 1, self.L, expand_message_xmd, hashlib.sha512, self.k)[0][0]
