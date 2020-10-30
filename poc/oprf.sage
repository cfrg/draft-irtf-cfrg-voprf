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

    def random_scalar(self):
        return None

    def identity(self):
        return 0

    def serialize(self, element):
        return None

    def deserialize(self, encoded):
        return None

    def hash_to_group(self, encoded):
        return None

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
        self.order = order
        self.h2c_suite = suite
        self.G = EC(F(gx), F(gy))
        self.m = F.degree()
        self.L = L
        self.k = k
        self.H = H
        self.expand = expand

    def suite_name(self):
        return self.name

    def random_scalar(self):
        return random.randint(1, self.order-1)

    def identity(self):
        return self.curve(0)

    def serialize(self, element):
        x, y = element[0], element[1]
        sgn = sgn0(y)
        byte = 2 if sgn == 0 else 3
        L = int(((log(self.p, 2) + 8) / 8).n())
        return I2OSP(byte, 1) + I2OSP(x, L)

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

    def hash_to_group(self, msg, dst):
        self.h2c_suite.dst = dst
        return self.h2c_suite(msg)

    def hash_to_scalar(self, msg, dst=""):
        return hash_to_field(msg, 1, dst, self.order, self.m, self.L, self.expand, self.H, self.k)[0][0]

    def key_gen(self):
        skS = ZZ(self.random_scalar())
        pkS = self.G * skS
        return skS, pkS

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

class Evaluation(object):
    def __init__(self, evaluated_element, proof):
        self.evaluated_element = evaluated_element
        self.proof = proof


class Ciphersuite(object):
    def __init__(self, name, identifier, group, H):
        self.name = name
        self.identifier = identifier
        self.group = group
        self.H = H

    def __str__(self):
        return self.name

class ClientContext(object):
    def __init__(self, suite, contextString):
        self.suite = suite
        self.contextString = contextString

    def identifier(self):
        return self.identifier

    def blind(self, x):
        r = ZZ(self.suite.group.random_scalar())
        dst = _as_bytes("VOPRF05-") + self.contextString
        P = self.suite.group.hash_to_group(x, dst)
        R = r * P
        return r, R, P

    def unblind(self, ev, r, _):
        N = ev.evaluated_element
        if (self.suite.group.name == "ristretto255") or (self.suite.group.name == "decaf448"):
           r_inv = inverse_mod(r, self.suite.group.order)
        else:
           r_inv = inverse_mod(r, self.suite.group.G.order())
        y = r_inv * N
        return y

    def finalize(self, x, y, info):
        finalizeDST = _as_bytes("VOPRF05-Finalize-") + self.contextString
        if (self.suite.group.name == "ristretto255") or (self.suite.group.name == "decaf448"):
           encoded_element = y.encode()
        else:
           encoded_element = self.suite.group.serialize(y)
        finalize_input = I2OSP(len(x), 2) + x \
            + I2OSP(len(encoded_element), 2) + encoded_element \
            + I2OSP(len(info), 2) + info \
            + I2OSP(len(finalizeDST), 2) + finalizeDST

        h = self.suite.H()
        h.update(finalize_input)
        return h.digest()

class ServerContext(object):
    def __init__(self, suite, contextString, skS, pkS):
        self.suite = suite
        self.contextString = contextString
        self.skS = skS
        self.pkS = pkS

    def evaluate(self, element):
        return Evaluation(self.skS * element, None)

    def verify_finalize(self, x, info, expected_digest):
        dst = _as_bytes("VOPRF05-") + self.contextString
        element = self.suite.group.hash_to_group(x, dst)
        issued_element = self.evaluate(element).evaluated_element
        if (self.suite.group.name == "ristretto255") or (self.suite.group.name == "decaf448"):
           encoded_element = issued_element.encode()
        else:
           encoded_element = self.suite.group.serialize(y)

        finalizeDST = _as_bytes("VOPRF05-Finalize-") + self.contextString
        finalize_input = I2OSP(len(x), 2) + x \
            + I2OSP(len(encoded_element), 2) + encoded_element \
            + I2OSP(len(info), 2) + info \
            + I2OSP(len(finalizeDST), 2) + finalizeDST

        h = self.suite.H()
        h.update(finalize_input)
        digest = h.digest()

        return (digest == expected_digest)


def compute_composites(suite, contextString, pkS, evaluate_input, evaluate_output):
    seedDST = _as_bytes("VOPRF05-seed-") + contextString
    hash_input = I2OSP(len(pkS), 2) + pkS \
        + I2OSP(len(evaluate_input), 2) + evaluate_input \
        + I2OSP(len(evaluate_output), 2) + evaluate_output \
        + I2OSP(len(seedDST), 2) + seedDST
    h = suite.H()
    h.update(hash_input)
    seed = h.digest()

    if (suite.group.name == "ristretto255") or (suite.group.name == "decaf448"):
       M = suite.group.identity()
       Z = suite.group.identity()
    else:
       M = suite.group.identity()
       Z = suite.group.identity()

    if (suite.group.name == "ristretto255") or (suite.group.name == "decaf448"):
       Mi = suite.group.decode(evaluate_input)
       Zi = suite.group.decode(evaluate_output)
    else:
       Mi = suite.group.deserialize(evaluate_input)
       Zi = suite.group.deserialize(evaluate_output)

    di = 1
    M = (di * Mi) + M
    Z = (di * Zi) + Z

    if (suite.group.name == "ristretto255") or (suite.group.name == "decaf448"):
       Mm = M.encode()
       Zm = Z.encode()
    else:
       Mm = suite.group.serialize(M)
       Zm = suite.group.serialize(Z)

    return Mm, Zm


class VerifiableClientContext(ClientContext):
    def __init__(self, suite, contextString, pkS):
        ClientContext.__init__(self, suite, contextString)
        self.pkS = pkS

    def verify_proof(self, evaluate_input, evaluate_output, pi):
        if (self.suite.group.name == "ristretto255") or (self.suite.group.name == "decaf448"):
           G = self.suite.group.base()
           pkSm = self.pkS.encode()
        else:
           G = self.suite.group.G
           pkSm = self.suite.group.serialize(self.pkS)

        (a1, a2) = compute_composites(self.suite, self.contextString, pkSm, evaluate_input, evaluate_output)
        if (self.suite.group.name == "ristretto255") or (self.suite.group.name == "decaf448"):
           M = self.suite.group.decode(a1)
           Z = self.suite.group.decode(a2)
        else:
           M = self.suite.group.deserialize(a1)
           Z = self.suite.group.deserialize(a2)

        Ap = (pi[1] * G) + (pi[0] * self.pkS)
        Bp = (pi[1] * M) + (pi[0] * Z)

        if (self.suite.group.name == "ristretto255") or (self.suite.group.name == "decaf448"):
           a3 = Ap.encode()
           a4 = Bp.encode()
        else:
           a3 = self.suite.group.serialize(Ap)
           a4 = self.suite.group.serialize(Bp)

        challengeDST = _as_bytes("VOPRF05-challenge-") + self.contextString
        h2s_input = I2OSP(len(pkSm), 2) + pkSm \
            + I2OSP(len(a1), 2) + a1 \
            + I2OSP(len(a2), 2) + a2 \
            + I2OSP(len(a3), 2) + a3 \
            + I2OSP(len(a4), 2) + a4 \
            + I2OSP(len(challengeDST), 2) + challengeDST

        c = self.suite.group.hash_to_scalar(h2s_input)

        assert(c == pi[0])
        return c == pi[0]

    def unblind(self, ev, r, R):
        N = ev.evaluated_element
        pi = ev.proof

        if (self.suite.group.name == "ristretto255") or (self.suite.group.name == "decaf448"):
           evaluate_input = R.encode()
           evaluate_output = N.encode()
        else:
           evaluate_input = self.suite.group.serialize(R)
           evaluate_output = self.suite.group.serialize(N)

        if not self.verify_proof(evaluate_input, evaluate_output, pi):
            raise Exception("Proof verification failed")

        if (self.suite.group.name == "ristretto255") or (self.suite.group.name == "decaf448"):
           r_inv = inverse_mod(r, self.suite.group.order)
        else:
           r_inv = inverse_mod(r, self.suite.group.G.order())

        y = r_inv * N
        return y

class VerifiableServerContext(ServerContext):
    def __init__(self, suite, contextString, skS, pkS):
        ServerContext.__init__(self, suite, contextString, skS, pkS)

    def generate_proof(self, evaluate_input, evaluate_output):
        if (self.suite.group.name == "ristretto255") or (self.suite.group.name == "decaf448"):
           G = self.suite.group.base()
           pkSm = self.pkS.encode()
        else:
           G = self.suite.group.G
           pkSm = self.suite.group.serialize(self.pkS)

        (a1, a2) = compute_composites(self.suite, self.contextString, pkSm, evaluate_input, evaluate_output)
        if (self.suite.group.name == "ristretto255") or (self.suite.group.name == "decaf448"):
           M = self.suite.group.decode(a1)
        else:
           M = self.suite.group.deserialize(a1)

        r = ZZ(self.suite.group.random_scalar())
        if (self.suite.group.name == "ristretto255") or (self.suite.group.name == "decaf448"):
           ta3 = r * G
           ta4 = r * M
           a3 = ta3.encode()
           a4 = ta4.encode()
        else:
           a3 = self.suite.group.serialize(r * G)
           a4 = self.suite.group.serialize(r * M)

        challengeDST = _as_bytes("VOPRF05-challenge-") + self.contextString
        h2s_input = I2OSP(len(pkSm), 2) + pkSm \
            + I2OSP(len(a1), 2) + a1 \
            + I2OSP(len(a2), 2) + a2 \
            + I2OSP(len(a3), 2) + a3 \
            + I2OSP(len(a4), 2) + a4 \
            + I2OSP(len(challengeDST), 2) + challengeDST

        c = self.suite.group.hash_to_scalar(h2s_input)
        if (self.suite.group.name == "ristretto255") or (self.suite.group.name == "decaf448"):
           s = (r - c * self.skS) % self.suite.group.order
        else:
           s = (r - c * self.skS) % G.order()

        return [c, s]

    def evaluate(self, element):
        evaluated_element = self.skS * element
        if (self.suite.group.name == "ristretto255") or (self.suite.group.name == "decaf448"):
           evaluate_input = element.encode()
        else:
           evaluate_input = self.suite.group.serialize(element)

        if (self.suite.group.name == "ristretto255") or (self.suite.group.name == "decaf448"):
           evaluate_output = evaluated_element.encode()
        else:
           evaluate_output = self.suite.group.serialize(evaluated_element)
        proof = self.generate_proof(evaluate_input, evaluate_output)
        return Evaluation(evaluated_element, proof)


mode_base = 0x00
mode_verifiable = 0x01

def KeyGen(suite):
    skS, pkS = suite.group.key_gen()
    return skS, pkS

def SetupBaseServer(suite, skS):
    contextString = I2OSP(mode_base, 1) + I2OSP(suite.identifier, 2)
    return ServerContext(suite, contextString, skS, None)

def SetupBaseClient(suite):
    contextString = I2OSP(mode_base, 1) + I2OSP(suite.identifier, 2)
    return ClientContext(suite, contextString)

def SetupVerifiableServer(suite, skS, pkS):
    contextString = I2OSP(mode_verifiable, 1) + I2OSP(suite.identifier, 2)
    return VerifiableServerContext(suite, contextString, skS, pkS), pkS

def SetupVerifiableClient(suite, pkS):
    contextString = I2OSP(mode_verifiable, 1) + I2OSP(suite.identifier, 2)
    return VerifiableClientContext(suite, contextString, pkS)

ciphersuite_ristretto255_sha512_r255map_ro = 0x0001
ciphersuite_decaf448_sha512_d448map_ro = 0x0002
ciphersuite_p256_sha256_sswu_ro = 0x0003
ciphersuite_p384_sha512_sswu_ro = 0x0004
ciphersuite_p521_sha512_sswu_ro = 0x0005

oprf_ciphersuites = {
    Ciphersuite("P256-SHA256-SSWU-RO", ciphersuite_p256_sha256_sswu_ro, GroupP256(), hashlib.sha256),
    Ciphersuite("P384-SHA512-SSWU-RO", ciphersuite_p384_sha512_sswu_ro, GroupP384(), hashlib.sha512),
    Ciphersuite("P521-SHA512-SSWU-RO", ciphersuite_p521_sha512_sswu_ro, GroupP521(), hashlib.sha512),
    Ciphersuite("ristretto255-SHA512-R255MAP-RO", ciphersuite_ristretto255_sha512_r255map_ro, Ed25519Point(), hashlib.sha512),
    Ciphersuite("decaf448-SHA512-R255MAP-RO", ciphersuite_decaf448_sha512_d448map_ro, Ed448GoldilocksPoint(), hashlib.sha512),
}
