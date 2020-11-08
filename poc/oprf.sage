#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import hashlib
import binascii

from collections import namedtuple

from hash_to_field import I2OSP, OS2IP, expand_message_xmd, hash_to_field

try:
    from sagelib.groups import GroupP256, GroupP384, GroupP521, GroupRistretto255, GroupDecaf448
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

class Evaluation(object):
    def __init__(self, evaluated_element, proof):
        self.evaluated_element = evaluated_element
        self.proof = proof

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
        r_inv = inverse_mod(r, self.suite.group.order())
        y = r_inv * N
        return y

    def finalize(self, x, y, info):
        finalizeDST = _as_bytes("VOPRF05-Finalize-") + self.contextString
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
        encoded_element = self.suite.group.serialize(issued_element)

        finalizeDST = _as_bytes("VOPRF05-Finalize-") + self.contextString
        finalize_input = I2OSP(len(x), 2) + x \
            + I2OSP(len(encoded_element), 2) + encoded_element \
            + I2OSP(len(info), 2) + info \
            + I2OSP(len(finalizeDST), 2) + finalizeDST

        h = self.suite.H()
        h.update(finalize_input)
        digest = h.digest()

        return (digest == expected_digest)

class Verifiable(object):
    def compute_composites_inner(self, skS, pkSm, evaluate_input, evaluate_output):
        seedDST = _as_bytes("VOPRF05-seed-") + self.contextString
        hash_input = I2OSP(len(pkSm), 2) + pkSm \
            + I2OSP(len(evaluate_input), 2) + evaluate_input \
            + I2OSP(len(evaluate_output), 2) + evaluate_output \
            + I2OSP(len(seedDST), 2) + seedDST
        h = self.suite.H()
        h.update(hash_input)
        seed = h.digest()

        M = self.suite.group.identity()
        Z = self.suite.group.identity()

        di = 1
        Mi = self.suite.group.deserialize(evaluate_input)
        M = (di * Mi) + M

        if skS == None:
            Zi = self.suite.group.deserialize(evaluate_output)
            Z = (di * Zi) + Z
        else:
            Z = self.skS * M

        Mm = self.suite.group.serialize(M)
        Zm = self.suite.group.serialize(Z)

        return [Mm, Zm]

    def compute_composites_fast(self, skS, pkSm, evaluate_input, evaluate_output):
        return self.compute_composites_inner(self.skS, pkSm, evaluate_input, evaluate_output)

    def compute_composites(self, pkSm, evaluate_input, evaluate_output):
        return self.compute_composites_inner(None, pkSm, evaluate_input, evaluate_output)

class VerifiableClientContext(ClientContext,Verifiable):
    def __init__(self, suite, contextString, pkS):
        ClientContext.__init__(self, suite, contextString)
        self.pkS = pkS

    def verify_proof(self, evaluate_input, evaluate_output, pi):
        G = self.suite.group.generator()
        pkSm = self.suite.group.serialize(self.pkS)

        a = self.compute_composites(pkSm, evaluate_input, evaluate_output)
        M = self.suite.group.deserialize(a[0])
        Z = self.suite.group.deserialize(a[1])

        Ap = (pi[1] * G) + (pi[0] * self.pkS)
        Bp = (pi[1] * M) + (pi[0] * Z)

        a2 = self.suite.group.serialize(Ap)
        a3 = self.suite.group.serialize(Bp)

        challengeDST = _as_bytes("VOPRF05-challenge-") + self.contextString
        h2s_input = I2OSP(len(pkSm), 2) + pkSm \
            + I2OSP(len(a[0]), 2) + a[0] \
            + I2OSP(len(a[1]), 2) + a[1] \
            + I2OSP(len(a2), 2) + a2 \
            + I2OSP(len(a3), 2) + a3 \
            + I2OSP(len(challengeDST), 2) + challengeDST

        c = self.suite.group.hash_to_scalar(h2s_input)

        assert(c == pi[0])
        return c == pi[0]

    def unblind(self, ev, r, R):
        N = ev.evaluated_element
        pi = ev.proof

        evaluate_input = self.suite.group.serialize(R)
        evaluate_output = self.suite.group.serialize(N)

        if not self.verify_proof(evaluate_input, evaluate_output, pi):
            raise Exception("Proof verification failed")

        r_inv = inverse_mod(r, self.suite.group.order())
        y = r_inv * N
        return y

class VerifiableServerContext(ServerContext,Verifiable):
    def __init__(self, suite, contextString, skS, pkS):
        ServerContext.__init__(self, suite, contextString, skS, pkS)

    def generate_proof(self, evaluate_input, evaluate_output):
        G = self.suite.group.generator()
        pkSm = self.suite.group.serialize(self.pkS)

        a = self.compute_composites_fast(self.skS, pkSm, evaluate_input, evaluate_output)
        M = self.suite.group.deserialize(a[0])

        r = ZZ(self.suite.group.random_scalar())
        a2 = self.suite.group.serialize(r * G)
        a3 = self.suite.group.serialize(r * M)

        challengeDST = _as_bytes("VOPRF05-challenge-") + self.contextString
        h2s_input = I2OSP(len(pkSm), 2) + pkSm \
            + I2OSP(len(a[0]), 2) + a[0] \
            + I2OSP(len(a[1]), 2) + a[1] \
            + I2OSP(len(a2), 2) + a2 \
            + I2OSP(len(a3), 2) + a3 \
            + I2OSP(len(challengeDST), 2) + challengeDST

        c = self.suite.group.hash_to_scalar(h2s_input)
        s = (r - c * self.skS) % self.suite.group.order()

        return [c, s]

    def evaluate(self, element):
        evaluated_element = self.skS * element
        evaluate_input = self.suite.group.serialize(element)
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
    return VerifiableServerContext(suite, contextString, skS, pkS)

def SetupVerifiableClient(suite, pkS):
    contextString = I2OSP(mode_verifiable, 1) + I2OSP(suite.identifier, 2)
    return VerifiableClientContext(suite, contextString, pkS)

Ciphersuite = namedtuple("Ciphersuite", ["name", "identifier", "group", "H"])

ciphersuite_ristretto255_sha256 = 0x0001
ciphersuite_decaf448_sha512 = 0x0002
ciphersuite_p256_sha256 = 0x0003
ciphersuite_p384_sha512 = 0x0004
ciphersuite_p521_sha512 = 0x0005

oprf_ciphersuites = [
    Ciphersuite("OPRF(ristretto255, SHA-256)", ciphersuite_ristretto255_sha256, GroupRistretto255(), hashlib.sha256),
    Ciphersuite("OPRF(decaf448, SHA-512)", ciphersuite_decaf448_sha512, GroupDecaf448(), hashlib.sha512),
    Ciphersuite("OPRF(P-256, SHA-256)", ciphersuite_p256_sha256, GroupP256(), hashlib.sha256),
    Ciphersuite("OPRF(P-384, SHA-512)", ciphersuite_p384_sha512, GroupP384(), hashlib.sha512),
    Ciphersuite("OPRF(P-521, SHA-512)", ciphersuite_p521_sha512, GroupP521(), hashlib.sha512),
]
