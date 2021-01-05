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
    def __init__(self, suite, context_string):
        self.suite = suite
        self.context_string = context_string

    def identifier(self):
        return self.identifier

    def group_domain_separation_tag(self):
        return _as_bytes("VOPRF06-HashToGroup-") + self.context_string

    def blind(self, x):
        blind = ZZ(self.suite.group.random_scalar())
        P = self.suite.group.hash_to_group(x, self.group_domain_separation_tag())
        R = blind * P
        blinded_element = self.suite.group.serialize(R)
        return blind, blinded_element

    def unblind(self, blind, evaluated_element, blinded_element, proof):
        # Note: blinded_element and proof are unused in the base mode
        Z = self.suite.group.deserialize(evaluated_element)
        blind_inv = inverse_mod(blind, self.suite.group.order())
        N = blind_inv * Z
        unblinded_element = self.suite.group.serialize(N)
        return unblinded_element

    def finalize(self, x, unblinded_element, info):
        finalizeDST = _as_bytes("VOPRF06-Finalize-") + self.context_string
        finalize_input = I2OSP(len(x), 2) + x \
            + I2OSP(len(unblinded_element), 2) + unblinded_element \
            + I2OSP(len(info), 2) + info \
            + I2OSP(len(finalizeDST), 2) + finalizeDST

        h = self.suite.H()
        h.update(finalize_input)
        return h.digest()

class ServerContext(object):
    def __init__(self, suite, context_string, skS, pkS):
        self.suite = suite
        self.context_string = context_string
        self.skS = skS
        self.pkS = pkS

    def group_domain_separation_tag(self):
        return _as_bytes("VOPRF06-HashToGroup-") + self.context_string

    def evaluate(self, blinded_element):
        R = self.suite.group.deserialize(blinded_element)
        Z = self.skS * R
        evaluated_element = self.suite.group.serialize(Z)
        return evaluated_element, None, None

    def verify_finalize(self, x, info, expected_digest):
        P = self.suite.group.hash_to_group(x, self.group_domain_separation_tag())
        input_element = self.suite.group.serialize(P)
        issued_element, _, _ = self.evaluate(input_element) # Ignore the proof output

        finalizeDST = _as_bytes("VOPRF06-Finalize-") + self.context_string
        finalize_input = I2OSP(len(x), 2) + x \
            + I2OSP(len(issued_element), 2) + issued_element \
            + I2OSP(len(info), 2) + info \
            + I2OSP(len(finalizeDST), 2) + finalizeDST

        h = self.suite.H()
        h.update(finalize_input)
        digest = h.digest()

        return (digest == expected_digest)

class Verifiable(object):
    def compute_composites_inner(self, skS, pkSm, blinded_elements, evaluated_elements):
        assert(len(blinded_elements) == len(evaluated_elements))
        seedDST = _as_bytes("VOPRF06-Seed-") + self.context_string
        compositeDST = _as_bytes("VOPRF06-Composite-") + self.context_string
        h1_input = I2OSP(len(pkSm), 2) + pkSm \
            + I2OSP(len(seedDST), 2) + seedDST
        h = self.suite.H()
        h.update(h1_input)
        seed = h.digest()

        M = self.suite.group.identity()
        Z = self.suite.group.identity()

        for i in range(len(blinded_elements)):
            blinded_element = blinded_elements[i]
            evaluated_element = evaluated_elements[i]
            h2_input = I2OSP(len(seed), 2) + seed \
                + I2OSP(i, 2) \
                + I2OSP(len(blinded_element), 2) + blinded_element \
                + I2OSP(len(evaluated_element), 2) + evaluated_element \
                + I2OSP(len(compositeDST), 2) + compositeDST

            di = self.suite.group.hash_to_scalar(h2_input)
            Mi = self.suite.group.deserialize(blinded_element)
            M = (di * Mi) + M

            if skS == None:
                Zi = self.suite.group.deserialize(evaluated_element)
                Z = (di * Zi) + Z

        if skS != None:
            Z = self.skS * M

        Mm = self.suite.group.serialize(M)
        Zm = self.suite.group.serialize(Z)

        return [Mm, Zm]

    def compute_composites_fast(self, skS, pkSm, blinded_elements, evaluated_elements):
        return self.compute_composites_inner(self.skS, pkSm, blinded_elements, evaluated_elements)

    def compute_composites(self, pkSm, blinded_elements, evaluated_elements):
        return self.compute_composites_inner(None, pkSm, blinded_elements, evaluated_elements)

class VerifiableClientContext(ClientContext,Verifiable):
    def __init__(self, suite, context_string, pkS):
        ClientContext.__init__(self, suite, context_string)
        self.pkS = pkS

    def verify_proof(self, blinded_elements, evaluated_elements, proof):
        G = self.suite.group.generator()
        pkSm = self.suite.group.serialize(self.pkS)

        a = self.compute_composites(pkSm, blinded_elements, evaluated_elements)
        M = self.suite.group.deserialize(a[0])
        Z = self.suite.group.deserialize(a[1])

        Ap = (proof[1] * G) + (proof[0] * self.pkS)
        Bp = (proof[1] * M) + (proof[0] * Z)

        a2 = self.suite.group.serialize(Ap)
        a3 = self.suite.group.serialize(Bp)

        challengeDST = _as_bytes("VOPRF06-Challenge-") + self.context_string
        h2s_input = I2OSP(len(pkSm), 2) + pkSm \
            + I2OSP(len(a[0]), 2) + a[0] \
            + I2OSP(len(a[1]), 2) + a[1] \
            + I2OSP(len(a2), 2) + a2 \
            + I2OSP(len(a3), 2) + a3 \
            + I2OSP(len(challengeDST), 2) + challengeDST

        c = self.suite.group.hash_to_scalar(h2s_input)

        assert(c == proof[0])
        return c == proof[0]

    def unblind(self, blind, evaluated_element, blinded_element, proof):
        if not self.verify_proof([blinded_element], [evaluated_element], proof):
            raise Exception("Proof verification failed")

        Z = self.suite.group.deserialize(evaluated_element)
        blind_inv = inverse_mod(blind, self.suite.group.order())
        N = blind_inv * Z
        unblinded_element = self.suite.group.serialize(N)
        return unblinded_element

    def unblind_batch(self, blinds, evaluated_elements, blinded_elements, proof):
        assert(len(blinds) == len(evaluated_elements))
        assert(len(evaluated_elements) == len(blinded_elements))

        if not self.verify_proof(blinded_elements, evaluated_elements, proof):
            raise Exception("Proof verification failed")

        unblinded_elements = []
        for i, evaluated_element in enumerate(evaluated_elements):
            Z = self.suite.group.deserialize(evaluated_element)
            blind_inv = inverse_mod(blinds[i], self.suite.group.order())
            N = blind_inv * Z
            unblinded_element = self.suite.group.serialize(N)
            unblinded_elements.append(unblinded_element)

        return unblinded_elements

class VerifiableServerContext(ServerContext,Verifiable):
    def __init__(self, suite, context_string, skS, pkS):
        ServerContext.__init__(self, suite, context_string, skS, pkS)

    def generate_proof(self, blinded_elements, evaluated_elements):
        G = self.suite.group.generator()
        pkSm = self.suite.group.serialize(self.pkS)

        a = self.compute_composites_fast(self.skS, pkSm, blinded_elements, evaluated_elements)
        M = self.suite.group.deserialize(a[0])

        r = ZZ(self.suite.group.random_scalar())
        a2 = self.suite.group.serialize(r * G)
        a3 = self.suite.group.serialize(r * M)

        challengeDST = _as_bytes("VOPRF06-Challenge-") + self.context_string
        h2s_input = I2OSP(len(pkSm), 2) + pkSm \
            + I2OSP(len(a[0]), 2) + a[0] \
            + I2OSP(len(a[1]), 2) + a[1] \
            + I2OSP(len(a2), 2) + a2 \
            + I2OSP(len(a3), 2) + a3 \
            + I2OSP(len(challengeDST), 2) + challengeDST

        c = self.suite.group.hash_to_scalar(h2s_input)
        s = (r - c * self.skS) % self.suite.group.order()

        return [c, s], r

    def evaluate(self, blinded_element):
        R = self.suite.group.deserialize(blinded_element)
        Z = self.skS * R
        evaluated_element = self.suite.group.serialize(Z)
        proof, r = self.generate_proof([blinded_element], [evaluated_element])
        return evaluated_element, proof, r

    def evaluate_batch(self, blinded_elements):
        evaluated_elements = []
        for blinded_element in blinded_elements:
            R = self.suite.group.deserialize(blinded_element)
            Z = self.skS * R
            evaluated_element = self.suite.group.serialize(Z)
            evaluated_elements.append(evaluated_element)

        proof, r = self.generate_proof(blinded_elements, evaluated_elements)
        return evaluated_elements, proof, r

mode_base = 0x00
mode_verifiable = 0x01

def KeyGen(suite):
    skS, pkS = suite.group.key_gen()
    return skS, pkS

def SetupBaseServer(suite, skS):
    context_string = I2OSP(mode_base, 1) + I2OSP(suite.identifier, 2)
    return ServerContext(suite, context_string, skS, None)

def SetupBaseClient(suite):
    context_string = I2OSP(mode_base, 1) + I2OSP(suite.identifier, 2)
    return ClientContext(suite, context_string)

def SetupVerifiableServer(suite, skS, pkS):
    context_string = I2OSP(mode_verifiable, 1) + I2OSP(suite.identifier, 2)
    return VerifiableServerContext(suite, context_string, skS, pkS)

def SetupVerifiableClient(suite, pkS):
    context_string = I2OSP(mode_verifiable, 1) + I2OSP(suite.identifier, 2)
    return VerifiableClientContext(suite, context_string, pkS)

Ciphersuite = namedtuple("Ciphersuite", ["name", "identifier", "group", "H"])

ciphersuite_ristretto255_sha512 = 0x0001
ciphersuite_decaf448_sha512 = 0x0002
ciphersuite_p256_sha256 = 0x0003
ciphersuite_p384_sha512 = 0x0004
ciphersuite_p521_sha512 = 0x0005

oprf_ciphersuites = [
    Ciphersuite("OPRF(ristretto255, SHA-512)", ciphersuite_ristretto255_sha512, GroupRistretto255(), hashlib.sha512),
    Ciphersuite("OPRF(decaf448, SHA-512)", ciphersuite_decaf448_sha512, GroupDecaf448(), hashlib.sha512),
    Ciphersuite("OPRF(P-256, SHA-256)", ciphersuite_p256_sha256, GroupP256(), hashlib.sha256),
    Ciphersuite("OPRF(P-384, SHA-512)", ciphersuite_p384_sha512, GroupP384(), hashlib.sha512),
    Ciphersuite("OPRF(P-521, SHA-512)", ciphersuite_p521_sha512, GroupP521(), hashlib.sha512),
]
