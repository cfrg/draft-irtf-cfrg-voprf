#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import hashlib
import binascii

from collections import namedtuple

from hash_to_field import I2OSP

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

    def finalize(self, x, blind, evaluated_element, blinded_element, proof):
        unblinded_element = self.unblind(blind, evaluated_element, blinded_element, proof)
        finalizeDST = _as_bytes("VOPRF06-Finalize-") + self.context_string
        finalize_input = I2OSP(len(x), 2) + x \
            + I2OSP(len(unblinded_element), 2) + unblinded_element \
            + I2OSP(len(finalizeDST), 2) + finalizeDST

        h = self.suite.H()
        h.update(finalize_input)
        if self.suite.name == "OPRF(decaf448, SHAKE-256)":
           return h.digest(int(56))
        else:
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

    def verify_finalize(self, x, expected_digest):
        P = self.suite.group.hash_to_group(x, self.group_domain_separation_tag())
        input_element = self.suite.group.serialize(P)
        issued_element, _, _ = self.evaluate(input_element) # Ignore the proof output

        finalizeDST = _as_bytes("VOPRF06-Finalize-") + self.context_string
        finalize_input = I2OSP(len(x), 2) + x \
            + I2OSP(len(issued_element), 2) + issued_element \
            + I2OSP(len(finalizeDST), 2) + finalizeDST

        h = self.suite.H()
        h.update(finalize_input)
        if self.suite.name == "OPRF(decaf448, SHAKE-256)":
           digest = h.digest(int(56))
        else:
           digest = h.digest()

        return (digest == expected_digest)

class Verifiable(object):
    def compute_composites_inner(self, k, B, Cs, Ds):
        assert(len(Cs) == len(Ds))

        seedDST = _as_bytes("VOPRF06-Seed-") + self.context_string
        compositeDST = _as_bytes("VOPRF06-Composite-") + self.context_string
        Bm = self.suite.group.serialize(B)

        h1_input = I2OSP(len(Bm), 2) + Bm \
            + I2OSP(len(seedDST), 2) + seedDST
        h = self.suite.H()
        h.update(h1_input)
        if self.suite.name == "OPRF(decaf448, SHAKE-256)":
           seed = h.digest(int(56))
        else:
           seed = h.digest()

        M = self.suite.group.identity()
        Z = self.suite.group.identity()

        for i in range(len(Cs)):
            Ci = self.suite.group.serialize(Cs[i])
            Di = self.suite.group.serialize(Ds[i])
            h2_input = I2OSP(len(seed), 2) + seed \
                + I2OSP(i, 2) \
                + I2OSP(len(Ci), 2) + Ci \
                + I2OSP(len(Di), 2) + Di \
                + I2OSP(len(compositeDST), 2) + compositeDST

            di = self.suite.group.hash_to_scalar(h2_input, _as_bytes("VOPRF06-HashToScalar-") + self.context_string)
            M = (di * Cs[i]) + M

            if k == None:
                Z = (di * Ds[i]) + Z

        if k != None:
            Z = k * M

        return [M, Z]

    def compute_composites_fast(self, k, B, Cs, Ds):
        return self.compute_composites_inner(k, B, Cs, Ds)

    def compute_composites(self, B, Cs, Ds):
        return self.compute_composites_inner(None, B, Cs, Ds)

class VerifiableClientContext(ClientContext,Verifiable):
    def __init__(self, suite, context_string, pkS):
        ClientContext.__init__(self, suite, context_string)
        self.pkS = pkS

    def verify_proof(self, A, B, Cs, Ds, proof):
        a = self.compute_composites(B, Cs, Ds)

        M = a[0]
        Z = a[1]
        t2 = (proof[1] * A) + (proof[0] * B)
        t3 = (proof[1] * M) + (proof[0] * Z)

        Bm = self.suite.group.serialize(B)
        a0 = self.suite.group.serialize(M)
        a1 = self.suite.group.serialize(Z)
        a2 = self.suite.group.serialize(t2)
        a3 = self.suite.group.serialize(t3)

        challengeDST = _as_bytes("VOPRF06-Challenge-") + self.context_string
        h2s_input = I2OSP(len(Bm), 2) + Bm \
            + I2OSP(len(a0), 2) + a0 \
            + I2OSP(len(a1), 2) + a1 \
            + I2OSP(len(a2), 2) + a2 \
            + I2OSP(len(a3), 2) + a3 \
            + I2OSP(len(challengeDST), 2) + challengeDST

        c = self.suite.group.hash_to_scalar(h2s_input, _as_bytes("VOPRF06-HashToScalar-") + self.context_string)

        assert(c == proof[0])
        return c == proof[0]

    def unblind(self, blind, evaluated_element, blinded_element, proof):
        G = self.suite.group.generator()
        R = self.suite.group.deserialize(blinded_element)
        Z = self.suite.group.deserialize(evaluated_element)
        if not self.verify_proof(G, self.pkS, [R], [Z], proof):
            raise Exception("Proof verification failed")

        blind_inv = inverse_mod(blind, self.suite.group.order())
        N = blind_inv * Z
        unblinded_element = self.suite.group.serialize(N)
        return unblinded_element

    def unblind_batch(self, blinds, evaluated_elements, blinded_elements, proof):
        assert(len(blinds) == len(evaluated_elements))
        assert(len(evaluated_elements) == len(blinded_elements))

        G = self.suite.group.generator()
        Rs = []
        Zs = []
        for i, _ in enumerate(blinded_elements):
            R = self.suite.group.deserialize(blinded_elements[i])
            Z = self.suite.group.deserialize(evaluated_elements[i])
            Rs.append(R)
            Zs.append(Z)
        if not self.verify_proof(G, self.pkS, Rs, Zs, proof):
            raise Exception("Proof verification failed")

        unblinded_elements = []
        for i, evaluated_element in enumerate(evaluated_elements):
            Z = self.suite.group.deserialize(evaluated_element)
            blind_inv = inverse_mod(blinds[i], self.suite.group.order())
            N = blind_inv * Z
            unblinded_element = self.suite.group.serialize(N)
            unblinded_elements.append(unblinded_element)

        return unblinded_elements

    def finalize_batch(self, xs, blinds, evaluated_elements, blinded_elements, proof):
        assert(len(blinds) == len(evaluated_elements))
        assert(len(evaluated_elements) == len(blinded_elements))

        unblinded_elements = self.unblind_batch(blinds, evaluated_elements, blinded_elements, proof)

        outputs = []
        finalizeDST = _as_bytes("VOPRF06-Finalize-") + self.context_string
        for i, unblinded_element in enumerate(unblinded_elements):
            finalize_input = I2OSP(len(xs[i]), 2) + xs[i] \
                + I2OSP(len(unblinded_element), 2) + unblinded_element \
                + I2OSP(len(finalizeDST), 2) + finalizeDST

            h = self.suite.H()
            h.update(finalize_input)

            if self.suite.name == "OPRF(decaf448, SHAKE-256)":
               outputs.append(h.digest(int(56)))
            else:
               outputs.append(h.digest())

        return outputs

class VerifiableServerContext(ServerContext,Verifiable):
    def __init__(self, suite, context_string, skS, pkS):
        ServerContext.__init__(self, suite, context_string, skS, pkS)

    def generate_proof(self, k, A, B, Cs, Ds):
        a = self.compute_composites_fast(k, B, Cs, Ds)

        r = ZZ(self.suite.group.random_scalar())
        M = a[0]
        Z = a[1]
        t2 = r * A
        t3 = r * M

        Bm = self.suite.group.serialize(B) 
        a0 = self.suite.group.serialize(M)
        a1 = self.suite.group.serialize(Z)
        a2 = self.suite.group.serialize(t2)
        a3 = self.suite.group.serialize(t3)

        challengeDST = _as_bytes("VOPRF06-Challenge-") + self.context_string
        h2s_input = I2OSP(len(Bm), 2) + Bm \
            + I2OSP(len(a0), 2) + a0 \
            + I2OSP(len(a1), 2) + a1 \
            + I2OSP(len(a2), 2) + a2 \
            + I2OSP(len(a3), 2) + a3 \
            + I2OSP(len(challengeDST), 2) + challengeDST

        c = self.suite.group.hash_to_scalar(h2s_input, _as_bytes("VOPRF06-HashToScalar-") + self.context_string)
        s = (r - c * k) % self.suite.group.order()

        return [c, s], r

    def evaluate(self, blinded_element):
        R = self.suite.group.deserialize(blinded_element)
        Z = self.skS * R
        evaluated_element = self.suite.group.serialize(Z)
        proof, r = self.generate_proof(self.skS, self.suite.group.generator(), self.pkS, [R], [Z])
        return evaluated_element, proof, r

    def evaluate_batch(self, blinded_elements):
        Rs = []
        Zs = []
        evaluated_elements = []
        for blinded_element in blinded_elements:
            R = self.suite.group.deserialize(blinded_element)
            Z = self.skS * R
            Rs.append(R)
            Zs.append(Z)
            evaluated_element = self.suite.group.serialize(Z)
            evaluated_elements.append(evaluated_element)

        proof, r = self.generate_proof(self.skS, self.suite.group.generator(), self.pkS, Rs, Zs)
        return evaluated_elements, proof, r

mode_base = 0x00
mode_verifiable = 0x01

def GenerateKeyPair(suite):
    skS, pkS = suite.group.key_gen()
    return skS, pkS

def DeriveKeyPair(suite, seed):
    skS = suite.group.hash_to_scalar(seed)
    pkS = skS * suite.group.generator()
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
ciphersuite_decaf448_shake256 = 0x0002
ciphersuite_p256_sha256 = 0x0003
ciphersuite_p384_sha512 = 0x0004
ciphersuite_p521_sha512 = 0x0005

oprf_ciphersuites = {
    ciphersuite_ristretto255_sha512: Ciphersuite("OPRF(ristretto255, SHA-512)", ciphersuite_ristretto255_sha512, GroupRistretto255(), hashlib.sha512),
    ciphersuite_decaf448_shake256: Ciphersuite("OPRF(decaf448, SHAKE-256)", ciphersuite_decaf448_shake256, GroupDecaf448(), hashlib.shake_256),
    ciphersuite_p256_sha256: Ciphersuite("OPRF(P-256, SHA-256)", ciphersuite_p256_sha256, GroupP256(), hashlib.sha256),
    ciphersuite_p384_sha512: Ciphersuite("OPRF(P-384, SHA-512)", ciphersuite_p384_sha512, GroupP384(), hashlib.sha512),
    ciphersuite_p521_sha512: Ciphersuite("OPRF(P-521, SHA-512)", ciphersuite_p521_sha512, GroupP521(), hashlib.sha512),
}
