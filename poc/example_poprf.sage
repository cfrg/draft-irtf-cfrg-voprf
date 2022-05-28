#!/usr/bin/sage
# vim: syntax=python

"""Exemplifies a run of the POPRF protocol"""

import os
import sys

try:
    from sagelib.test_drng import TestDRNG
    from sagelib.oprf \
    import DeriveKeyPair, SetupPOPRFServer, SetupPOPRFClient, MODE_POPRF, \
           oprf_ciphersuites, ciphersuite_p256_sha256

except ImportError as err:
    sys.exit("Try running `make setup && make clean pyfiles`. Full error: " + err)

to_hex = lambda x: "".join(["{:02x}".format(i) for i in x])

if __name__ == "__main__":
    # Offline Setup
    rng = TestDRNG('prng-seed'.encode('utf-8'))
    suite = oprf_ciphersuites[ciphersuite_p256_sha256]
    Ns = suite.group.scalar_byte_length()
    info = b'info specific for this key'
    seed = os.urandom(Ns)
    skS, pkS = DeriveKeyPair(MODE_POPRF, suite, seed, info)

    client = SetupPOPRFClient(suite, pkS)
    server = SetupPOPRFServer(suite, skS, pkS)

    # Online Protocol
    #
    # Client(pkS, info)        <---- pkS ------       Server(skS, info)
    #  -------------------------------------------------------------------
    #  blind, blindedElement, tweakedKey = Blind(input, info)
    input = b'alice in wonderland'
    blind, blinded_element, tweaked_key = client.blind(input, info, rng)
    #
    #                             blindedElement
    #                               ---------->
    #
    #        evaluatedElement, proof = BlindEvaluate(blindedElement, info)
    evaluated_element, proof, _ = server.blind_evaluate(blinded_element, info, rng)
    #
    #                         evaluatedElement, proof
    #                               <----------
    #
    #  output = Finalize(input, blind, evaluatedElement,
    #                    blindedElement, proof, info, tweakedKey)
    output = client.finalize(input, blind, evaluated_element, blinded_element, proof, info, tweaked_key)
    print("mode:", "POPRF")
    print("suite:", suite.name)
    print("input:", to_hex(input))
    print("output:", to_hex(output))
