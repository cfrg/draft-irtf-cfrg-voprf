#!/usr/bin/sage
# vim: syntax=python

"""Exemplifies a run of the OPRF protocol"""

import os
import sys

try:
    from sagelib.test_drng import TestDRNG
    from sagelib.oprf \
    import DeriveKeyPair, SetupOPRFServer, SetupOPRFClient, MODE_OPRF, \
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
    skS, _ = DeriveKeyPair(MODE_OPRF, suite, seed, info)

    client = SetupOPRFClient(suite)
    server = SetupOPRFServer(suite, skS)

    # Online Protocol
    #
    #   Client                                                Server(skS)
    # -------------------------------------------------------------------
    # blind, blindedElement = Blind(input)
    input = b'alice in wonderland'
    blind, blinded_element = client.blind(input, rng)
    #                            blindedElement
    #                              ---------->
    #
    #               evaluatedElement = BlindEvaluate(skS, blindedElement)
    evaluated_element = server.blind_evaluate(blinded_element, rng)
    #
    #                            evaluatedElement
    #                              <----------
    #
    # output = Finalize(input, blind, evaluatedElement)
    output = client.finalize(input, blind, evaluated_element)
    print("mode:", "OPRF")
    print("suite:", suite.name)
    print("input:", to_hex(input))
    print("output:", to_hex(output))
