#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import binascii

try:
    from sagelib.oprf \
    import DeriveKeyPair, \
           SetupOPRFServer, SetupOPRFClient, MODE_OPRF, \
           SetupVOPRFServer, SetupVOPRFClient, MODE_VOPRF, \
           SetupPOPRFServer, SetupPOPRFClient, MODE_POPRF, \
           oprf_ciphersuites, _as_bytes, \
           ciphersuite_ristretto255_sha512, \
           ciphersuite_decaf448_shake256, \
           ciphersuite_p256_sha256, \
           ciphersuite_p384_sha384, \
           ciphersuite_p521_sha512
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def to_hex_string(octet_string):
    if isinstance(octet_string, str):
        return "".join("{:02x}".format(ord(c)) for c in octet_string)
    assert isinstance(octet_string, (bytes, bytearray))
    return "".join("{:02x}".format(c) for c in octet_string)

def to_hex(octet_string):
    if isinstance(octet_string, list):
        return ",".join([to_hex_string(x) for x in octet_string])
    return to_hex_string(octet_string)

test_suites = [
    ciphersuite_ristretto255_sha512,
    ciphersuite_decaf448_shake256,
    ciphersuite_p256_sha256,
    ciphersuite_p384_sha384,
    ciphersuite_p521_sha512
]

class Protocol(object):
    def __init__(self, suite, mode, info):
        self.inputs = [b'\x00', b'\x5A'*17]
        self.suite = suite
        self.mode = mode
        self.info = info

        self.seed = b'\xA3' * suite.group.scalar_byte_length()
        skS, pkS = DeriveKeyPair(self.mode, self.suite, self.seed, info)
        if mode == MODE_OPRF:
            self.server = SetupOPRFServer(suite, skS)
            self.client = SetupOPRFClient(suite)
        elif mode == MODE_VOPRF:
            self.server = SetupVOPRFServer(suite, skS, pkS)
            self.client = SetupVOPRFClient(suite, pkS)
        elif mode == MODE_POPRF:
            self.server = SetupPOPRFServer(suite, skS, pkS)
            self.client = SetupPOPRFClient(suite, pkS)
        else:
            raise Exception("bad mode")

    def run(self):
        group = self.client.suite.group
        client = self.client
        server = self.server

        def create_test_vector_for_input(x, info):
            blind, blinded_element = client.blind(x)
            evaluated_element, proof, proof_randomness = server.evaluate(blinded_element, info)
            output = client.finalize(x, blind, evaluated_element, blinded_element, proof, info)

            assert(server.verify_finalize(x, output, info))

            vector = {}
            vector["Blind"] = to_hex(group.serialize_scalar(blind))
            vector["BlindedElement"] = to_hex(group.serialize(blinded_element))
            vector["EvaluationElement"] = to_hex(group.serialize(evaluated_element))

            if self.mode == MODE_VOPRF or self.mode == MODE_POPRF:
                vector["Proof"] = {
                    "proof": to_hex(group.serialize_scalar(proof[0]) + group.serialize_scalar(proof[1])),
                    "r": to_hex(group.serialize_scalar(proof_randomness)),
                }

            vector["Input"] = to_hex(x)
            if self.mode == MODE_POPRF:
                vector["Info"] = to_hex(info)
            vector["Output"] = to_hex(output)
            vector["Batch"] = int(1)

            return vector

        def create_batched_test_vector_for_inputs(xs, info):
            blinds = []
            blinded_elements = []
            for x in xs:
                blind, blinded_element = client.blind(x)
                blinds.append(blind)
                blinded_elements.append(blinded_element)

            evaluated_elements, proof, proof_randomness = server.evaluate_batch(blinded_elements, info)

            outputs = client.finalize_batch(xs, blinds, evaluated_elements, blinded_elements, proof, info)
            for i, output in enumerate(outputs):
                assert(server.verify_finalize(xs[i], output, info))

            vector = {}
            vector["Blind"] = ",".join([to_hex(group.serialize_scalar(blind)) for blind in blinds])
            vector["BlindedElement"] = to_hex(list(map(lambda e : group.serialize(e), blinded_elements)))
            vector["EvaluationElement"] = to_hex(list(map(lambda e : group.serialize(e), evaluated_elements)))

            if self.mode == MODE_VOPRF or self.mode == MODE_POPRF:
                vector["Proof"] = {
                    "proof": to_hex(group.serialize_scalar(proof[0]) + group.serialize_scalar(proof[1])),
                    "r": to_hex(group.serialize_scalar(proof_randomness)),
                }

            vector["Input"] = to_hex(xs)
            if self.mode == MODE_POPRF:
                vector["Info"] = to_hex(info)
            vector["Output"] = to_hex(outputs)
            vector["Batch"] = int(len(xs))

            return vector

        vectors = [create_test_vector_for_input(x, self.info) for x in self.inputs]
        if self.mode == MODE_VOPRF:
            vectors.append(create_batched_test_vector_for_inputs(self.inputs, self.info))

        vecSuite = {}
        vecSuite["suiteName"] = self.suite.name
        vecSuite["suiteID"] = int(self.suite.identifier)
        vecSuite["mode"] = int(self.mode)
        vecSuite["hash"] = self.suite.H().name.upper()
        vecSuite["seed"] = to_hex(self.seed)
        vecSuite["skSm"] = to_hex(group.serialize_scalar(server.skS))
        vecSuite["groupDST"] = to_hex(client.group_domain_separation_tag())
        if self.mode == MODE_VOPRF or self.mode == MODE_POPRF:
            vecSuite["pkSm"] = to_hex(group.serialize(server.pkS))
        vecSuite["vectors"] = vectors

        return vecSuite

def wrap_write(fh, arg, *args):
    line_length = 68
    string = " ".join( [arg] + list(args))
    for hunk in (string[0+i:line_length+i] for i in range(0, len(string), line_length)):
        if hunk and len(hunk.strip()) > 0:
            fh.write(hunk + "\n")

def write_blob(fh, name, blob):
    wrap_write(fh, name + ' = ' + to_hex(blob))

def write_value(fh, name, value):
    wrap_write(fh, name + ' = ' + value)

def write_oprf_vector(fh, vector):
    fh.write("~~~\n")
    write_value(fh, "seed", vector["seed"])
    write_value(fh, "skSm", vector["skSm"])
    fh.write("~~~\n")
    fh.write("\n")
    for i, v in enumerate(vector["vectors"]):
        fh.write("#### Test Vector " + str(i+1) + ", Batch Size " + str(v["Batch"]) + "\n")
        fh.write("\n")
        fh.write("~~~\n")
        write_value(fh, "Input", v["Input"])
        write_value(fh, "Blind", v["Blind"])
        write_value(fh, "BlindedElement", v["BlindedElement"])
        write_value(fh, "EvaluationElement", v["EvaluationElement"])
        write_value(fh, "Output", v["Output"])
        fh.write("~~~\n")
        fh.write("\n")

def write_voprf_vector(fh, vector):
    fh.write("~~~\n")
    write_value(fh, "seed", vector["seed"])
    write_value(fh, "skSm", vector["skSm"])
    write_value(fh, "pkSm", vector["pkSm"])
    fh.write("~~~\n")
    fh.write("\n")
    for i, v in enumerate(vector["vectors"]):
        fh.write("#### Test Vector " + str(i+1) + ", Batch Size " + str(v["Batch"]) + "\n")
        fh.write("\n")
        fh.write("~~~\n")
        write_value(fh, "Input", v["Input"])
        write_value(fh, "Blind", v["Blind"])
        write_value(fh, "BlindedElement", v["BlindedElement"])
        write_value(fh, "EvaluationElement", v["EvaluationElement"])
        write_value(fh, "Proof", v["Proof"]["proof"])
        write_value(fh, "ProofRandomScalar", v["Proof"]["r"])
        write_value(fh, "Output", v["Output"])
        fh.write("~~~\n")
        fh.write("\n")

def write_poprf_vector(fh, vector):
    fh.write("~~~\n")
    write_value(fh, "seed", vector["seed"])
    write_value(fh, "skSm", vector["skSm"])
    write_value(fh, "pkSm", vector["pkSm"])
    fh.write("~~~\n")
    fh.write("\n")
    for i, v in enumerate(vector["vectors"]):
        fh.write("#### Test Vector " + str(i+1) + ", Batch Size " + str(v["Batch"]) + "\n")
        fh.write("\n")
        fh.write("~~~\n")
        write_value(fh, "Input", v["Input"])
        write_value(fh, "Info", v["Info"])
        write_value(fh, "Blind", v["Blind"])
        write_value(fh, "BlindedElement", v["BlindedElement"])
        write_value(fh, "EvaluationElement", v["EvaluationElement"])
        write_value(fh, "Proof", v["Proof"]["proof"])
        write_value(fh, "ProofRandomScalar", v["Proof"]["r"])
        write_value(fh, "Output", v["Output"])
        fh.write("~~~\n")
        fh.write("\n")

mode_map = {
    MODE_OPRF: "OPRF",
    MODE_VOPRF: "VOPRF",
    MODE_POPRF: "POPRF",
}

def main(path="vectors"):
    allVectors = {}
    for suite_id in test_suites:
        suite = oprf_ciphersuites[suite_id]
        suiteVectors = {}
        for mode in [MODE_OPRF, MODE_VOPRF, MODE_POPRF]:
            protocol = Protocol(suite, mode, _as_bytes("test info"))
            suiteVectors[str(mode)] = protocol.run()
        allVectors[suite.name] = suiteVectors

    flatVectors = []
    for suite in allVectors:
        for mode in allVectors[suite]:
            flatVectors.append(allVectors[suite][mode])
    with open(path + "/allVectors.json", 'wt') as f:
        json.dump(flatVectors, f, sort_keys=True, indent=2)
        f.write("\n")

    with open(path + "/allVectors.txt", 'wt') as f:
        for suite in allVectors:
            f.write("## " + suite + "\n")
            f.write("\n")
            for mode in allVectors[suite]:
                if mode == str(MODE_OPRF):
                    f.write("### OPRF Mode\n")
                    f.write("\n")
                    write_oprf_vector(f, allVectors[suite][mode])
                elif mode == str(MODE_VOPRF):
                    f.write("### VOPRF Mode\n")
                    f.write("\n")
                    write_voprf_vector(f, allVectors[suite][mode])
                else:
                    f.write("### POPRF Mode\n")
                    f.write("\n")
                    write_poprf_vector(f, allVectors[suite][mode])

if __name__ == "__main__":
    main()
