#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import binascii

try:
    from sagelib.oprf                                                       \
    import KeyGen, SetupBaseServer, SetupBaseClient, SetupVerifiableServer, \
           SetupVerifiableClient, oprf_ciphersuites, _as_bytes, mode_base,  \
           mode_verifiable
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def to_hex_string(octet_string):
    if isinstance(octet_string, str):
        return "".join("{:02x}".format(ord(c)) for c in octet_string)
    assert isinstance(octet_string, (bytes, bytearray))
    return "0x" + "".join("{:02x}".format(c) for c in octet_string)

def to_hex(octet_string):
    if isinstance(octet_string, list):
        return ",".join([to_hex_string(x) for x in octet_string])
    return to_hex_string(octet_string)

class Protocol(object):
    def __init__(self, suite, mode):
        self.inputs = [b'\x00', b'\x5A'*17]
        self.suite = suite
        self.mode = mode
        skS, pkS = KeyGen(suite)
        if mode == mode_base:
            self.server = SetupBaseServer(suite, skS)
            self.client = SetupBaseClient(suite)
        elif mode == mode_verifiable:
            self.server = SetupVerifiableServer(suite, skS, pkS)
            self.client = SetupVerifiableClient(suite, pkS)
        else:
            raise Exception("bad mode")

    def run(self):
        group = self.client.suite.group
        client = self.client
        server = self.server
        info = "some_info".encode("utf-8")

        def create_test_vector_for_input(x):
            blind, blinded_element = client.blind(x)
            evaluated_element, proof = server.evaluate(blinded_element)
            unblinded_element = client.unblind(blind, evaluated_element, blinded_element, proof)
            output = client.finalize(x, unblinded_element, info)

            assert(server.verify_finalize(x, info, output))

            vector = {}
            vector["Blind"] = hex(blind)
            vector["BlindedElement"] = to_hex(blinded_element)
            vector["EvaluationElement"] = to_hex(evaluated_element)
            vector["UnblindedElement"] = to_hex(unblinded_element)

            if self.mode == mode_verifiable:
                vector["EvaluationProof"] = {
                    "c": hex(proof[0]),
                    "s": hex(proof[1]),
                }

            vector["Input"] = to_hex(x)
            vector["Info"] = to_hex(info)
            vector["Output"] = to_hex(output)
            vector["Batch"] = str(1)

            return vector

        def create_batched_test_vector_for_inputs(xs):
            blinds = []
            blinded_elements = []
            for x in xs:
                blind, blinded_element = client.blind(x)
                blinds.append(blind)
                blinded_elements.append(blinded_element)

            evaluated_elements, proof = server.evaluate_batch(blinded_elements)
            unblinded_elements = client.unblind_batch(blinds, evaluated_elements, blinded_elements, proof)

            outputs = []
            for i, unblinded_element in enumerate(unblinded_elements):
                output = client.finalize(xs[i], unblinded_element, info)
                assert(server.verify_finalize(xs[i], info, output))
                outputs.append(output)

            vector = {}
            vector["Blind"] = ",".join([hex(blind) for blind in blinds])
            vector["BlindedElement"] = to_hex(blinded_elements)
            vector["EvaluationElement"] = to_hex(evaluated_elements)
            vector["UnblindedElement"] = to_hex(unblinded_elements)

            if self.mode == mode_verifiable:
                vector["EvaluationProof"] = {
                    "c": hex(proof[0]),
                    "s": hex(proof[1]),
                }

            vector["Input"] = to_hex(xs)
            vector["Info"] = to_hex(info)
            vector["Output"] = to_hex(outputs)
            vector["Batch"] = str(len(xs))

            return vector

        vectors = [create_test_vector_for_input(x) for x in self.inputs]
        if self.mode == mode_verifiable:
            vectors.append(create_batched_test_vector_for_inputs(self.inputs))

        vecSuite = {}
        vecSuite["suite"] = self.suite.name
        vecSuite["mode"] = int(self.mode)
        vecSuite["hash"] = self.suite.H().name.upper()
        vecSuite["skSm"] = hex(server.skS)
        if self.mode == mode_verifiable:
            vecSuite["pkSm"] = to_hex(group.serialize(server.pkS))
        vecSuite["vectors"] = vectors

        return vecSuite

def wrap_write(fh, arg, *args):
    line_length = 68
    string = arg + " " + " ".join(args)
    for hunk in (string[0+i:line_length+i] for i in range(0, len(string), line_length)):
        if hunk and len(hunk.strip()) > 0:
            fh.write(hunk + "\n")

def write_blob(fh, name, blob):
    wrap_write(fh, name + ' = ' + to_hex(blob))

def write_value(fh, name, value):
    wrap_write(fh, name + ' = ' + value)

def write_base_vector(fh, vector):
    write_value(fh, "skSm", vector["skSm"])
    fh.write("\n")
    for i, v in enumerate(vector["vectors"]):
        fh.write("#### Test Vector " + str(i+1) + ", Batch Size " + v["Batch"] + "\n")
        fh.write("\n")
        write_value(fh, "Input", v["Input"])
        write_value(fh, "Blind", v["Blind"])
        write_value(fh, "BlindedElement", v["BlindedElement"])
        write_value(fh, "EvaluationElement", v["EvaluationElement"])
        write_value(fh, "UnblindedElement", v["UnblindedElement"])
        write_value(fh, "Info", v["Info"])
        write_value(fh, "Output", v["Output"])
        fh.write("\n")

def write_verifiable_vector(fh, vector):
    write_value(fh, "skSm", vector["skSm"])
    write_value(fh, "pkSm", vector["pkSm"])
    fh.write("\n")
    for i, v in enumerate(vector["vectors"]):
        fh.write("#### Test Vector " + str(i+1) + ", Batch Size " + v["Batch"] + "\n")
        fh.write("\n")
        write_value(fh, "Input", v["Input"])
        write_value(fh, "Blind", v["Blind"])
        write_value(fh, "BlindedElement", v["BlindedElement"])
        write_value(fh, "EvaluationElement", v["EvaluationElement"])
        write_value(fh, "UnblindedElement", v["UnblindedElement"])
        write_value(fh, "EvaluationProofC", v["EvaluationProof"]["c"])
        write_value(fh, "EvaluationProofS", v["EvaluationProof"]["s"])
        write_value(fh, "Info", v["Info"])
        write_value(fh, "Output", v["Output"])
        fh.write("\n")

def main(path="vectors"):
    allVectors = {}
    for suite in oprf_ciphersuites:
        suiteVectors = {}
        for mode in [mode_base, mode_verifiable]:
            protocol = Protocol(suite, mode)
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
                if mode == str(mode_base):
                    f.write("### Base Mode\n")
                    f.write("\n")
                    write_base_vector(f, allVectors[suite][mode])
                else:
                    f.write("### Verifiable Mode\n")
                    f.write("\n")
                    write_verifiable_vector(f, allVectors[suite][mode])

if __name__ == "__main__":
    main()
