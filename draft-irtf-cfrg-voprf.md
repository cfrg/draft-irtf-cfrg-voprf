---
title: Oblivious Pseudorandom Functions (OPRFs) using Prime-Order Groups
abbrev: OPRFs
docname: draft-irtf-cfrg-voprf-latest
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: A. Davidson
    name: Alex Davidson
    email: alex.davidson92@gmail.com
 -
    ins: A. Faz-Hernandez
    name: Armando Faz-Hernandez
    org: Cloudflare
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: armfazh@cloudflare.com
 -
    ins: N. Sullivan
    name: Nick Sullivan
    org: Cloudflare
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: nick@cloudflare.com
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: caw@heapingbits.net

normative:
  RFC2119:
  RFC7748:
  PrivacyPass:
    title: Privacy Pass
    target: https://github.com/privacypass/challenge-bypass-server
    date: false
  BB04:
    title: Short Signatures Without Random Oracles
    target: http://ai.stanford.edu/~xb/eurocrypt04a/bbsigs.pdf
    date: false
    authors:
      -
        ins: D. Boneh
        org: Stanford University, CA, USA
      -
        ins: X. Boyen
        org: Voltage Security, Palo Alto, CA, USA
  BG04:
    title: The Static Diffie-Hellman Problem
    target: https://eprint.iacr.org/2004/306
    date: false
    authors:
      -
        ins: D. Brown
        org: Certicom Research
      -
        ins: R. Gallant
        org: Certicom Research
  Cheon06:
    title: Security Analysis of the Strong Diffie-Hellman Problem
    target: https://www.iacr.org/archive/eurocrypt2006/40040001/40040001.pdf
    date: false
    authors:
      -
        ins: J. H. Cheon
        org: Seoul National University, Republic of Korea
  JKKX16:
    title: Highly-Efficient and Composable Password-Protected Secret Sharing (Or, How to Protect Your Bitcoin Wallet Online)
    target: https://eprint.iacr.org/2016/144
    date: false
    authors:
      -
        ins: S. Jarecki
        org: UC Irvine, CA, USA
      -
        ins: A. Kiayias
        org: University of Athens, Greece
      -
        ins: H. Krawczyk
        org: IBM Research, NY, USA
      -
        ins: Jiayu Xu
        org: UC Irvine, CA, USA
  JKK14:
    title:  Round-Optimal Password-Protected Secret Sharing and T-PAKE in the Password-Only model
    target: https://eprint.iacr.org/2014/650
    date: false
    authors:
      -
        ins: S. Jarecki
        org: UC Irvine, CA, USA
      -
        ins: A. Kiayias
        org: University of Athens, Greece
      -
        ins: H. Krawczyk
        org: IBM Research, NY, USA
  SJKS17:
    title:  SPHINX, A Password Store that Perfectly Hides from Itself
    target: https://eprint.iacr.org/2018/695
    date: false
    authors:
      -
        ins: M. Shirvanian
        org: University of Alabama at Birmingham, USA
      -
        ins: S. Jarecki
        org: UC Irvine, CA, USA
      -
        ins: H. Krawczyk
        org: IBM Research, NY, USA
      -
        ins: N. Saxena
        org: University of Alabama at Birmingham, USA
  DGSTV18:
    title: Privacy Pass, Bypassing Internet Challenges Anonymously
    target: https://www.degruyter.com/view/j/popets.2018.2018.issue-3/popets-2018-0026/popets-2018-0026.xml
    date: false
    authors:
      -
        ins: A. Davidson
        org: RHUL, UK
      -
        ins: I. Goldberg
        org: University of Waterloo, Canada
      -
        ins: N. Sullivan
        org: Cloudflare, CA, USA
      -
        ins: G. Tankersley
        org: Independent
      -
        ins: F. Valsorda
        org: Independent
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography"
    target: https://www.secg.org/sec1-v2.pdff
    date: false
    author:
      -
        ins: Standards for Efficient Cryptography Group (SECG)
  SEC2:
    title: "SEC 2: Recommended Elliptic Curve Domain Parameters"
    target: http://www.secg.org/sec2-v2.pdf
    date: false
    author:
      -
        ins: Standards for Efficient Cryptography Group (SECG)
  x9.62:
    title: "Public Key Cryptography for the Financial Services Industry: the Elliptic Curve Digital Signature Algorithm (ECDSA)"
    date: Sep, 1998
    seriesinfo:
      "ANSI": X9.62-1998
    author:
      -
        org: ANSI

--- abstract

An Oblivious Pseudorandom Function (OPRF) is a two-party protocol for
computing the output of a PRF. One party (the server) holds the PRF
secret key, and the other (the client) holds the PRF input. The
'obliviousness' property ensures that the server does not learn anything
about the client's input during the evaluation. The client should also
not learn anything about the server's secret PRF key. Optionally, OPRFs
can also satisfy a notion 'verifiability' (VOPRF). In this setting, the
client can verify that the server's output is indeed the result of
evaluating the underlying PRF with just a public key. This document
specifies OPRF and VOPRF constructions instantiated within prime-order
groups, including elliptic curves.

--- middle

# Introduction

A pseudorandom function (PRF) F(k, x) is an efficiently computable
function taking a private key k and a value x as input. This function is
pseudorandom if the keyed function K(\_) = F(K, \_) is indistinguishable
from a randomly sampled function acting on the same domain and range as
K(). An oblivious PRF (OPRF) is a two-party protocol between a server
and a client, where the server holds a PRF key k and the client holds
some input x. The protocol allows both parties to cooperate in computing
F(k, x) such that: the client learns F(k, x) without learning anything
about k; and the server does not learn anything about x or F(k, x).
A Verifiable OPRF (VOPRF) is an OPRF wherein the server can prove to the
client that F(k, x) was computed using the key k.

The usage of OPRFs has been demonstrated in constructing a number of
applications: password-protected secret sharing schemes {{JKKX16}};
privacy-preserving password stores {{SJKS17}}; and
password-authenticated key exchange or PAKE {{!I-D.irtf-cfrg-opaque}}. A VOPRF is
necessary in some applications, e.g., the Privacy Pass protocol
{{!I-D.davidson-pp-protocol}}, wherein this VOPRF is used to generate
one-time authentication tokens to bypass CAPTCHA challenges. VOPRFs have
also been used for password-protected secret sharing schemes e.g.
{{JKK14}}.

This document introduces an OPRF protocol built in prime-order groups,
applying to finite fields of prime-order and also elliptic curve (EC)
groups. The protocol has the option of being extended to a VOPRF with
the addition of a NIZK proof for proving discrete log equality
relations. This proof demonstrates correctness of the computation, using
a known public key that serves as a commitment to the server's secret
key. The document describes the protocol, the public-facing API, and its
security properties.

## Change log

[draft-05](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-05):

- Move to ristretto255 and decaf448 ciphersuites.
- Clean up ciphersuite definitions.
- Pin domain separation tag construction to draft version.
- Move key generation outside of context construction functions.
- Editorial changes.

[draft-04](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-04):

- Introduce Client and Server contexts for controlling verifiability and
  required functionality.
- Condense API.
- Remove batching from standard functionality (included as an extension)
- Add Curve25519 and P-256 ciphersuites for applications that prevent
  strong-DH oracle attacks.
- Provide explicit prime-order group API and instantiation advice for
  each ciphersuite.
- Proof-of-concept implementation in sage.
- Remove privacy considerations advice as this depends on applications.

[draft-03](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-03):

- Certify public key during VerifiableFinalize.
- Remove protocol integration advice.
- Add text discussing how to perform domain separation.
- Drop OPRF_/VOPRF_ prefix from algorithm names.
- Make prime-order group assumption explicit.
- Changes to algorithms accepting batched inputs.
- Changes to construction of batched DLEQ proofs.
- Updated ciphersuites to be consistent with hash-to-curve and added
  OPRF specific ciphersuites.

[draft-02](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-02):

- Added section discussing cryptographic security and static DH oracles.
- Updated batched proof algorithms.

[draft-01](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-01):

- Updated ciphersuites to be in line with
  https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04.
- Made some necessary modular reductions more explicit.

## Terminology {#terminology}

The following terms are used throughout this document.

- PRF: Pseudorandom Function.
- OPRF: Oblivious Pseudorandom Function.
- VOPRF: Verifiable Oblivious Pseudorandom Function.
- Client: Protocol initiator. Learns pseudorandom function evaluation as
  the output of the protocol.
- Server: Computes the pseudorandom function over a secret key. Learns
  nothing about the client's input.
- NIZK: Non-interactive zero knowledge.
- DLEQ: Discrete Logarithm Equality.

## Requirements

{::boilerplate bcp14}

# Preliminaries

The (V)OPRF protocol in this document has two primary dependencies:

- `GG`: A prime-order group implementing the API described below in {{pog}},
  with base point defined in the corresponding reference for each group.
  (See {{ciphersuites}} for these base points.)
- `Hash`: A cryptographic hash function that is indifferentiable from a
  Random Oracle, whose output length is Nh bytes long.

{{ciphersuites}} specifies ciphersuites as combinations of `GG` and `Hash`.

## Prime-Order Group Dependency {#pog}

In this document, we assume the construction of an additive, prime-order
group `GG` for performing all mathematical operations. Such groups are
uniquely determined by the choice of the prime `p` that defines the
order of the group. We use `GF(p)` to represent the finite field of
order `p`. For the purpose of understanding and implementing this
document, we take `GF(p)` to be equal to the set of integers defined by
`{0, 1, ..., p-1}`.

The fundamental group operation is addition `+` with identity element
`I`. For any elements `A` and `B` of the group `GG`, `A + B = B + A` is
also a member of `GG`. Also, for any `A` in `GG`, there exists an element
`-A` such that `A + (-A) = (-A) + A = I`. Scalar multiplication is
equivalent to the repeated application of the group operation on an
element A with itself `r-1` times, this is denoted as `r*A = A + ... + A`.
For any element `A`, `p*A=I`. Scalar base multiplication is equivalent to
the repeated application of the group operation on the base point with
itself `r-1` times, this is denoted as `ScalarBaseMult(r)`. The set of
scalars corresponds to `GF(p)`.

We now detail a number of member functions that can be invoked on a
prime-order group `GG`.

- Order(): Outputs the order of `GG` (i.e. `p`).
- Identity(): Outputs the identity element of the group (i.e. `I`).
- HashToGroup(x): A member function of `GG` that deterministically maps
  an array of bytes `x` to an element of `GG`. The map must ensure that,
  for any adversary receiving `R = HashToGroup(x)`, it is
  computationally difficult to reverse the mapping. Examples of hash to
  group functions satisfying this property are described for prime-order
  (sub)groups of elliptic curves, see {{!I-D.irtf-cfrg-hash-to-curve}}.
- HashToScalar(x): A member function of `GG` that deterministically maps
  an array of bytes `x` to an element in GF(p). A recommended method
  for its implementation is instantiating the hash to field function,
  defined in {{!I-D.irtf-cfrg-hash-to-curve}} setting the target field to GF(p).
- RandomScalar(): A member function of `GG` that chooses at random a
  non-zero element in GF(p).
- SerializeElement(A): A member function of `GG` that maps a group element `A`
  to a unique byte array `buf` of fixed length `Ne`.
- DeserializeElement(buf): A member function of `GG` that maps a byte array
  `buf` to a group element `A`, or fails if the input is not a valid
  byte representation of an element.
- SerializeScalar(s): A member function of `GG` that maps a scalar element `s`
  to a unique byte array `buf` of fixed length `Ns`.
- DeserializeScalar(buf): A member function of `GG` that maps a byte array
  `buf` to a scalar `s`, or fails if the input is not a valid byte
  representation of a scalar.

Using the API of a prime-order group, we assume the existence of a function
`GenerateKeyPair()` that generates a random private and public key pair
(`skS`, `pkS`). One possible implementation might be to compute
`skS = RandomScalar()` and `pkS = ScalarBaseMult(skS)`. We also assume the
existence of a `DeriveKeyPair(seed)` function that deterministically generates
a private and public key pair from input `seed`, where `seed` is a random
byte string that SHOULD have at least `Ns` bytes of entropy.
`DeriveKeyPair(seed)` computes `skS = HashToScalar(seed)` and
`pkS = ScalarBaseMult(skS)`.

It is convenient in cryptographic applications to instantiate such
prime-order groups using elliptic curves, such as those detailed in
{{SEC2}}. For some choices of elliptic curves (e.g. those detailed in
{{RFC7748}}, which require accounting for cofactors) there are some
implementation issues that introduce inherent discrepancies between
standard prime-order groups and the elliptic curve instantiation. In
this document, all algorithms that we detail assume that the group is a
prime-order group, and this MUST be upheld by any implementer. That is,
any curve instantiation should be written such that any discrepancies
with a prime-order group instantiation are removed. See {{ciphersuites}}
for advice corresponding to the implementation of this interface for
specific definitions of elliptic curves.

## Other Conventions

- For any object `x`, we write `len(x)` to denote its length in bytes.
- For two byte arrays `x` and `y`, write `x || y` to denote their
  concatenation.
- I2OSP and OS2IP: Convert a byte array to and from a non-negative
  integer as described in {{!RFC8017}}. Note that these functions
  operate on byte arrays in big-endian byte order.

All algorithm descriptions are written in a Python-like pseudocode. We
use the `ABORT()` function for presentational clarity to denote the
process of terminating the algorithm or returning an error accordingly.
We also use the `CT_EQUAL(a, b)` function to represent constant-time
byte-wise equality between byte arrays `a` and `b`. This function
returns `true` if `a` and `b` are equal, and `false` otherwise.

# OPRF Protocol {#protocol}

In this section, we define two OPRF variants: a base mode and verifiable
mode. In the base mode, a client and server interact to compute y =
F(skS, x), where x is the client's input, skS is the server's private
key, and y is the OPRF output. The client learns y and the server learns
nothing. In the verifiable mode, the client also gets proof that the
server used skS in computing the function.

To achieve verifiability, as in the original work of {{JKK14}}, we
provide a zero-knowledge proof that the key provided as input by the
server in the `Evaluate` function is the same key as it used to produce
their public key. As an example of the nature of attacks that this
prevents, this ensures that the server uses the same private key for
computing the VOPRF output and does not attempt to "tag" individual
servers with select keys. This proof must not reveal the server's
long-term private key to the client.

The following one-byte values distinguish between these two modes:

| Mode           | Value |
|:===============|:======|
| modeBase       | 0x00  |
| modeVerifiable | 0x01  |

## Overview {#protocol-overview}

Both participants agree on the mode and a choice of ciphersuite that is
used before the protocol exchange. Once established, the core protocol
runs to compute `output = F(skS, input)` as follows:

~~~
   Client(pkS, input)                     Server(skS, pkS)
  ----------------------------------------------------------
    blind, blindedElement = Blind(input)

                       blindedElement
                        ---------->

    evaluatedElement, proof = Evaluate(skS, pkS, blindedElement)

                  evaluatedElement, proof
                        <----------

    output = Finalize(input, blind, evaluatedElement, blindedElement, pkS, proof)
~~~

In `Blind` the client generates a token and blinding data. The server
computes the (V)OPRF evaluation in `Evaluation` over the client's
blinded token. In `Finalize` the client unblinds the server response,
verifies the server's proof if verifiability is required, and produces
a byte array corresponding to the output of the OPRF protocol.

## Context Setup

Both modes of the OPRF involve an offline setup phase. In this phase,
both the client and server create a context used for executing the
online phase of the protocol. Prior to this phase, the key pair
(`skS`, `pkS`) should be generated by calling `GenerateKeyPair()`
or `DeriveKeyPair()` appropriately.

The base mode setup functions for creating client and server contexts are below:

~~~
def SetupBaseServer(suite, skS):
  contextString = I2OSP(modeBase, 1) || I2OSP(suite.ID, 2)
  return ServerContext(contextString, skS)

def SetupBaseClient(suite):
  contextString = I2OSP(modeBase, 1) || I2OSP(suite.ID, 2)
  return ClientContext(contextString)
~~~

The verifiable mode setup functions for creating client and server
contexts are below:

~~~
def SetupVerifiableServer(suite, skS, pkS):
  contextString = I2OSP(modeVerifiable, 1) || I2OSP(suite.ID, 2)
  return VerifiableServerContext(contextString, skS)

def SetupVerifiableClient(suite, pkS):
  contextString = I2OSP(modeVerifiable, 1) || I2OSP(suite.ID, 2)
  return VerifiableClientContext(contextString, pkS)
~~~

Each setup function takes a ciphersuite from the list defined in
{{ciphersuites}}. Each ciphersuite has a two-byte field ID used to
identify the suite.

## Data Types {#structs}

The following is a list of data structures that are defined for
providing inputs and outputs for each of the context interfaces defined
in {{api}}. Data structure description uses TLS notation (see {{?RFC8446}},
Section 3).

This document uses the types `Element` and `Scalar` to denote elements of the
group `GG` and its underlying scalar field `GF(p)`, respectively. For notational
clarity, `PublicKey` is an item of type `Element` and `PrivateKey` is an item
of type `Scalar`. `SerializedElement` and `SerializedScalar` are serialized
representations of `Element` and `Scalar` types of length `Ne` and `Ns`,
respectively; see {{pog}}. `ClientInput` is an opaque byte string of arbitrary
length. `Proof` is a sequence of two `SerializedScalar` elements, as shown below.

~~~
SerializedScalar Proof[2];
~~~

## Context APIs {#api}

In this section, we detail the APIs available on the client and server
(V)OPRF contexts.

### Server Context

The ServerContext encapsulates the context string constructed during
setup and the (V)OPRF key pair. It has three functions, `Evaluate`,
`FullEvaluate` and `VerifyFinalize` described below. `Evaluate` takes
serialized representations of blinded group elements from the client as inputs.

`FullEvaluate` takes ClientInput values, and it is useful for applications
that need to compute the whole OPRF protocol on the server side only.

`VerifyFinalize` takes ClientInput values and their corresponding output
digests from `Finalize` as input, and returns true if the inputs match the outputs.

Note that `VerifyFinalize` and `FullEvaluate` are not used in the main OPRF
protocol. They are exposed as an API for building higher-level protocols.

#### Evaluate

~~~
Input:

  PrivateKey skS
  SerializedElement blindedElement

Output:

  SerializedElement evaluatedElement

def Evaluate(skS, blindedElement):
  R = GG.DeserializeElement(blindedElement)
  Z = skS * R
  evaluatedElement = GG.SerializeElement(Z)

  return evaluatedElement
~~~

#### FullEvaluate

~~~
Input:

  PrivateKey skS
  ClientInput input

Output:

  opaque output[Nh]

def FullEvaluate(skS, input):
  P = GG.HashToGroup(input)
  T = skS * P
  issuedElement = GG.SerializeElement(T)

  finalizeDST = "VOPRF06-Finalize-" || self.contextString
  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(issuedElement), 2) || issuedElement ||
              I2OSP(len(finalizeDST), 2) || finalizeDST

  return Hash(hashInput)
~~~

[[RFC editor: please change "VOPRF06" to "RFCXXXX", where XXXX is the final number, here and elsewhere before publication.]]

#### VerifyFinalize

~~~
Input:

  PrivateKey skS
  ClientInput input
  opaque output[Nh]

Output:

  boolean valid

def VerifyFinalize(skS, input, output):
  T = GG.HashToGroup(input)
  element = GG.SerializeElement(T)
  issuedElement = Evaluate(skS, [element])
  E = GG.SerializeElement(issuedElement)

  finalizeDST = "VOPRF06-Finalize-" || self.contextString
  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(E), 2) || E ||
              I2OSP(len(finalizeDST), 2) || finalizeDST

  digest = Hash(hashInput)

  return CT_EQUAL(digest, output)
~~~

[[RFC editor: please change "VOPRF06" to "RFCXXXX", where XXXX is the final number, here and elsewhere before publication.]]

### VerifiableServerContext

The VerifiableServerContext extends the base ServerContext with an
augmented `Evaluate()` function. This function produces a proof that
`skS` was used in computing the result. It makes use of the helper
functions `GenerateProof` and `ComputeComposites`, described below.

#### Evaluate

~~~
Input:

  PrivateKey skS
  PublicKey pkS
  SerializedElement blindedElement

Output:

  SerializedElement evaluatedElement
  Proof proof

def Evaluate(skS, pkS, blindedElement):
  R = GG.DeserializeElement(blindedElement)
  Z = skS * R
  evaluatedElement = GG.SerializeElement(Z)

  proof = GenerateProof(skS, pkS, blindedElement, evaluatedElement)

  return evaluatedElement, proof
~~~

The helper functions `GenerateProof` and `ComputeComposites` are defined
below.

#### GenerateProof

~~~
Input:

  PrivateKey skS
  PublicKey pkS
  SerializedElement blindedElement
  SerializedElement evaluatedElement

Output:

  Proof proof

def GenerateProof(skS, pkS, blindedElement, evaluatedElement)
  blindedElementList = [blindedElement]
  evaluatedElementList = [evaluatedElement]

  a = ComputeCompositesFast(skS, pkS, blindedElementList, evaluatedElementList)

  M = GG.DeserializeElement(a[0])
  r = GG.RandomScalar()
  a2 = GG.SerializeElement(ScalarBaseMult(r))
  a3 = GG.SerializeElement(r * M)

  pkSm = GG.SerializeElement(pkS)
  challengeDST = "VOPRF06-Challenge-" || self.contextString
  h2Input = I2OSP(len(pkSm), 2) || pkSm ||
            I2OSP(len(a[0]), 2) || a[0] ||
            I2OSP(len(a[1]), 2) || a[1] ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            I2OSP(len(challengeDST), 2) || challengeDST

  c = GG.HashToScalar(h2Input)
  s = (r - c * skS) mod p
  proof = [GG.SerializeScalar(c), GG.SerializeScalar(s)]

  return proof
~~~

##### Batching inputs

Unlike other functions, `ComputeComposites` takes lists of inputs,
rather than a single input. Applications can take advantage of this
functionality by invoking `GenerateProof` on batches of inputs to
produce a combined, constant-size proof. (In the pseudocode above,
the single inputs `blindedElement` and `evaluatedElement` are passed as
one-item lists to `ComputeComposites`.)

In particular, servers can produce a single, constant-sized proof for N
client inputs sent in a single request, rather than one proof per client
input. This optimization benefits clients and servers since it amortizes
the cost of proof generation and bandwidth across multiple requests.

##### Fresh Randomness

We note here that it is essential that a different `r` value is used for
every invocation. If this is not done, then this may leak `skS` as is
possible in Schnorr or (EC)DSA scenarios where fresh randomness is not
used.

#### ComputeComposites

The definition of `ComputeComposites` is given below. This function is
used both on generation and verification of the proof.

~~~
Input:

  PublicKey pkS
  SerializedElement blindedElements[m]
  SerializedElement evaluatedElements[m]

Output:

  SerializedElement composites[2]

def ComputeComposites(pkS, blindedElements, evaluatedElements):
  pkSm = GG.SerializeElement(pkS)
  seedDST = "VOPRF06-Seed-" || self.contextString
  compositeDST = "VOPRF06-Composite-" || self.contextString
  h1Input = I2OSP(len(pkSm), 2) || pkSm ||
            I2OSP(len(seedDST), 2) || seedDST

  seed = Hash(h1Input)
  M = GG.Identity()
  Z = GG.Identity()
  for i = 0 to m-1:
    h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
              I2OSP(len(blindedElements[i]), 2) || blindedElements[i] ||
              I2OSP(len(evaluatedElements[i]), 2) || evaluatedElements[i] ||
              I2OSP(len(compositeDST), 2) || compositeDST
    di = GG.HashToScalar(h2Input)
    Mi = GG.DeserializeElement(blindedElements[i])
    M = di * Mi + M
    Zi = GG.DeserializeElement(evaluatedElements[i])
    Z = di * Zi + Z

 return [GG.SerializeElement(M), GG.SerializeElement(Z)]
~~~

If the private key is known, as is the case for the server, this function
can be optimized as shown in `ComputeCompositesFast` below.

~~~
Input:

  PrivateKey skS
  PublicKey pkS
  SerializedElement blindedElements[m]
  SerializedElement evaluatedElements[m]

Output:

  SerializedElement composites[2]

def ComputeCompositesFast(skS, pkS, blindedElements, evaluatedElements):
  pkSm = GG.SerializeElement(pkS)
  seedDST = "VOPRF06-Seed-" || self.contextString
  compositeDST = "VOPRF06-Composite-" || self.contextString
  h1Input = I2OSP(len(pkSm), 2) || pkSm ||
            I2OSP(len(seedDST), 2) || seedDST

  seed = Hash(h1Input)
  M = GG.Identity()
  for i = 0 to m-1:
    h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
              I2OSP(len(blindedElements[i]), 2) || blindedElements[i] ||
              I2OSP(len(evaluatedElements[i]), 2) || evaluatedElements[i] ||
              I2OSP(len(compositeDST), 2) || compositeDST
    di = GG.HashToScalar(h2Input)
    Mi = GG.DeserializeElement(blindedElements[i])
    M = di * Mi + M

  Z = skS * M

 return [GG.SerializeElement(M), GG.SerializeElement(Z)]
~~~

### Client Context

The ClientContext encapsulates the context string constructed during
setup. It has two functions, `Blind()` and `Finalize()`, as described
below. It also has an internal function, `Unblind()`, which is used
by `Finalize`. Its implementation varies depending on the mode.

#### Blind

We note here that the blinding mechanism that we use can be modified
slightly with the opportunity for making performance gains in some
scenarios. We detail these modifications in {{blinding}}.

~~~
Input:

  ClientInput input

Output:

  Scalar blind
  SerializedElement blindedElement

def Blind(input):
  blind = GG.RandomScalar()
  P = GG.HashToGroup(input)
  blindedElement = GG.SerializeElement(blind * P)

  return blind, blindedElement
~~~

#### Unblind

In this mode, `Unblind` takes only two inputs. The additional inputs indicated
in {{protocol-overview}} are only omitted as they are ignored. These additional
inputs are only useful for the verifiable mode, described in {{verifiable-unblind}}.

~~~
Input:

  Scalar blind
  SerializedElement evaluatedElement

Output:

  SerializedElement unblindedElement

def Unblind(blind, evaluatedElement, ...):
  Z = GG.DeserializeElement(evaluatedElement)
  N = (blind^(-1)) * Z
  unblindedElement = GG.SerializeElement(N)

  return unblindedElement
~~~

#### Finalize

`Finalize` depends on the internal `Unblind` function. In this mode, `Finalize`
and does not include all inputs listed in {{protocol-overview}}. These additional
inputs are only useful for the verifiable mode, described in {{verifiable-unblind}}.

~~~
Input:

  ClientInput input
  Scalar blind
  SerializedElement evaluatedElement

Output:

  opaque output[Nh]

def Finalize(input, blind, evaluatedElement):
  unblindedElement = Unblind(blind, evaluatedElement)

  finalizeDST = "VOPRF06-Finalize-" || self.contextString
  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(unblindedElement), 2) || unblindedElement ||
              I2OSP(len(finalizeDST), 2) || finalizeDST
  return Hash(hashInput)
~~~

### VerifiableClientContext {#verifiable-client}

The VerifiableClientContext extends the base ClientContext with the
desired server public key `pkS` with an augmented `Unblind()` function.
This function verifies an evaluation proof using `pkS`. It makes use of
the helper function `ComputeComposites` described above. It has one
helper function, `VerifyProof()`, defined below.

#### VerifyProof

This algorithm outputs a boolean `verified` which indicates whether the
proof inside of the evaluation verifies correctly, or not.

~~~
Input:

  PublicKey pkS
  SerializedElement blindedElement
  SerializedElement evaluatedElement
  Proof proof

Output:

  boolean verified

def VerifyProof(pkS, blindedElement, evaluatedElement, proof):
  blindedElementList = [blindedElement]
  evaluatedElementList = [evaluatedElement]

  a = ComputeComposites(pkS, blindedElementList, evaluatedElementList)
  c = GG.DeserializeScalar(proof[0])
  s = GG.DeserializeScalar(proof[1])

  M = GG.DeserializeElement(a[0])
  Z = GG.DeserializeElement(a[1])
  A' = (ScalarBaseMult(s) + c * pkS)
  B' = (s * M + c * Z)
  a2 = GG.SerializeElement(A')
  a3 = GG.SerializeElement(B')

  challengeDST = "VOPRF06-Challenge-" || self.contextString
  h2Input = I2OSP(len(pkS), 2) || pkS ||
            I2OSP(len(a[0]), 2) || a[0] ||
            I2OSP(len(a[1]), 2) || a[1] ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            I2OSP(len(challengeDST), 2) || challengeDST

  expected_c  = GG.HashToScalar(h2Input)

  return CT_EQUAL(expected_c, c)
~~~

#### Verifiable Unblind {#verifiable-unblind}

~~~
Input:

  Scalar blind
  SerializedElement evaluatedElement
  SerializedElement blindedElement
  PublicKey pkS
  Scalar proof

Output:

  SerializedElement unblindedElement

def Unblind(blind, evaluatedElement, blindedElement, pkS, proof):
  if VerifyProof(pkS, blindedElement, evaluatedElement, proof) == false:
    ABORT()

  Z = GG.DeserializeElement(evaluatedElement)
  N = (blind^(-1)) * Z
  unblindedElement = GG.SerializeElement(N)

  return unblindedElement
~~~

#### Verifiable Finalize {#verifiable-finalize}

~~~
Input:

  ClientInput input
  Scalar blind
  SerializedElement evaluatedElement
  SerializedElement blindedElement
  PublicKey pkS
  Scalar proof

Output:

  SerializedElement unblindedElement

def Finalize(input, blind, evaluatedElement, blindedElement, pkS, proof):
  unblindedElement = Unblind(blind, evaluatedElement, blindedElement, pkS, proof)

  finalizeDST = "VOPRF06-Finalize-" || self.contextString
  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(unblindedElement), 2) || unblindedElement ||
              I2OSP(len(finalizeDST), 2) || finalizeDST
  return Hash(hashInput)
~~~

# Domain Separation {#domain-separation}

Applications SHOULD construct input to the protocol to provide domain
separation. Any system which has multiple (V)OPRF applications should
use distinguish client inputs to ensure the OPRF results are separate.
Guidance for constructing info can be found in
{{!I-D.irtf-cfrg-hash-to-curve}}; Section 3.1.

# Ciphersuites {#ciphersuites}

A ciphersuite (also referred to as 'suite' in this document) for the protocol
wraps the functionality required for the protocol to take place. This
ciphersuite should be available to both the client and server, and agreement
on the specific instantiation is assumed throughout. A ciphersuite contains
instantiations of the following functionalities:

- `GG`: A prime-order group exposing the API detailed in {{pog}}, with base
  point defined in the corresponding reference for each group. Each group also
  specifies HashToGroup, HashToScalar, and serialization functionalities. For
  HashToGroup, the domain separation tag (DST) is constructed in accordance
  with the recommendations in {{!I-D.irtf-cfrg-hash-to-curve}}, Section 3.1.
- `Hash`: A cryptographic hash function that is indifferentiable from a
  Random Oracle, whose output length is Nh bytes long.

This section specifies ciphersuites with supported groups and hash functions.

Applications should take caution in using ciphersuites targeting P-256
and ristretto255. See {{cryptanalysis}} for related discussion.

## OPRF(ristretto255, SHA-512)

- Group: ristretto255 {{!RISTRETTO=I-D.irtf-cfrg-ristretto255-decaf448}}
  - HashToGroup(): Use hash_to_ristretto255
    {{!I-D.irtf-cfrg-hash-to-curve}} with DST =
    "VOPRF06-HashToGroup-" || contextString, where contextString is that which is
    computed in the Setup functions, and `expand_message` = `expand_message_xmd`
    using SHA-512.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L = 48, and expand_message_xmd
    with SHA-512.
  - Serialization: Both group elements and scalars are encoded in Ne = Ns = 32
    bytes. For group elements, use the 'Encode' and 'Decode' functions from
    {{!RISTRETTO}}. For scalars, ensure they are fully reduced modulo p and
    in little-endian order.
- Hash: SHA-512, and Nh = 64.
- ID: 0x0001

## OPRF(decaf448, SHA-512)

- Group: decaf448 {{!RISTRETTO}}
  - HashToGroup(): Use hash_to_decaf448
    {{!I-D.irtf-cfrg-hash-to-curve}} with DST =
    "VOPRF06-HashToGroup-" || contextString, where contextString is that which is
    computed in the Setup functions, and `expand_message` = `expand_message_xmd`
    using SHA-512.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L = 84, and `expand_message_xmd`
    with SHA-512.
  - Serialization: Both group elements and scalars are encoded in Ne = Ns = 56
    bytes. For group elements, use the 'Encode' and 'Decode' functions from
    {{!RISTRETTO}}. For scalars, ensure they are fully reduced modulo p and
    in little-endian order.
- Hash: SHA-512, and Nh = 64.
- ID: 0x0002

## OPRF(P-256, SHA-256)

- Group: P-256 (secp256r1) {{x9.62}}
  - HashToGroup(): Use hash_to_curve with suite P256_XMD:SHA-256_SSWU_RO\_
    {{!I-D.irtf-cfrg-hash-to-curve}} and DST =
    "VOPRF06-HashToGroup-" || contextString, where contextString is that which is
    computed in the Setup functions.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L = 48, and `expand_message_xmd`
    with SHA-256.
  - Serialization: Elements are serialized as Ne = 33 byte strings using
    compressed point encoding for the curve {{SEC1}}. Scalars are serialized as
    Ns = 32 byte strings by fully reducing the value modulo p and in big-endian
    order.
- Hash: SHA-256, and Nh = 32.
- ID: 0x0003

## OPRF(P-384, SHA-512)

- Group: P-384 (secp384r1) {{x9.62}}
  - HashToGroup(): Use hash_to_curve with suite P384_XMD:SHA-512_SSWU_RO\_
    {{!I-D.irtf-cfrg-hash-to-curve}} and DST =
    "VOPRF06-HashToGroup-" || contextString, where contextString is that which is
    computed in the Setup functions.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L = 72, and `expand_message_xmd`
    with SHA-512.
  - Serialization: Elements are serialized as Ne = 49 byte strings using
    compressed point encoding for the curve {{SEC1}}. Scalars are serialized as
    Ns = 48 byte strings by fully reducing the value modulo p and in big-endian
    order.
- Hash: SHA-512, and Nh = 64.
- ID: 0x0004

## OPRF(P-521, SHA-512)

- Group: P-521 (secp521r1) {{x9.62}}
  - HashToGroup(): Use hash_to_curve with suite P521_XMD:SHA-512_SSWU_RO\_
    {{!I-D.irtf-cfrg-hash-to-curve}} and DST =
    "VOPRF06-HashToGroup-" || contextString, where contextString is that which is
    computed in the Setup functions.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L = 98, and `expand_message_xmd`
    with SHA-512.
  - Serialization: Elements are serialized as Ne = 67 byte strings using
    compressed point encoding for the curve {{SEC1}}. Scalars are serialized as
    Ns = 66 byte strings by fully reducing the value modulo p and in big-endian
    order.
- Hash: SHA-512, and Nh = 64.
- ID: 0x0005

# Security Considerations {#sec}

This section discusses the cryptographic security of our protocol, along
with some suggestions and trade-offs that arise from the implementation
of an OPRF.

## Security Properties {#properties}

The security properties of an OPRF protocol with functionality y = F(k,
x) include those of a standard PRF. Specifically:

- Pseudorandomness: F is pseudorandom if the output y = F(k,x) on any
  input x is indistinguishable from uniformly sampling any element in
  F's range, for a random sampling of k.

In other words, consider an adversary that picks inputs x from the
domain of F and evaluates F on (k,x) (without knowledge of randomly
sampled k). Then the output distribution F(k,x) is indistinguishable
from the output distribution of a randomly chosen function with the same
domain and range.

A consequence of showing that a function is pseudorandom, is that it is
necessarily non-malleable (i.e. we cannot compute a new evaluation of F
from an existing evaluation). A genuinely random function will be
non-malleable with high probability, and so a pseudorandom function must
be non-malleable to maintain indistinguishability.

An OPRF protocol must also satisfy the following property:

- Oblivious: The server must learn nothing about the client's input or
  the output of the function. In addition, the client must learn nothing
  about the server's private key.

Essentially, obliviousness tells us that, even if the server learns the
client's input x at some point in the future, then the server will not
be able to link any particular OPRF evaluation to x. This property is
also known as unlinkability {{DGSTV18}}.

Optionally, for any protocol that satisfies the above properties, there
is an additional security property:

- Verifiable: The client must only complete execution of the protocol if
  it can successfully assert that the OPRF output it computes is
  correct. This is taken with respect to the OPRF key held by the
  server.

Any OPRF that satisfies the 'verifiable' security property is known as a
verifiable OPRF, or VOPRF for short. In practice, the notion of
verifiability requires that the server commits to the key before the
actual protocol execution takes place. Then the client verifies that the
server has used the key in the protocol using this commitment. In the
following, we may also refer to this commitment as a public key.

## Cryptographic Security {#cryptanalysis}

Below, we discuss the cryptographic security of the (V)OPRF protocol
from {{protocol}}, relative to the necessary cryptographic assumptions
that need to be made.

### Computational Hardness Assumptions {#assumptions}

Each assumption states that the problems specified below are
computationally difficult to solve in relation to a particular choice of
security parameter `sp`.

Let GG = GG(sp) be a group with prime-order p, and let GF(p) be a finite
field of order p.

#### Discrete-log (DL) Problem {#dl}

Given G, a generator of GG, and H = hG for some h in GF(p); output h.

#### Decisional Diffie-Hellman (DDH) Problem {#ddh}

Sample uniformly at random d in {0,1}. Given (G, aG, bG, C), where

- G is a generator of GG;
- a,b are elements of GF(p);
- if d == 0: C = abG; else: C is sampled uniformly at random from GG.

Output d' == d.

### Protocol Security {#protocol-sec}

Our OPRF construction is based on the VOPRF construction known as
2HashDH-NIZK given by {{JKK14}}; essentially without providing
zero-knowledge proofs that verify that the output is correct. Our VOPRF
construction is identical to the {{JKK14}} construction, except that we
can optionally perform multiple VOPRF evaluations in one go, whilst only
constructing one NIZK proof object. This is enabled using an established
batching technique.

Consequently, the cryptographic security of our construction is based on
the assumption that the One-More Gap DH is computationally difficult to
solve.

The (N,Q)-One-More Gap DH (OMDH) problem asks the following.

~~~
    Given:
    - G, k * G, and (G_1, ... , G_N), all elements of GG;
    - oracle access to an OPRF functionality using the key k;
    - oracle access to DDH solvers.

    Find Q+1 pairs of the form below:

    (G_{j_s}, k * G_{j_s})

    where the following conditions hold:
      - s is a number between 1 and Q+1;
      - j_s is a number between 1 and N for each s;
      - Q is the number of allowed queries.
~~~

The original paper {{JKK14}} gives a security proof that the
2HashDH-NIZK construction satisfies the security guarantees of a VOPRF
protocol {{properties}} under the OMDH assumption in the universal
composability (UC) security model.

### Q-Strong-DH Oracle {#qsdh}

A side-effect of our OPRF design is that it allows instantiation of a
oracle for constructing Q-strong-DH (Q-sDH) samples. The Q-Strong-DH
problem asks the following.

~~~
    Given G1, G2, h*G2, (h^2)*G2, ..., (h^Q)*G2; for G1 and G2
    generators of GG.

    Output ( (1/(k+c))*G1, c ) where c is an element of GF(p)
~~~

The assumption that this problem is hard was first introduced in
{{BB04}}. Since then, there have been a number of cryptanalytic studies
that have reduced the security of the assumption below that implied by
the group instantiation (for example, {{BG04}} and {{Cheon06}}). In
summary, the attacks reduce the security of the group instantiation by
log_2(Q) bits.

As an example, suppose that a group instantiation is used that provides
128 bits of security against discrete log cryptanalysis. Then an
adversary with access to a Q-sDH oracle and makes Q=2^20 queries can
reduce the security of the instantiation by log_2(2^20) = 20 bits.

Notice that it is easy to instantiate a Q-sDH oracle using the OPRF
functionality that we provide. A client can just submit sequential
queries of the form (G, k * G, (k^2)G, ..., (k^(Q-1))G), where each
query is the output of the previous interaction. This means that any
client that submits Q queries to the OPRF can use the aforementioned
attacks to reduce the security of the group instantiation by log_2(Q) bits.

Recall that from a malicious client's perspective, the adversary wins if
they can distinguish the OPRF interaction from a protocol that computes
the ideal functionality provided by the PRF.

### Implications for Ciphersuite Choices

The OPRF instantiations that we recommend in this document are informed
by the cryptanalytic discussion above. In particular, choosing elliptic
curves configurations that describe 128-bit group instantiations would
appear to in fact instantiate an OPRF with 128-log_2(Q) bits of
security.

In most cases, it would require an informed and persistent attacker to
launch a highly expensive attack to reduce security to anything much
below 100 bits of security. We see this possibility as something that
may result in problems in the future. For applications that cannot
tolerate discrete logarithm security of lower than 128 bits, we
recommend only implementing ciphersuites with IDs: 0x0002, 0x0004, and
0x0005.

## Hashing to Group

A critical requirement of implementing the prime-order group using
elliptic curves is a method to instantiate the function
`GG.HashToGroup`, that maps inputs to group elements. In the elliptic
curve setting, this deterministically maps inputs x (as byte arrays) to
uniformly chosen points on the curve.

In the security proof of the construction Hash is modeled as a random
oracle. This implies that any instantiation of `GG.HashToGroup` must be
pre-image and collision resistant. In {{ciphersuites}} we give
instantiations of this functionality based on the functions described in
{{!I-D.irtf-cfrg-hash-to-curve}}. Consequently, any OPRF implementation
must adhere to the implementation and security considerations discussed
in {{!I-D.irtf-cfrg-hash-to-curve}} when instantiating the function.

## Timing Leaks

To ensure no information is leaked during protocol execution, all
operations that use secret data MUST run in constant time. Operations that
SHOULD run in constant time include all prime-order group operations and
proof-specific operations (`GenerateProof()` and `VerifyProof()`).

## Key Rotation {#key-rotation}

Since the server's key is critical to security, the longer it is exposed
by performing (V)OPRF operations on client inputs, the longer it is
possible that the key can be compromised. For example, if the key is kept
in circulation for a long period of time, then it also allows the
clients to make enough queries to launch more powerful variants of the
Q-sDH attacks from {{qsdh}}.

To combat attacks of this nature, regular key rotation should be
employed on the server-side. A suitable key-cycle for a key used to
compute (V)OPRF evaluations would be between one week and six months.

# Additive Blinding {#blinding}

Let `H` refer to the function `GG.HashToGroup`, in {{pog}} we assume
that the client-side blinding is carried out directly on the output of
`H(x)`, i.e. computing `r * H(x)` for some `r` sampled uniformly at random
from `GF(p)`. In the {{!I-D.irtf-cfrg-opaque}} document, it is noted that it
may be more efficient to use additive blinding (rather than multiplicative)
if the client can preprocess some values. For example, a valid way of
computing additive blinding would be to instead compute `H(x) + (r * G)`,
where `G` is the fixed generator for the group `GG`.

The advantage of additive blinding is that it allows the client to
pre-process tables of blinded scalar multiplications for `G`. This may
give it a computational efficiency advantage (due to the fact that a
fixed-base multiplication can be calculated faster than a variable-base
multiplication). Pre-processing also reduces the amount of computation
that needs to be done in the online exchange. Choosing one of these
values `r * G` (where `r` is the scalar value that is used), then
computing `H(x) + (r * G)` is more efficient than computing `r * H(x)`.
Therefore, it may be advantageous to define the OPRF and VOPRF protocols
using additive (rather than multiplicative) blinding. In fact,
the only algorithms that need to change are `Blind` and `Unblind` (and
similarly for the VOPRF variants).

We define the variants of the algorithms in {{api}} for performing
additive blinding below, called `AdditiveBlind` and `AdditiveUnblind`,
along with a new algorithm `Preprocess`. The `Preprocess` algorithm can
take place offline and before the rest of the OPRF protocol. `AdditiveBlind`
takes the preprocessed values as inputs. `AdditiveUnblind` takes the
preprocessed values and evaluated element from the server as inputs.

## Preprocess

~~~
Input:

  PublicKey pkS

Output:

  Element blindedGenerator
  Element blindedPublicKey

def Preprocess(pkS):
  blind = GG.RandomScalar()
  blindedGenerator = ScalarBaseMult(blind)
  blindedPublicKey = blind * pkS

  return blindedGenerator, blindedPublicKey
~~~

## AdditiveBlind

~~~
Input:

  ClientInput input
  Element blindedGenerator

Output:

  SerializedElement blindedElement

def AdditiveBlind(input, blindedGenerator):
  P = GG.HashToGroup(input)
  blindedElement = GG.SerializeElement(P + blindedGenerator) /* P + ScalarBaseMult(r) */

  return blindedElement
~~~

## AdditiveUnblind

~~~
Input:

  Element blindedPublicKey
  SerializedElement evaluatedElement

Output:

 SerializedElement unblindedElement

def AdditiveUnblind(blindedPublicKey, evaluatedElement):
  Z = GG.DeserializeElement(evaluatedElement)
  N := Z - blindedPublicKey

  unblindedElement = GG.SerializeElement(N)

  return unblindedElement
~~~

Let `P = GG.HashToGroup(input)`. Notice that AdditiveUnblind computes:

~~~
Z - blindedPublicKey = k * (P + r * G) - r * pkS
                     = k * P + k * (r * G) - r * (k * G)
                     = k * P
~~~

by the commutativity of the scalar field. This is the same
output as in the `Unblind` algorithm for multiplicative blinding.

Note that the verifiable variant of `AdditiveUnblind` works as above but
includes the step to `VerifyProof`, as specified in {{verifiable-client}}.

### Parameter Commitments

For some applications, it may be desirable for the server to bind tokens to
certain parameters, e.g., protocol versions, ciphersuites, etc. To
accomplish this, the server should use a distinct scalar for each parameter
combination. Upon redemption of a token T from the client, the server can
later verify that T was generated using the scalar associated with the
corresponding parameters.

# Acknowledgements

This document resulted from the work of the Privacy Pass team
{{PrivacyPass}}. The authors would also like to acknowledge helpful
conversations with Hugo Krawczyk. Eli-Shaoul Khedouri provided
additional review and comments on key consistency. Daniel Bourdrez,
Tatiana Bradley, Sofía Celi, Frank Denis, and Bas Westerbaan also
provided helpful input and contributions to the document.

--- back

# Test Vectors

This section includes test vectors for the (V)OPRF protocol specified
in this document. For each ciphersuite specified in {{ciphersuites}},
there is a set of test vectors for the protocol when run in the base
mode and verifiable mode. Each test vector lists the batch size for
the evaluation. Each test vector value is encoded as a hexadecimal
byte string. The label for each test vector value is described below.

- "Input": The client input, an opaque byte string.
- "Blind": The blind value output by `Blind()`, a serialized `Scalar`
  of `Ns` bytes long.
- "BlindedElement": The blinded value output by `Blind()`, a serialized
  `Element` of `Ne` bytes long.
- "EvaluatedElement": The evaluated element output by `Evaluate()`,
  a serialized `Element` of `Ne` bytes long.
- "EvaluationProofC": The "c" component of the Evaluation proof (only
  listed for verifiable mode test vectors), a serialized `Scalar` of
  `Ns` bytes long.
- "EvaluationProofS": The "s" component of the Evaluation proof (only
  listed for verifiable mode test vectors), a serialized `Scalar` of
  `Ns` bytes long.
- "Output": The OPRF output, a byte string of length `Nh` bytes.

Test vectors with batch size B > 1 have inputs separated by a comma
",". Applicable test vectors will have B different values for the
"Input", "Blind", "BlindedElement", "EvaluationElement", and
"Output" fields.

The server key material, `pkSm` and `skSm`, are listed under the mode for
each ciphersuite. Both `pkSm` and `skSm` are the serialized values of
`pkS` and `skS`, respectively, as used in the protocol. Each key pair
is derived from a `seed`, which is listed as well.

## OPRF(ristretto255, SHA-512)

### Base Mode

~~~
seed = 84ad9a654ba6269c0b6fa7e675d3b22916d57ebc6284393d6784c83b8e4ab
d6d
skSm = d8a4482f3ee268d06b99a2e86d091f72b971810b8791527eb9dc5b10764a5
e0e
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf
8e03
BlindedElement = 3c7f2d901c0d4f245503a186086fbdf5d8b4408432b25c5163e
8b5a19c258348
EvaluationElement = d40741f1409d364a3ce4edc816900197c8da0cbc1599ea40
867beaa557083558
Output = 8e33e779006a83dfb2334cca1f4892ede299e3d968ce7657414213ece0e
7b18e9ebb726483687aa1bcbfb3016e8ee06af6d120034cb59b2574b431d314aecb1
8
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037
e50b
BlindedElement = 28a5e797b710f76d20a52507145fbf320a574ec2c8ab0e33e65
dd2c277d0ee56
EvaluationElement = 44731d092e243ab43027b641a8a19da4cc1bf0e457ef08a0
e80697354c2d860c
Output = ac5f4d9e5b741f3f10dfe390ff969f7279b3e804c2c57eac8fd92cbd485
60001baf59a2c3273a4be5560f68729dcbdc09b3683be96debbe133dd9b21f6eebb9
c
~~~

### Verifiable Mode

~~~
seed = 76e16eb378955c7881886fe994a7d2372fc814c062fbc5ca341a01411d623
124
skSm = 2bf60ae11f60e6ff4886137ef3251b6afcaa2b800ed49debfd8f1c5d618be
509
pkSm = 243c037df4eeb0a4debfd8a84e8420ee038023030966f7f62eb1953995cdb
d5a
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e326
3503
BlindedElement = 9cf00acd9be7d00b87012823aec2480afac98468fc7e0766e52
c2c42eb66802a
EvaluationElement = 685ea58d018a3f1aa7fb85bf2db6337f9ed1fb53ac97b4ba
612c0fc8f339286c
EvaluationProofC = b4e64381690b551c721bb392f98a32385138d01d0948c55c7
b14f0dd6bdc3508
EvaluationProofS = b36179715c918c010e17745b59c751b50c16a55e30435d14b
dd1b30ebfd6d604
Output = 45e2d3d98ec110e08a4c62a0e135b506266485ca1699570e4c5a431adae
61bfacbd7d92b86ef94142bc3785fbab206ffb0c7bb7e7da7f3e728e709fa0c74627
e
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd4171
ea02
BlindedElement = 9669e8326632c31ddac138b1da65cf39bdc6fa085050f5afd2b
fedf3dc1a3313
EvaluationElement = 020046dd9409f7150896eb4d2fd16655b075877de43f7d42
f5f47a82524abf58
EvaluationProofC = 4aed98c6d6acfac66c5c51024c3e0a70ec6e8d948cc877d9d
aa829e1be25020d
EvaluationProofS = 61e6a6d337575061548cc592c8856a61a8f9fa9fdbdbda240
147e4271ed27303
Output = 72a763df8a4752cd0d44d3aa5f4469c747f4e5b72216eccc16158de40b9
70022447ee0579f91a72dc2786a0715fb46ce026348921a30022a8f4deb8771a6db7
d
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 80513e77795feeec6d2c450589b0e1b178febd5c193a9fcba0d27f0a06e0
d50f,533c2e6d91c934f919ac218973be55ba0d7b234160a0d4cf3bddafbda99e2e0
c
BlindedElement = 6620ec0b7dc26cb6a6cc7a72ecf28971863861b88363b374f91
c44c056544245,06f533d9495a54252c2ccced2edb2fb5840f9cf8462a8233a7b4ec
2d5f788348
EvaluationElement = b6ae4521436bd2ca9f0878c5810e17a81d19d5dd8379a68f
d9eb625dbe736478,14d86abaadea58513b1783ec3b25d706baeda1a488528cf1163
c65cd96db8b52
EvaluationProofC = a2ca2e1e6bcd70a4923aee27961812e4a83e4ca9ca6458f8c
45d7ea23abf360c
EvaluationProofS = f989e73bf00c20a9bfd711ffb6a0412a7b9aed6f1f016c112
d6e206a63a3480e
Output = 45e2d3d98ec110e08a4c62a0e135b506266485ca1699570e4c5a431adae
61bfacbd7d92b86ef94142bc3785fbab206ffb0c7bb7e7da7f3e728e709fa0c74627
e,72a763df8a4752cd0d44d3aa5f4469c747f4e5b72216eccc16158de40b97002244
7ee0579f91a72dc2786a0715fb46ce026348921a30022a8f4deb8771a6db7d
~~~

## OPRF(decaf448, SHA-512)

### Base Mode

~~~
seed = 7c9dc8e57c9219e97ade87ed95e058485d7f8e47d02b54f68582ee1bd3a26
e39af72203dc7b8dd2762bb80b1f045cd268c3f9394a5f50e11
skSm = 520151e8533b5d5961387b0ccd9f56ed0a5da1edf19f558e01c8ff2b98e68
b0d0bfc5e3d05ba51bbde5accfb06eadb96ae0ee999de9c1235
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = d1080372f0fcf8c5eace50914e7127f576725f215cc7c111673c635ce668
bbbb9b50601ad89b358ab8c23ed0b6c9d040365ec9d060868714
BlindedElement = 0e5e2ac2924bee04fa1ae372a6a26f6f71972372494c08433d6
766aeb103c2aef393e06cdc52ed270f1c94e4538068ab724d84ad217f7b2c
EvaluationElement = 98810b820036097c7dfde33e7c3f7849b5bc486c8ffac42f
eef2651eb168fac23239881562c75fa141bb4d10883abf5496f279e9e82dc92c
Output = a4d221a913858716ec121b04b786bce208c471d2408f48adbf1b9e2f299
214e0440cc30d9c74ddde8456effe7a14f08b09db6b1766b3a840eead012a5fd27e3
2
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = aed1ffa44fd8f0ed16373606a3cf7df589cca86d8ea1abbf5768771dbef3
d401c74ae55ba1e28b9565e1e4018eb261a14134a4ce60c1c718
BlindedElement = 0016392cdfbe773dd6740eaa7b41ad19b62b7552a5fff88a337
90391c656726e7c7b346c2d6989085c6bc11b31a14b15ba2340f776891dc0
EvaluationElement = 84e51149ec393ce79081b27d68b2cd9624f962b196f5369c
7b9832a2914fd931f85ef24701f08bea3b349c9a19237890061a616fb54cdb36
Output = b54cf89216a3597f919fb1b4bee6ea5c81aaefc8c95de8775dd1c30081a
bbbf2d82b16dd0335c48531e21802859b7bc0f92ab532331d67ccec66d36171ba230
b
~~~

### Verifiable Mode

~~~
seed = d59cbccae17874e74c0c36c58481c2a6c04c4279825aa8121597ac865e9fd
71296e66d90701a3a8ec9148399d146b99346ca64cd7c05d099
skSm = 1237482779975e6ec1c458c23c5b4620ca568df36a26ea057d18a7aa0ccf4
0b09fbe4850bbdd6ad54593d561205cbb952bc18e39ff5cab1b
pkSm = aa17a1e71fe53faeb4f2476a30d0eef9bdb08dba7956fd973e8917b4bddae
7621e76b4240fb87c2664a78397ef95cd5f70cf1af2df2a6c42
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 4c936db1779a621b6c71475ac3111fd5703a59b713929f36dfd1e892a7fe
814479c93d8b4b6e11d1f6fe5351e51457b665fa7b76074e531f
BlindedElement = b06491721a030478fcf4756de92f0937e29a3898496964636be
0c9c884a3143a933dcc085e9a0303bde79b3ebdc77448eaa80203d7b57c40
EvaluationElement = a88ac9044c17276ed49a1776d06f8ad2bf00f0608a6c70eb
9209be13858aa5560636163cd7a3659bbfe87d5089f17f673df74c17a529108e
EvaluationProofC = 7aef3b8a3a64933a89673473f114cb0e93a60b279968db509
c9fd1e430c1965dc7138ae33fabf9114dd3b393cc952099570b76e48ae7d106
EvaluationProofS = 862a168a107616c1c1ba7aff18f95b68b30bffcd7432a6404
7a81f2a76a1676d4802d13df10997797aeeff4ead4e5ad3f5764979a4730320
Output = 18385868e64b774de1ad9c64331d2daa965685a9b0f33c97978ad531347
6c5331223c738cdcb0e694cdc85e1fd228d8d36e69ae6315ccb77b7aeb0e599d29d5
a
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 15b3355179392f40c3d5a15f0d5ffc354e340454ec779f575e4573a3886a
b5e57e4da2985cea9e32f6d95539ce2c7189e1bd7462e8c5483a
BlindedElement = 3ea98d0d80c5e34582534f06daa3f5747d594fc271dddf4bcb9
034442eb01564ad92e4a4340f2c9e40f4f212a0a7cdc7bdcad3b8cf83998f
EvaluationElement = 10523520fe22e37212d11dfdaa149169e25edf9a101e06b9
9b9d09df52a9e0795f33b2157e06172719039305a6a001d5ae2850b3a1ab6625
EvaluationProofC = 89b3e36d63c8a9fefb39cb5fd596a73a3b8465b9a2160300b
c1143b9e65a666752a524a884387b8900e6978b6f97f75c30b11577d6397f1e
EvaluationProofS = d5687b1ddf719afc9a206e6ac5bfbbb98808a8430e7e822bf
97de34fdb101a3d856ca3e23f01d3c898c6cf3c91e1b6e50738d5eed881030d
Output = d02f4037e286a5f081b5b9b8ee63d4627ecdc9f23b1207688ad5b3c49a3
32a2b07809ab0158d97a523711ba24767673cce29bf7dc0c422e951c3642640be19b
d
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 614bb578f29cc677ea9e7aea3e4839413997e020f9377b63c13584156a09
a46dd2a425c41eac0e313a47e99d05df72c6e1d58e6592577a0d,4c115060bca87db
7d73e00cbb8559f84cb7a221b235b0950a0ab553f03f10e1386abe954011b7da62bb
6599418ef90b5d4ea98cc28aff517
BlindedElement = 3a3cb2e82a88063371b1983fbb47e4b6838102f3225f21fb578
af1398ca763a0c1ef7e3c827547d85d87a53ea18b6e29695c0667f7e6d062,a27a04
823af77878e659b5be66bd61baf06207cfcba7365c9a4dbbdc4d013119c0d88d6b23
b1eb7dee10bb553ec8bdbc1d1e38a18ee7103c
EvaluationElement = 36b056aa344a7a34de0ff33502c7101de3869dfd1b91ab86
2ba446be86fc10da3b495a2dac745521fcc407f07f5cc6c9a7a5b224571115f5,e60
41e1ea18db24778592c9a12d6ad73f856448e7b14e700c19c27102137fa0ee24b002
107cecb49106043f5329134de2169dc30d1bb4503
EvaluationProofC = b019df26d530fdea40fde23e398cc57f0fc97f82b7d377fa8
33c8ca43781c3717493a0989f499430bdf7fb605e62337e19739a30a4c4e912
EvaluationProofS = 039dad61c72648313d2cf5c6ba40840a72e230d4a28839f40
5c840d77ff107fa497dacb07e10a9e4e1444c9e3287e0a1b3dda1137bfda408
Output = 18385868e64b774de1ad9c64331d2daa965685a9b0f33c97978ad531347
6c5331223c738cdcb0e694cdc85e1fd228d8d36e69ae6315ccb77b7aeb0e599d29d5
a,d02f4037e286a5f081b5b9b8ee63d4627ecdc9f23b1207688ad5b3c49a332a2b07
809ab0158d97a523711ba24767673cce29bf7dc0c422e951c3642640be19bd
~~~

## OPRF(P-256, SHA-256)

### Base Mode

~~~
seed = 53cc70bf72877ae990ac5dc0f46f18e5df3e39a2180a0debd85fadfff70c4
bdc
skSm = e9fd3072c71cd8e3f8a0d369720f11d8b32869cf044521129fc5adb6099a1
fd5
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 5d9e7f6efd3093c32ecceabd57fb03cf760c926d2a7bfa265babf29ec98a
f0d0
BlindedElement = 02f09475852ef62318680a3ea1319d0474dfabc4402b752ec94
7c8a37c5c1491a2
EvaluationElement = 03de5464cad076ec979c725e5af3c0bcae48d0dd20cab437
2a6f94bcb360792c22
Output = a06cce99aab508f14a9134a38637524eb9650febdfa99f7953f2155c41b
e0d28
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 825155ab61f17605af2ae2e935c78d857c9407bcd45128d57d338f1671b5
fcbe
BlindedElement = 02589019677db1bca1ca2f94da740691016578952337e2d19e0
7d1de0d26563c4f
EvaluationElement = 02be6c7044faf28b5945cb00b8f3f9ece41e8aa2e560ddb5
16bd7a60dece7308d3
Output = dcdad0c892aa07a2d632f2da6849d9748fbca942d337589b9936d5c65ae
c1f18
~~~

### Verifiable Mode

~~~
seed = f496804abce4df227209032c42754519eb59ed0410deaed557df1d5077c79
587
skSm = e780f40a1dbc256c479ecb3746ad7d153d2bf1083ae0cd9c4d402386e4c59
825
pkSm = 03b4f4f7adf36dc6cfb039bdac06140b0b59437d8b5bad6eb13d0f362190f
f6a0a
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = cee64d86fd20ab4caa264a26c0e3d42fb773b3173ba76f9588c9b14779bd
8d91
BlindedElement = 03458b1f2964895be9500419f7252a5f899932a0e1a80dad2a5
8c93205d87c189c
EvaluationElement = 020ca97be3585592f932d40add8aa0117a587d079e311c66
2b5ba589c278861f49
EvaluationProofC = 6b6d56f58c48a43245c0873015ddac5f3fbed57081cbf16d4
6d3282587957a42
EvaluationProofS = 9925239dccf01fd8f83337d86ca014bfab06f66eb41d7cbf7
aef0bc1989f3d53
Output = 04eafb6e3ad1c240168935cff01183b84d059ba751d40d93e2ee4a0165f
a3d05
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 5c4b401063eff0bf242b4cd534a79bacfc2e715b2db1e7a3ad4ff8af1b24
daa2
BlindedElement = 02b600c8cd1f859fb7a87a1c9298b68d12902e4d093c9573af0
6b1b376c58e6623
EvaluationElement = 0372c2d3889b39e34169f2ff660de57bdf67fcb438e85100
78b654cc0bca9e21a2
EvaluationProofC = 3ebbf076af23dd58db8eb1eb22c1b2aa060112d25c18a1a16
ed05e9a3f426a4c
EvaluationProofS = a6f0f618d9fca995140641b7fb572530c30cd84d101f2eba5
5a7a71ae3696595
Output = 65bfbc9a9d129fe05d15eb992f94804da5bf20d5dfe48e3a61e58bd07c9
4e51b
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = f0c7822ba317fb5e86028c44b92bd3aedcf6744d388ca013ef33edd36930
4eda,3b9631be9f8b274d9aaf671bfb6a775229bf435021b89c683259773bc686956
b
BlindedElement = 03ac68c358da4a3cff87c0a31e9646d178be69bbda8e00d204e
10d00d4518b8821,03f0189aef822b923cfacb055a74af1111c545093a1c8b2afabc
d79abf79a300da
EvaluationElement = 03cd2d82acfc7f7838eed0bbfccec13381ad529764bb8d4c
7a4773df397926971f,0339408d5721d59c588dff5fca8a7e4b06af7bc238f1000e7
278f92d742b5cec0a
EvaluationProofC = fc91dd1dc85c7111b272526a061dd113509e1410cc19fe881
fcf19f2ca6b219f
EvaluationProofS = f6170a40420a367c506075120fb8c9d5973ce5f8350d9bec3
cb61e3a1e531a2d
Output = 04eafb6e3ad1c240168935cff01183b84d059ba751d40d93e2ee4a0165f
a3d05,65bfbc9a9d129fe05d15eb992f94804da5bf20d5dfe48e3a61e58bd07c94e5
1b
~~~

## OPRF(P-384, SHA-512)

### Base Mode

~~~
seed = c89a6f18a5e72666064cff889ac10f6f13dbe3ddd34ea5dbac72848ee05cd
0ceb21b4d7608f9a662e5c87b803235a5ae
skSm = ef8436649b81690a7ecd55404b2d5cf69286564706fc76374f9c4fc706962
522a9a4efc5c151529d8457381f7e8fbbac
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 359073c015b92d15450f7fb395bf52c6ea98384c491fe4e4d423b59de7b0
df382902c13bdc9993d3717bda68fc080b99
BlindedElement = 022250ba7604814ab2058e70fdc5dcf2604afb3ab6e15fc97c5
14973bb5e574d586ce518700ad0dd02b54982ce202020e1
EvaluationElement = 0334b883dfda229cbca329167430585037dc31cfc085829a
c345d72be8658a9c015abd5731de76aee3ecc2fc056367c5c8
Output = 34b2abdac4a02c2279a8c2a45cfe32706d38d943d2470eecd211b4604ab
182298cc8eccc84b3228fcef50f4875b72a2af44ba100e5ff82e1899d20cf67a0ec6
7
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 21ece4f9b6ffd01ce82082545413bd9bb5e8f3c63b86ae88d9ce0530b01c
b1c23382c7ec9bdd6e75898e4877d8e2bc17
BlindedElement = 022dd0addbced4c8ea73eaa8e38f43506a7c3f98288ed479725
d596fa3a578f728915414f5df77084cadefcd5e4662f6df
EvaluationElement = 03387108a1e54a446026d6ea28a78c2540a9ae9040c008f4
3d3a79b3e82b9bd135b9243f371871049e226ffc3bed136ab0
Output = 9f9680b3df599e5075c1d6921b2ef5ad5902df471c8796c52e70b249a72
c2056d59ec3fdf5cf382eefb631383ed5393938d78a55f52ed6b3c15e7c6e867e442
c
~~~

### Verifiable Mode

~~~
seed = d8d0083597590a63603124300f6720181e3607e8dc32f72077275abdf2269
96c655776ed2c5158cdb6a5d79647ff2a12
skSm = bc87df3f48bf90134eaa92bd26ac7feb3a518957d81b95812f8e6ed0b802d
6df62dbeb26088c3fb9b08f8c255d5785ac
pkSm = 02ec43bde442d896ae2c8ae3202302081af86f1cf7ce984622249bc11b897
4e50ce596092978a7b22b69c410dd3ddb8a6d
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 102f6338df84c9602bfa9e7d690b1f7a173d07e6d54a419db4a6308f8b09
589e4283efb9cd1ee4061c6bf884e60a8774
BlindedElement = 03c267661f12013daa1e4fe319713adde264a37bea8b91c5cb2
71e9e3ee12e5ed829f5a7a23aa4803704381e638a927e3a
EvaluationElement = 0280d8a1d8f8af6f1895c1f9fcabb66a317b3334e4c813a9
d47362cbf0fd1291b99f4058b8618e233e0debb5134b115487
EvaluationProofC = 1af017b1571d48f790876a5cfecf69cdef01bf8aa1cdfef9f
b7b94a45f0590721748b7c5b7ab7b4febd418898089e176
EvaluationProofS = a54e3b49f2f7fe1eb820b20b09745f82c1ebab817707c5b7a
ab89cd082e309b24334e8473c431fbb79ebfc837a31b94c
Output = 0ff12ee0bfddc7f622c0678d053f626795802ea3c98bf5e81cbc46a354e
b7c61442d7bca65d5f91e1b8f4af9d8bcdbe15129e58e54fb3fec46098f0964375c3
e
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 8aec1d0c3d16afd032da7ba961449a56cec6fb918e932b06d5778ac7f67b
ecfb3e3869237f74106241777f230582e84a
BlindedElement = 038f7b700d59fe135484a799fa10bb761b622d29a606ef9ecb5
b922409de93473c850bbccfd449a9cd1c352021faed9285
EvaluationElement = 0257fdb30b157976e3174611ceec0acba88ae046d02575d1
0faf28ddffdd4363f865040433ffbdbf4201a2a8dfb0e51456
EvaluationProofC = 3c4b469b6204738d9738c1a7614e59f2a6f6de7029b5af6d6
c65923bb13dcb52948ec2e3ae61cf42f0202f279b0e5e28
EvaluationProofS = a780692837bf3018c791ba09f163c9b005e8095e9232471ec
80ac7213f6e18150a695811ebee3d6f98621f377520a63c
Output = 03a5d4eb603ae201d745b479916a3c3cc702d914bf79b6a86f1c1c12373
ae7909192181b49f3f7e16e8198de7b73dc41e033c958a46d9a10cc100733166ec45
2
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 41fabd4722d92472d858051ce9ad1a533176a862c697b2c392aff2aeb77e
b20c2ae6ba52fe31e13e03bf1d9f39878b23,51171628f1d28bb7402ca4aea6465e2
67b7f977a1fb71593281099ef2625644aee0b6c5f5e6e01a2b052b3bd4caf539b
BlindedElement = 0261f6684d6b14f9a751e3837b09545fea017d792c3b3585524
7b4e900adf6874c77a57805b020c3ae2e7560e078fb2410,02e2b67e4571f2d83998
6cd1b989edebe55ed6c05fb5173e12ed7c56fd262f2ab806b23f44e81101f532b224
d788e66c02
EvaluationElement = 02eb68f9cc7a3a75af84410b54b1902763f97169f6b49b51
918b923f7ad4abd8fec5ceb869343916c2ac089225f464c130,033b9e5d650b7ea56
d3222d38eb8786a4f3dfd1dd366ea8da0bf9ce0ae4906e94e1c59074117ac7dadb12
dc5c66dd5dc5d
EvaluationProofC = 320424ae89e399c04ab4d6775c5a4e723384de7bc721d3d4c
8d564e5f62a23cb2fd8c435fb4e9ce127ec80dc4461d9af
EvaluationProofS = f458fe7dc9e0a2e217b76fbd2fd54b22ec41863b73c17f4c0
69d04394102b8b4d4f5e1d19f634daa663cc9c66f86b31f
Output = 0ff12ee0bfddc7f622c0678d053f626795802ea3c98bf5e81cbc46a354e
b7c61442d7bca65d5f91e1b8f4af9d8bcdbe15129e58e54fb3fec46098f0964375c3
e,03a5d4eb603ae201d745b479916a3c3cc702d914bf79b6a86f1c1c12373ae79091
92181b49f3f7e16e8198de7b73dc41e033c958a46d9a10cc100733166ec452
~~~

## OPRF(P-521, SHA-512)

### Base Mode

~~~
seed = 8816feb42544cd0fbc9fed3962939243596db24c62106a7c396b0b45da753
cf785991c97cf0e86c623a907932617095d8c7d9759677db020d7a2d7fd570467582
5a0
skSm = 006b570ae37e48f6e6a79026bf278d7c28f92fff6216246d77bdd4b7b5d08
7450809294a4db302e017dade499097896c36b68875ea542ff2786c7e4a6693172a1
968
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 01b983705fcc9a39607288b935b0797ac6b3c4b2e848823ac9ae16b3a3b5
816be03432370deb7c3c17d9fc7cb4e0ce646e04e42d638e0fa7a434ed340772a8b5
d626
BlindedElement = 0301df6ecf5c96659ecc36613357a9f337b43687e0073f67b9a
d8b6714bc1e8abdfbb74115189474ddb697df70676c551c103d601640c51e10ef607
fc4d0fe485b557f
EvaluationElement = 0300f08007b7bf4f7bed5874372a4efd30aef81c2816ebff
87f8a6b8cc08df934376647dfcc7b9b24f08061f0f8c2f72cd86a2d0694315457e2f
40c5e39ffc694a47c3
Output = fa7a26e773bf0d9824c8bb7d0b05c2d64f863a2e6e90d1418685645695b
c1fb2aa2e35e75a9930a0e65bd5606205703df00be3eb396da4883a23770bffc3a21
3
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 01a03b1096b0316bc8567c89bd70267d35c8ddcb2be2cdc867089a2eb5cf
471b1e6eb4b043b9644c8539857abe3a2022e9c9fd6a1695bbabe8add48bcd149ff3
b841
BlindedElement = 0201412d7330e8ef457d1e21e25feb41c3b09d3bcd347916743
f60b10cdb0bd9498a965f35ee525ffccc16606be42a1c1764d18fabd7bb0b61da95a
b3c9a23918233ef
EvaluationElement = 0201d341300a520c5bc40dfdce0fcab4adbf387ca26d7f25
8e927ffa83c5dbb7b97e3551af97e85383086a8f69e59a7809038f4489ee23fd15d8
d79bb7064d1bc9eab9
Output = db99d2d651d1336b444bfa1e3728839ebf68c8ec53cab8b41fd3b56e934
87fcca024ff4567bb55a366b39be284887133a8b800a1f0bfe16e719de8bb064d24d
5
~~~

### Verifiable Mode

~~~
seed = bf515b5d982bc7e28f2fdf5e224d1f6054265eb65240234e15390c816a538
0ec7a3657dc55c5181a332e46293cefd980cd001a83d9fbd370ee8f3fbc4e7deec37
706
skSm = 01820b00b38bb91dbe25cda9610dfe78c71d8185dbfff1eb9d87d7226b32e
e9deddff3f87075077d33a507d19f6117940863bde8efef960e3af9cc886342e735e
b96
pkSm = 0200ef613d78ec301019d2c8b06b40384b2a5c99ab5cfb88d3ed74e993168
732f786e035178f4a0f525a85f19ac5b43a3e686ed9145b6e75a81636b80382e4ad0
32d2c
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 00bbb82117c88bbd91b8954e16c0b9ceed3ce992b198be1ebfba9ba970db
d75beefbfc6d056b7f7ba1ef79f4facbf2d912c26ce2ecc5bb8d66419b379952e96b
d6f5
BlindedElement = 0200f9ed4c09f771e30913440c62139f63300f6577d31f5af0b
026ef2c7dfa438516c7265702cc9bfdba04e1bca1796447ad55fab987d4d72ee7076
5328651033581e2
EvaluationElement = 0300e69b51285e4ede2e004f360225a521c017d13f773e06
823ef36c1dec52fd1d4c986aa8d56260499a7b9e8e6675a46ca4882b27e8b1c61c7f
b2599e92ef7b764dd2
EvaluationProofC = 011c5c9ebe5e674aae19f8ca9bdada561c5602d14dcfc5706
01122e169c0053f287cce030f73481b769d648ab4187e5318456787a61bdc046b37d
3cf4cd4d114b527
EvaluationProofS = 014419624b343f3fc01f78e1d46e35eafd61bfa59fcbfd6f9
509bf5ea4eedfeb4ed4bb6cafc1788bab547d73f3370dd792b625c59b6377c76b408
b20e6f0b9ca2146
Output = 4723f22c5999822817568024b45c910e7e596a44fd320ad8cca5abbb83d
86c6dd1fa15fe0e3f35bad25ec514d76c6be20ae2fed76aef3ad13b9e880100ec391
9
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 009055c99bf9591cb0eab2a72d044c05ca2cc2ef9b609a38546f74b6d688
f70cf205f782fa11a0d61b2f5a8a2a1143368327f3077c68a1545e9aafbba6a90dc0
d40a
BlindedElement = 0201dfa5dc7ea17f0cf60caa26d2a488e7af296268834b35eaf
f497488a211670008a74ed649b20379ab63a3ff8f2dd718f5418cb30ec317e68b5c8
014a577b19710a3
EvaluationElement = 0201fb53da2469a1f68a7a16116c73bb72d25b8d25f8d4db
a00fd0f557bc24251f23ec5884c746d5d4b257fc713584c53fee638541d3b892e175
15386e3b2c87c0afb9
EvaluationProofC = 0197897d8f949a90c9673d047e46e109fc86b23656c1e9ec3
093cb6cf3fdc0ee49017dcde9d8bf7654f518711076a37a871a013e4e617f01c5570
03f8d8c737fc4b3
EvaluationProofS = 00343663ecf67a038f2d4c6585e448bb71c43dea3ce4410c9
11acb26c882fa7e1310587e04dc5e15b48ba61d76a0ec38ded2faacf0be96ad818f6
e50297dee778a11
Output = e2692004bbb1d0952b7798607ab10765a3c60251d4d068307c56d756f49
90839ea875e0054e6be3f192f89befdb097b75d95a665885c12f98e5778261042193
3
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 01c6cf092d80c7cf2cb55388d899515238094c800bdd9c65f71780ba85f5
ae9b4703e17e559ca3ccd1944f9a70536c175f11a827452672b60d4e9f89eba28104
6e29,00cba1ba1a337759061965a423d9d3d6e1e1006dc8984ad28a4c93ecfc36fc2
171046b3c4284855cfa2434ed98db9e68a597db2c14728fade716a6a82d600444b26
e
BlindedElement = 0300be204aba0367d902f293aa8bda66a136f7e3962dfafab88
ba04aacf62a4e63993060704cd1714cf7af4e16ea0a1c91ff7506a65b40253f6ae01
9b7a6160d50c814,0200082b5f723e4a635902e5bbf27fea807792399af5ac8d276b
c6aa62bc1685cb6bdb2ff1c92979d4413da3627df180d709ddd03597fc8f095c6826
fd97e8adbceca9
EvaluationElement = 020181096cc2eee197188ea9d8ec582e02453371270ed3a0
fdbd397953603ced627f5fdaa66696c684e66b7263cf1f0b575792fab24dbf3ebb9d
b2a706f52c561574a2,03019c5e0b12eb9352e8a6565108863651730e57a97e58e91
68ee3a8798ec44122ae07368d54ce8b0cc00196099e6af6aaf7d9f99108874f50acb
13692dac81af0a0f0
EvaluationProofC = 0196e71b66ab219da00e507ed0af3597640c904221e7b688b
cb61017c90ac62f3ab6a6fe33407bcbddf95484b634d8fac567c95308d82c69f2467
7499c784ddf4358
EvaluationProofS = 01caf08ecf805d7aaa5daa0a5882e74b498abff728e463433
d33a40e7b758ae695e0f4a3a3654efe6d9dadadd911946ccf501b6b703f380c18c7a
87db844a9f0aa80
Output = 4723f22c5999822817568024b45c910e7e596a44fd320ad8cca5abbb83d
86c6dd1fa15fe0e3f35bad25ec514d76c6be20ae2fed76aef3ad13b9e880100ec391
9,e2692004bbb1d0952b7798607ab10765a3c60251d4d068307c56d756f4990839ea
875e0054e6be3f192f89befdb097b75d95a665885c12f98e57782610421933
~~~
