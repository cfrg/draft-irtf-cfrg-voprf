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

[draft-06](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-06):

- Specify of group element and scalar serialization.
- Remove info parameter from the protocol API and update domain separation guidance.
- Fold Unblind function into Finalize.
- Optimize ComputeComposites for servers (using knowledge of the private key).
- Specify deterministic key generation method.
- Update test vectors.
- Apply various editorial changes.

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
For any element `A`, `p*A=I`. We denote `G` as the fixed generator of
the group. Scalar base multiplication is equivalent to the repeated
application of the group operation `G` with itself `r-1` times, this
is denoted as `ScalarBaseMult(r)`. The set of scalars corresponds to
`GF(p)`.

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

  proof = GenerateProof(skS, G, pkS, R, Z)

  return evaluatedElement, proof
~~~

The helper functions `GenerateProof` and `ComputeComposites` are defined
below.

#### GenerateProof

~~~
Input:

  Scalar k
  Element A
  Element B
  Element C
  Element D

Output:

  Proof proof

def GenerateProof(k, A, B, C, D)
  Cs = [C]
  Ds = [D]
  a = ComputeCompositesFast(k, B, Cs, Ds)

  r = GG.RandomScalar()
  M = a[0]
  Z = a[1]
  t2 = r * A
  t3 = r * M

  Bm = GG.SerializeElement(B)
  a0 = GG.SerializeElement(M)
  a1 = GG.SerializeElement(Z)
  a2 = GG.SerializeElement(t2)
  a3 = GG.SerializeElement(t3)

  challengeDST = "VOPRF06-Challenge-" || self.contextString
  h2Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(a0), 2) || a0 ||
            I2OSP(len(a1), 2) || a1 ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            I2OSP(len(challengeDST), 2) || challengeDST

  c = GG.HashToScalar(h2Input)
  s = (r - c * k) mod p
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

  Element B
  Element Cs[m]
  Element Ds[m]

Output:

  Element composites[2]

def ComputeComposites(B, Cs, Ds):
  Bm = GG.SerializeElement(B)
  seedDST = "VOPRF06-Seed-" || self.contextString
  compositeDST = "VOPRF06-Composite-" || self.contextString

  h1Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(seedDST), 2) || seedDST
  seed = Hash(h1Input)

  M = GG.Identity()
  Z = GG.Identity()
  for i = 0 to m-1:
    Ci = GG.SerializeElement(Cs[i])
    Di = GG.SerializeElement(Ds[i])
    h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
              I2OSP(len(Ci), 2) || Ci ||
              I2OSP(len(Di), 2) || Di ||
              I2OSP(len(compositeDST), 2) || compositeDST
    di = GG.HashToScalar(h2Input)
    M = di * Cs[i] + M
    Z = di * Ds[i] + Z

 return [M, Z]
~~~

If the private key is known, as is the case for the server, this function
can be optimized as shown in `ComputeCompositesFast` below.

~~~
Input:

  Scalar k
  Element B
  Element Cs[m]
  Element Ds[m]

Output:

  Element composites[2]

def ComputeCompositesFast(k, B, Cs, Ds):
  Bm = GG.SerializeElement(B)
  seedDST = "VOPRF06-Seed-" || self.contextString
  compositeDST = "VOPRF06-Composite-" || self.contextString

  h1Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(seedDST), 2) || seedDST
  seed = Hash(h1Input)

  M = GG.Identity()
  for i = 0 to m-1:
    Ci = GG.SerializeElement(Cs[i])
    Di = GG.SerializeElement(Ds[i])
    h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
              I2OSP(len(Ci), 2) || Ci ||
              I2OSP(len(Di), 2) || Di ||
              I2OSP(len(compositeDST), 2) || compositeDST
    di = GG.HashToScalar(h2Input)
    M = di * Cs[i] + M

  Z = k * M

 return [M, Z]
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

  Element A
  Element B
  Element C
  Element D
  Proof proof

Output:

  boolean verified

def VerifyProof(A, B, C, D, proof):
  Cs = [C]
  Ds = [D]

  a = ComputeComposites(B, Cs, Ds)
  c = GG.DeserializeScalar(proof[0])
  s = GG.DeserializeScalar(proof[1])

  M = a[0]
  Z = a[1]
  t2 = ((s * A) + (c * B))
  t3 = ((s * M) + (c * Z))

  Bm = GG.SerializeElement(B)
  a0 = GG.SerializeElement(M)
  a1 = GG.SerializeElement(Z)
  a2 = GG.SerializeElement(t2)
  a3 = GG.SerializeElement(t3)

  challengeDST = "VOPRF06-Challenge-" || self.contextString
  h2Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(a0), 2) || a0 ||
            I2OSP(len(a1), 2) || a1 ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            I2OSP(len(challengeDST), 2) || challengeDST

  expectedC  = GG.HashToScalar(h2Input)

  return CT_EQUAL(expectedC, c)
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
  Z = GG.DeserializeElement(evaluatedElement)
  R = GG.DeserializeElement(blindedElement)
  if VerifyProof(G, pkS, R, Z, proof) == false:
    ABORT()

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

  opaque output[Nh]

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
distinguish client inputs to ensure the OPRF results are separate.
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
For each ciphersuite, contextString is that which is computed in the Setup
functions.

Applications should take caution in using ciphersuites targeting P-256
and ristretto255. See {{cryptanalysis}} for related discussion.

## OPRF(ristretto255, SHA-512)

- Group: ristretto255 {{!RISTRETTO=I-D.irtf-cfrg-ristretto255-decaf448}}
  - HashToGroup(): Use hash_to_ristretto255
    {{!I-D.irtf-cfrg-hash-to-curve}} with DST =
    "VOPRF06-HashToGroup-" || contextString, and `expand_message` = `expand_message_xmd`
    using SHA-512.
  - HashToScalar(): Compute `uniform_bytes` using `expand_message` = `expand_message_xmd`,
    DST = "VOPRF06-HashToScalar-" || contextString, and output length 64, interpret
    `uniform_bytes` as a 512-bit integer in little-endian order, and reduce the integer
    modulo `Order()`.
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
    "VOPRF06-HashToGroup-" || contextString, and `expand_message` = `expand_message_xmd`
    using SHA-512.
  - HashToScalar(): Compute `uniform_bytes` using `expand_message` = `expand_message_xmd`,
    DST = "VOPRF06-HashToScalar-" || contextString, and output length 64, interpret
    `uniform_bytes` as a 512-bit integer in little-endian order, and reduce the integer
    modulo `Order()`.
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
    "VOPRF06-HashToGroup-" || contextString.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, L = 48, `expand_message_xmd`
    with SHA-256, and DST = "VOPRF06-HashToScalar-" || contextString.
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
    "VOPRF06-HashToGroup-" || contextString.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, L = 72, `expand_message_xmd`
    with SHA-512, and DST = "VOPRF06-HashToScalar-" || contextString.
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
    "VOPRF06-HashToGroup-" || contextString.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, L = 98, `expand_message_xmd`
    with SHA-512, and DST = "VOPRF06-HashToScalar-" || contextString.
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
seed = aca1ae53bec831a1279b75ec6091b23d28034b59f77abeb0fa8f6d1a01340
234
skSm = 758cbac0e1eb4265d80f6e6489d9a74d788f7ddeda67d7fb3c08b08f44bda
30a
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf
8e03
BlindedElement = 3c7f2d901c0d4f245503a186086fbdf5d8b4408432b25c5163e
8b5a19c258348
EvaluationElement = fc6c2b854553bf1ed6674072ed0bde1a9911e02b4bd64aa0
2cfb428f30251e77
Output = d8ed12382086c74564ae19b7a2b5ed9bdc52656d1fc151faaae51aaba86
291e8df0b2143a92f24d44d5efd0892e2e26721d27d88745343493634a66d3a925e3
a
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037
e50b
BlindedElement = 28a5e797b710f76d20a52507145fbf320a574ec2c8ab0e33e65
dd2c277d0ee56
EvaluationElement = 345e140b707257ae83d4911f7ead3177891e7a62c5409773
2802c4c7a98ab25a
Output = 4d5f4221b5ebfd4d1a9dd54830e1ed0bce5a8f30a792723a6fddfe6cfe9
f86bb1d95a3725818aeb725eb0b1b52e01ee9a72f47042372ef66c307770054d674f
c
~~~

### Verifiable Mode

~~~
seed = 23ad84086377ae0ac20acfcf143a9b5c34be63758b94f7ed0a8485345a748
431
skSm = 8d30b6ed995e28692f9ae5517ad4d974395605fd31cbe65b47f88822a142e
d05
pkSm = c447ae83e5ea5a070c3b35ca0926460020378fd48402b54a7ba2e36b48011
f0c
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e326
3503
BlindedElement = 9cf00acd9be7d00b87012823aec2480afac98468fc7e0766e52
c2c42eb66802a
EvaluationElement = a0a6cbd69a6c3c84bf84ae2b2178debe5ca2d7de8c0c3439
e340f503e87f9b65
EvaluationProofC = 4c1e61ab430c2026b14dbe2df62d64bf5b76001edc0ac5e84
b0b50b09977da05
EvaluationProofS = 490660d2a0974c09ab13a10091f70d21e6229638c4e6a902a
7a0530962cd990f
Output = 960fb25a94db326205638c0d02c87c064445514e30d539acecb440b36bf
74c7182a915b7b900ddeab239d4fe73ebcb451e05a4aacb8a05cfd403327b4606f27
a
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd4171
ea02
BlindedElement = 9669e8326632c31ddac138b1da65cf39bdc6fa085050f5afd2b
fedf3dc1a3313
EvaluationElement = dc1bf956f7ee401ff5fd1ab206ac13ead704d609ce81469a
9710cde58ef9bc7c
EvaluationProofC = 44d8c86b857be2321c2ddf75898508e0f9b56e96ea21c76a8
ddc2f229ff4bc00
EvaluationProofS = cec985971cfb2b5747374d85527a58b0a69ce906e5f9eb2fd
56c56b409e51e02
Output = fce0ce88eda349292e209eae49032e03bc73a756a5093ca380b0f59db94
2783aa29396bd2215a721e55a71c166586d3b867e5673713951f79c2499f75a7fa0e
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
EvaluationElement = c2860fa4213e425c1e5eebff92bbb8e532389b8871fae9fa
f2348718483f6c05,9618bb1dee5a94017e020993ad7cb0cfb4b5d5b70538ce85680
acd3b9348757b
EvaluationProofC = 8ecc6109a673872da634dbaa091674a255866599e380dc6c2
12e163f976b7706
EvaluationProofS = 0949b5e1705ba2c76d179deef6c45891cc38a0515010be0a9
007bf9471c7fe0e
Output = 960fb25a94db326205638c0d02c87c064445514e30d539acecb440b36bf
74c7182a915b7b900ddeab239d4fe73ebcb451e05a4aacb8a05cfd403327b4606f27
a,fce0ce88eda349292e209eae49032e03bc73a756a5093ca380b0f59db942783aa2
9396bd2215a721e55a71c166586d3b867e5673713951f79c2499f75a7fa0ed
~~~

## OPRF(decaf448, SHA-512)

### Base Mode

~~~
seed = 22bfaee29297b24011e2635ddcd67155ec1805954faa50deb34d937143b4a
eea23dcd5713571c0ab8d1810efe2749a23c323e2eb757f1f75
skSm = 4b2674b32c4975645382b98f2cd8401eaf90a48c5be505118bc674eca46e7
422042565e51ca263bb8b4285d7f0f099835da2d4a4ecfccd39
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = d1080372f0fcf8c5eace50914e7127f576725f215cc7c111673c635ce668
bbbb9b50601ad89b358ab8c23ed0b6c9d040365ec9d060868714
BlindedElement = 0e5e2ac2924bee04fa1ae372a6a26f6f71972372494c08433d6
766aeb103c2aef393e06cdc52ed270f1c94e4538068ab724d84ad217f7b2c
EvaluationElement = 9837f23012ebd3f817e597481b03d6da85b17d16eee4c5f4
6986355a751a348d0911b141173b40d0dc0c97792fc4a0749c1b9586cfab0b6d
Output = 9139010e665e84800d86d912c5ea0407b51efd3fb9fdad5fc661964a15a
1591e35f22d5d5dc14f4f68456987702863642eca5fadbc8ad5e07732d0a8c589813
3
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = aed1ffa44fd8f0ed16373606a3cf7df589cca86d8ea1abbf5768771dbef3
d401c74ae55ba1e28b9565e1e4018eb261a14134a4ce60c1c718
BlindedElement = 0016392cdfbe773dd6740eaa7b41ad19b62b7552a5fff88a337
90391c656726e7c7b346c2d6989085c6bc11b31a14b15ba2340f776891dc0
EvaluationElement = fc0afdf7f6eaefb86c884b2dd8a21ffe8c375d1e189def2d
b0b284542be94f338bea2e341961a31d61644e01e2ff6f3d6a07dd5212fda0c7
Output = 52f8970ec1ed4759758135e5526422d0dfb912b45a963a0e94ea8aa27c0
54b34c8eb1b5bb65bb3ea45dbb58e1da99046658669cc5161c20d5f948f9a7fce0a0
c
~~~

### Verifiable Mode

~~~
seed = 9cd0d686c7af3459483e2dcd807912748650131d61c654dd0657213eea091
03b13290911110f36b27e2d1a73660fc7c7dc7d2243f5c56c35
skSm = 2e233ab9d5a9300c0c8af8410b819eff8c47ddf6a65daddf046ee1ef91b05
89b39bad3b5ac2cf6b0263c201dd98bf79fcd9eee79d2890f34
pkSm = ac0a06cde8eddf02a5fb710537e00ffcac23ca6de5c744309366fd7fe71b7
1a135a7977c763c457d0449d2fd627132817036349e65adcbf5
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 4c936db1779a621b6c71475ac3111fd5703a59b713929f36dfd1e892a7fe
814479c93d8b4b6e11d1f6fe5351e51457b665fa7b76074e531f
BlindedElement = b06491721a030478fcf4756de92f0937e29a3898496964636be
0c9c884a3143a933dcc085e9a0303bde79b3ebdc77448eaa80203d7b57c40
EvaluationElement = e20b32caa3976efe88ff6104ae69d1e4110ce8d536e7b8d6
c42e9d3188ceacb11c759f2e6352d1ea52272b018e0a6c30da35f2ffb4d53f50
EvaluationProofC = 75162c17aaa22c38538ad5d3bb1dab6b7dde1410f76f58de2
5fe98e90c3d43a6532f6277ef45c424deeb4b0f4105bf3edbbef9e8d6327330
EvaluationProofS = 6e6cb40e86974de14f2a96a87d8e4b78f31a92b67a2232f44
39d0d28e65a79e2b764006c11b89620e15e826bc6ffb22c4e3c3c41593b6830
Output = 727b216c822412144797413444bf52bde9a7e3d0e0b8a18fbce80316914
01992cc413951da6f2e557833bf5ef227260ea508f7e2fb7fe221adaa98c8d990177
a
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 15b3355179392f40c3d5a15f0d5ffc354e340454ec779f575e4573a3886a
b5e57e4da2985cea9e32f6d95539ce2c7189e1bd7462e8c5483a
BlindedElement = 3ea98d0d80c5e34582534f06daa3f5747d594fc271dddf4bcb9
034442eb01564ad92e4a4340f2c9e40f4f212a0a7cdc7bdcad3b8cf83998f
EvaluationElement = 4a981797731fad28fac6c9423eaf3d4ec74214ef38edc8a6
33cbe8912d1ec157ecb34f8b10f23eb67f7dbc35764b0e37d02e3e3254793a45
EvaluationProofC = 3ec1c00ad2821e528058ed30081e6a1cd5f344a45e9bf51eb
9a34895b680b88c20d9464023ae8e754c208a9792af139a2f5a6ab43b266924
EvaluationProofS = 0063bb1ffffe2e2ec2d22d7b9fa61d8d8914b5599eaaf8998
6d41201b9baa51b9393cce63e7ea7e5155fdf6c7747ddbd999d1818a06b9a29
Output = 025579e09632d69fa8a58fb93fd7dd0b03fa719247cbe6716ebdc49e2c9
f5e10ac2ea2c17230a86d0716efd4e223e541e65cd83e8ef95eb5c212456126f75d1
6
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
EvaluationElement = 8e6630cac5c1d4d7b76b478432a9a5b633314e0880d2c026
04267ea2499998170ac84ac6ad0c71ef335ac8201ae1f9bda3d4c6873e175a88,08c
4e567eac74f299a91474d893fc204625e1e15db42b81e574950fbf0d51f78059feb0
d7a3cb528b65e81b2902fcf78f1b785bd54d90ac2
EvaluationProofC = 060ea0d134649060a9dc7d4747f9302096229bbd90d6bed3a
b2f9694cbd06e2642d12b533dab8ba3a96eb47e635c8c6ca544e5f74b2c4535
EvaluationProofS = f15fabd7dfb504b9473989366b19b6d3576d8c64670099f66
a41756e6dcbf854100dc33ce97d27599f5dfe388ba1efb36ca4737de11b1403
Output = 727b216c822412144797413444bf52bde9a7e3d0e0b8a18fbce80316914
01992cc413951da6f2e557833bf5ef227260ea508f7e2fb7fe221adaa98c8d990177
a,025579e09632d69fa8a58fb93fd7dd0b03fa719247cbe6716ebdc49e2c9f5e10ac
2ea2c17230a86d0716efd4e223e541e65cd83e8ef95eb5c212456126f75d16
~~~

## OPRF(P-256, SHA-256)

### Base Mode

~~~
seed = 3eff673ea2fb8669d141dddd1af5a7e43f97f3e00e00273f6435d8407ec93
322
skSm = 95771c829754f4bec369da4f9502fbd709b5b98a260ae720fe41661868639
b20
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 5d9e7f6efd3093c32ecceabd57fb03cf760c926d2a7bfa265babf29ec98a
f0d0
BlindedElement = 02f09475852ef62318680a3ea1319d0474dfabc4402b752ec94
7c8a37c5c1491a2
EvaluationElement = 03b304fc1030556762e95ada14aaf68358a68cc66efa231b
5a6014daff0d75f239
Output = a7bb47cee7f531bd5dc412a4a14b10c6fe532c5e9e74a7509a4b2349311
b01a8
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 825155ab61f17605af2ae2e935c78d857c9407bcd45128d57d338f1671b5
fcbe
BlindedElement = 02589019677db1bca1ca2f94da740691016578952337e2d19e0
7d1de0d26563c4f
EvaluationElement = 02d26a438f0b7fd11950ddca72f9d8302c3c9363c596255e
544f3cc1680736d6d1
Output = 26918fb45d5aa80e101954ac6f6455497aab7423e7271571f87fad343c3
93dd1
~~~

### Verifiable Mode

~~~
seed = ab2f339a7220e50cc4dc9da84913863596593d9ead69c6a61cf50d8da5cdf
079
skSm = 0773c16f0faf8a5d3e8f76631600d5d5837cb65192531d8f06add8151c895
923
pkSm = 02715ccbcb67ce334bc6527dfbc795aea8839d13c888eeae822022ff8062c
c7e5b
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = cee64d86fd20ab4caa264a26c0e3d42fb773b3173ba76f9588c9b14779bd
8d91
BlindedElement = 03458b1f2964895be9500419f7252a5f899932a0e1a80dad2a5
8c93205d87c189c
EvaluationElement = 02f33b62756f2af3e7789adb228a69d6a477fb9c71ff0bf7
31f9e1688fed173856
EvaluationProofC = f20cd08a2fc81ac3379f1704cb1e63fd7d206fab9b0d8aeda
4d3814e2d21ac83
EvaluationProofS = 85ca571b54edea4b8bce2247c37cdea760aab6f480286e871
d1b5aaf8354fe7c
Output = 307bce9725d306e5b28c589084e9458985d57e482c8a4e92bf2ffd1e236
3672d
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 5c4b401063eff0bf242b4cd534a79bacfc2e715b2db1e7a3ad4ff8af1b24
daa2
BlindedElement = 02b600c8cd1f859fb7a87a1c9298b68d12902e4d093c9573af0
6b1b376c58e6623
EvaluationElement = 03af5ace869c4c48a4d169f72a5d78fa806c566f36dbd73a
40372373b5ff5b7d47
EvaluationProofC = 31b202d4df078ac8def9054a29ee0dce585fbff4384763606
c16bd2489b9507e
EvaluationProofS = 1cfc5ab981b3da6a9ee344108fb1e2547e7817ec7f1966638
6014b4950f62230
Output = cba462665ec1a01c302a05f2c29a2e4b5282ee639db91460f63353999ec
6ac53
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
EvaluationElement = 03f7c0a0373e2bf57d0f86d92ad1e8d97c009a420d43706e
f3ba5707c8b0fb4b85,02b14ee68ff6194b8be68a72f6968f62f53018699694f3ada
bc5825f7181cf60d4
EvaluationProofC = 0785f1389d3e9e91e5514d97d192f8f35cd5288b52b750332
e7ae696d350abc2
EvaluationProofS = b0e8ee29aabee13fa30833e9c55b9c657d1b52e6599058432
3825ed6c596f9b2
Output = 307bce9725d306e5b28c589084e9458985d57e482c8a4e92bf2ffd1e236
3672d,cba462665ec1a01c302a05f2c29a2e4b5282ee639db91460f63353999ec6ac
53
~~~

## OPRF(P-384, SHA-512)

### Base Mode

~~~
seed = 63e92b15555b6cb760d44daf230782c763430c860fcac60eac7508526b79c
96cdf05f0489f13a1196b4d5cabc8f257f3
skSm = 8abb9c0771d2fd11ffb7d84ae7623d32c92a8688f7ab4110f041cba48990a
533f4c5d6d396e75ceeddffda061301f0ff
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 359073c015b92d15450f7fb395bf52c6ea98384c491fe4e4d423b59de7b0
df382902c13bdc9993d3717bda68fc080b99
BlindedElement = 022250ba7604814ab2058e70fdc5dcf2604afb3ab6e15fc97c5
14973bb5e574d586ce518700ad0dd02b54982ce202020e1
EvaluationElement = 02779e7450227d438ee2b24d257cad8ec842fe6b1f1ed55e
fdb65c07d3058036759059b8f4bbdbae3d5db0b7444b276a43
Output = 26668250052b501b6d884549726eaf95094a4c249eb83ff6c90fab0e798
88b0b3fdbb449e22d42834377d3a990087fe0b33a20ab60ce1a0b0d75d09c08c7c76
4
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 21ece4f9b6ffd01ce82082545413bd9bb5e8f3c63b86ae88d9ce0530b01c
b1c23382c7ec9bdd6e75898e4877d8e2bc17
BlindedElement = 022dd0addbced4c8ea73eaa8e38f43506a7c3f98288ed479725
d596fa3a578f728915414f5df77084cadefcd5e4662f6df
EvaluationElement = 0274578679fbcff1a9d8e5fedf024361a039915b7e347540
960f24fb7434b1d9b54655e91237226234182f2515e1d50501
Output = 4e603ffa07b244507b6939359caa372a27793c65a08027df9859fe768cb
c0d454803d6929d95a7a0bf399065d91140a559e627d9b2386fae03c3d8c4f9ad9c4
f
~~~

### Verifiable Mode

~~~
seed = 1ce2b395fbc9b0c94142ca50b5237fbf30955deb98195e4a8f9b85b14cbfb
a7a12c9fe2fa70222086298dce67fc0ce56
skSm = b33d6912f3d98f4127eb29022196ae5fd203875953fdd00eed62588cf7511
9c594e841c2caea2b7eac83bdf6f26e9b4a
pkSm = 029668c6874e11fb84c854653910bad621060af56e3beaa459a454ac9d8d6
90092aa5361739737da93327a76e219fa6155
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 102f6338df84c9602bfa9e7d690b1f7a173d07e6d54a419db4a6308f8b09
589e4283efb9cd1ee4061c6bf884e60a8774
BlindedElement = 03c267661f12013daa1e4fe319713adde264a37bea8b91c5cb2
71e9e3ee12e5ed829f5a7a23aa4803704381e638a927e3a
EvaluationElement = 02711fcd5e6f778121ff23f40fbbf0280ff022f61437be61
931126244a0c5ab3ad80bb28eb5112f750e82bb2951d39ccf1
EvaluationProofC = 51ead6a0432a4d5c355fc58c075d420907e1155703a9df21e
51128ed900391e5e4aa6b14d7d5a1df271c7c8e816363ed
EvaluationProofS = 88a8510e0aabfd3d0957616adc007508d030e21d695a768df
57b1db194847f4e93aa89cdb553c5d9ebc141f4a0bb9369
Output = 1512d25e41336b8975d51e061f3ad8ca79f76fb6c5467526c9fecfd38cf
e7d811fc969d10c9caa87190a3879004e9bcbeef8904f4c644cb378bf461c237fff0
0
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 8aec1d0c3d16afd032da7ba961449a56cec6fb918e932b06d5778ac7f67b
ecfb3e3869237f74106241777f230582e84a
BlindedElement = 038f7b700d59fe135484a799fa10bb761b622d29a606ef9ecb5
b922409de93473c850bbccfd449a9cd1c352021faed9285
EvaluationElement = 028bb86d62701dd511ae0e7d074ed46519c71d3d8b82be23
6e17de883e41e2c5d0d779f75c59fcdd7b21a7aebdaddb1294
EvaluationProofC = 4ad66d430fe36eca8dd13d72b8a79c14afe42dd8b78196cef
650c6c9425c01cc269ddcfb435db06924047fdfa32d87fe
EvaluationProofS = d8340cbcbf1bc19afeca7bac68610b6101588b99a99cea1dd
5aa7824d0f7cd188204883f20252d23e453ee7d2dea6a54
Output = 2fed20cb0c1bcda344057b5c16faa96cc62a9ae6572a94a175b1a2742a2
d299ff95de6ebcfe6ac1859d88cd154c1498a22ce7578ed2d1beca5c21f9857f0207
d
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
EvaluationElement = 029a2f611bd2f4346e9f834e91c6828354fb49262e60473f
a494b65be33478bcac5e253878be75613beffb45da0ac3c3a0,03fc35912f5f1642c
75bbbddbd6844861eef94ab435ea63292e3c073b8af4f3c2c20db0741b5a167acf5e
3f92b8eeceeb5
EvaluationProofC = a3009c06dd2c102d748bb7d3bc873fb6bad12aa310f6ca83a
2d9591109ef05211789c9876704e043054ebd4bc11e62a8
EvaluationProofS = 861ab3ea88d2e428d0ca95332a7ccb3f3d71c5158502925e2
3d4ee84b1f4619302ba7bd4822538be223bb22f6955cf39
Output = 1512d25e41336b8975d51e061f3ad8ca79f76fb6c5467526c9fecfd38cf
e7d811fc969d10c9caa87190a3879004e9bcbeef8904f4c644cb378bf461c237fff0
0,2fed20cb0c1bcda344057b5c16faa96cc62a9ae6572a94a175b1a2742a2d299ff9
5de6ebcfe6ac1859d88cd154c1498a22ce7578ed2d1beca5c21f9857f0207d
~~~

## OPRF(P-521, SHA-512)

### Base Mode

~~~
seed = 860941f8d1d28513d9b38da971d0291cb2532a9dacc9256d5eaaa022e3f32
bb447479ec7d6bc8204328b9f28fb3ccf63ebba9e02837c8386e7a50f6cb210467e5
78f
skSm = 0095b985908df61dae8bf8c037488cafea62377af2a2f41030f6dd8b3c750
237c241ad68e7f07682d422fc2395008a3811675be0a53a58c4dae4b5974ad11d6f8
4d4
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
EvaluationElement = 0300b7706ad75473f5265a4456b3fbc61c998895cc157cb1
f48ba433f5fc3cb9caf845aa959b89eca919aff08f19d38d195a9fa7c0862362e681
09a45f980b124e5be0
Output = 3a34c3c5c87a7d14617e3f20fb76b861f6db25b0074369b80e5256dd30b
8a749393f90e7bcea80c844fc1bbdc62d52a80c6c648fb3e470d39ea4cd98138a819
f
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
EvaluationElement = 020182d03c2244a6be2246f023ce67cd876b88dc75ebfcad
d0c952f6cc4ec7f47c31b2f019e8091e999f866ec3110cfd7c84e91c4185dab1e2bc
5cdd9e87662276ad85
Output = 105da360c0bca0e14a645cbb8b93e0033d061f3351ac494882c9a00c9c6
0263a17382bcec7bcf96a96a41800de007a5313120ff6b96ec236eed872a4de23f70
d
~~~

### Verifiable Mode

~~~
seed = 2d317f9cfdbedf19e3b3264399ffbac20c1c39899b50af2f0abb24177ddfc
5b0682e6ba98e41e90814b9b8216d82c211be6a9f886b5f73f49188ba7aeb7fab828
d0b
skSm = 0097bfe7b0db0760d3d062be371d5fb9ae91f75221dc7b24be288deec3dac
d049f79ed8f5ae99d825970b37c398ea01e8a3e14209fb2e8f53be8dd98b63626ab0
df6
pkSm = 0200641f1fbe204bdf4f47b358a3daa1f0c68ca55e39716178ae7804c5b86
faf4822bcffef994411eee7bf8d708b42b5d02b7fc13de3ab14cf3fd1ca24d9d83e9
f3db9
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
EvaluationElement = 0300c69b7af34014ec66228f8109a71294e86b232a500ca4
a8e5c29f105a7c078f08eaeb1a29dbf8c1baa64976097c938f721686aac8f22b5b4c
f09147606d07bedd14
EvaluationProofC = 0180092b8c106e6453eee63718642a11580d3943947940e71
abc67d961693153e32f8c3428514c3f32bbf04cd2cee437f5dad3de81802ee259aa6
9f14de908c4af1c
EvaluationProofS = 00010c5168438bcfb0fcdd5737416ed4c2f3ab9fdd70d5552
721444872dd6dda4c7324eade2460aa1cd193b2f2b99f7651f090a163ddab135d69e
73e816a0e5cb101
Output = 5d6bb0a459ebabdc24f4eb1f2d5ba84967b5362e28b4263113ae82f64b6
16b14675c300a80d1a29f3b9f43c7c115d76a55b69785925b193d0742e32c7c26abc
2
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
EvaluationElement = 03008ec6ce61d8438ba2d10d83a476ba8cc28d7e385e2ea6
357ac00226491fa9b037d14775bd0beb152ba0b1559979f0d186fcd3b76983d1a25f
9a958d71eba5564e4f
EvaluationProofC = 01dfab8e49173c15e3fe755b6d0d18181eb6f223cd44c4d8c
3bb67727cabf209d95858fe82ecfab0ed6958bd088567cc759d7fe2d00be07973248
b5154f567598443
EvaluationProofS = 017a99db7e59297be3bee22d7de9f7939dbf55a3d0d3344ec
61f44be16ef2aed795b355a1fb583b5bef5aefe105f7ffa2e0feb063d56be48ee8d5
a43fdf4f11f9339
Output = be1882653a80f060f3c65f654270c202abbc5be961cb8c79ff952f2e284
a82ba087e8c26f06c43c98518b0b75940d061a3f5665557e292cee9e86487be05bba
6
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
EvaluationElement = 0200482edc448a8be76098f64ff783309b7e5c1e8882b7e1
c25c05308ce594063252e5b6ff7ea52621d56762ae4dbac4ff38be14608a5f967667
79d331e65964823d80,03008c0faeb5ba9eaf1c2303e2dbaed68274b77898455a944
fab83603c5495e4ec74adcc3bf78cdacdac6996d657f6f163e82680987f0ded2062b
ee712843c4ffaf054
EvaluationProofC = 0008ce3eb07c5b4b230c1e7424d3282ebfa665aee41f69860
a64312d706361cb3c2704b12490f5e0d58681c91cbea4f53cbd1d4925c450b2ed9b4
b1ddfa92cb30cbb
EvaluationProofS = 00b5521b8a33efb3bb0e1c02f5d93b3fb9d8f6531085a7117
cd78cea125bf20eaeae59a179067d45119b34f2ef82f71e54bda17440c3e27f04d50
04c49ab25a62add
Output = 5d6bb0a459ebabdc24f4eb1f2d5ba84967b5362e28b4263113ae82f64b6
16b14675c300a80d1a29f3b9f43c7c115d76a55b69785925b193d0742e32c7c26abc
2,be1882653a80f060f3c65f654270c202abbc5be961cb8c79ff952f2e284a82ba08
7e8c26f06c43c98518b0b75940d061a3f5665557e292cee9e86487be05bba6
~~~
