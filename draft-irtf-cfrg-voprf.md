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
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, L = 48, `expand_message_xmd`
    with SHA-512, and DST = "VOPRF06-HashToScalar-" || contextString.
  - Serialization: Both group elements and scalars are encoded in Ne = Ns = 32
    bytes. For group elements, use the 'Encode' and 'Decode' functions from
    {{!RISTRETTO}}. For scalars, ensure they are fully reduced modulo p and
    in little-endian order.
- Hash: SHA-512, and Nh = 64.
- ID: 0x0001

## OPRF(decaf448, SHAKE-256)

- Group: decaf448 {{!RISTRETTO}}
  - HashToGroup(): Use hash_to_decaf448
    {{!I-D.irtf-cfrg-hash-to-curve}} with DST =
    "VOPRF06-HashToGroup-" || contextString, and `expand_message` = `expand_message_xof`
    using SHAKE-256.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, L = 84, `expand_message_xof`
    with SHAKE-256, and DST = "VOPRF06-HashToScalar-" || contextString.
  - Serialization: Both group elements and scalars are encoded in Ne = Ns = 56
    bytes. For group elements, use the 'Encode' and 'Decode' functions from
    {{!RISTRETTO}}. For scalars, ensure they are fully reduced modulo p and
    in little-endian order.
- Hash: SHAKE-256, and Nh = 56.
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
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 031806835f6808c8ac3808672e25a7802d94346bb33b52d712331f34faa64
d08
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf
8e03
BlindedElement = 3c7f2d901c0d4f245503a186086fbdf5d8b4408432b25c5163e
8b5a19c258348
EvaluationElement = 1a34dc32aa2a725530c9d4d32485427889e8e97f4e9d353d
19096ed3d83dd93e
Output = 6b6e7c7820a781f6d2b01d54df03afcf3c3a6769fca4ea9afbde6a00034
17cb13feaa6362979c8d48541b675584cc0d15ace06488c37681fc75b13e2fa94c2f
1
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037
e50b
BlindedElement = 28a5e797b710f76d20a52507145fbf320a574ec2c8ab0e33e65
dd2c277d0ee56
EvaluationElement = 5a085a73daacdbf274dd3fc2e539463d2ebb6ba73ebcdbce
24a86e85e2268616
Output = ef537f82bfa935b942c2490bf4974e59ec95db16f48a952053fe34967bd
ea1c7a6d6f624d5ad80e412d132c123cd96c40bde77bbb0d73b407ef5241a36b69ec
e
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 031806835f6808c8ac3808672e25a7802d94346bb33b52d712331f34faa64
d08
pkSm = 2cb7002ab1fa2b15d873f897b89402bdbc9f97b21762f3fc185cbba6e5718
903
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e326
3503
BlindedElement = 9cf00acd9be7d00b87012823aec2480afac98468fc7e0766e52
c2c42eb66802a
EvaluationElement = aea80b7accd371ee8960c3a59d86960f6538abef8057f1d9
8210d7e720364435
EvaluationProofC = 505093c502120000e02f015a082ab611960aa9544d379d152
e45b0caf7e07202
EvaluationProofS = ece9563dfbd6a2af2b6753caf3fb0228f16022ca51b202972
54a1e952613e204
Output = 79e119f5ff6ea18b6572792253570ac1e9a831ce76b01e214c9731f9d2e
b5458ccd320855796f5d382b61484c03f263397c81fda5915cf5cbdc0e94c7da625e
2
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd4171
ea02
BlindedElement = 9669e8326632c31ddac138b1da65cf39bdc6fa085050f5afd2b
fedf3dc1a3313
EvaluationElement = 308db64194f96845c75105ab9aa8be7fb2563ad678de8ad8
095ffa070ab9b31a
EvaluationProofC = ef31a128f65868b895a3e8aa0387951c0e7dcd1e863a1b980
b9e416d2656900e
EvaluationProofS = c8a60f50672e1bb572edf65ba563cf08371253ccf595aef5c
28f79d15f449105
Output = 92b2f2af62636725420186a41392483a69b36654e61a73c249dcc9487e6
be818af094a35cffb710bf57f02c6d38dec162533395c5975ca9ecb2266cf09f484b
3
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
EvaluationElement = 90b94ca36ee58c58f00a394535720a333fe532f99863705a
b503cccde20fe366,0c16a51a44298b96bc404046cc4e10cebfa8184583feb867cb8
ae058b1a0f11d
EvaluationProofC = d87de9a8b240e3d4f37bec9691bb278c8bdd75c11acd04207
78efe817c75b607
EvaluationProofS = 1a0de926efd4d8cc5607ecb04413cb5b3d668bd779b3c045d
1168b58af1c670c
Output = 79e119f5ff6ea18b6572792253570ac1e9a831ce76b01e214c9731f9d2e
b5458ccd320855796f5d382b61484c03f263397c81fda5915cf5cbdc0e94c7da625e
2,92b2f2af62636725420186a41392483a69b36654e61a73c249dcc9487e6be818af
094a35cffb710bf57f02c6d38dec162533395c5975ca9ecb2266cf09f484b3
~~~

## OPRF(decaf448, SHAKE-256)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 9a0d56305d39170591a216d9151c3e7643bd617dade5a7706094e0f90a970
4b31d9f9310fb85d5015e236ab088df6573a6a9f3ef16edd301
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = d1080372f0fcf8c5eace50914e7127f576725f215cc7c111673c635ce668
bbbb9b50601ad89b358ab8c23ed0b6c9d040365ec9d060868714
BlindedElement = 90d7f3c03a6e3fcbcd37b745092ae2b8de12160e9fddb06b46a
c8e1ad037c1b2b2df174d675772df5d78a7882ee0d476aa41ad0407c13077
EvaluationElement = ba5bf9e3e9722777a881fa9245b8ff45b241658fa961a9bc
4ad1a445a8769c849aad254f844c93b1c2d1e35bdc9bbe4085f5ac4a4b7717ff
Output = fceb56e33ee80555c0d6dff38702832168fc643e936af3ff17c848cad7d
abd8c9aee32fc4b79891d79bea7753c1700066b7ca40047081ec8
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = aed1ffa44fd8f0ed16373606a3cf7df589cca86d8ea1abbf5768771dbef3
d401c74ae55ba1e28b9565e1e4018eb261a14134a4ce60c1c718
BlindedElement = 9029ec8b17cbf8558773f9204df61b4a057ced8978834cafc11
39493d26f59bffc099678795192200816ad7fb8f418de7d08c90092983839
EvaluationElement = 68eeb6db51347a32d30f6fc8fb0efbfa583e036eeff7720d
c75fbf9af94e0239069616510280c9325fd7f4b3e63701b6defec0dd4754b871
Output = 574e7699db7619b921d7f2b51566417d27a7666f92343d1b2daef435ece
d67ab045be9b4817232838ff762aa36d94d8c66bfed91eb10dcb0
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 9a0d56305d39170591a216d9151c3e7643bd617dade5a7706094e0f90a970
4b31d9f9310fb85d5015e236ab088df6573a6a9f3ef16edd301
pkSm = 7c40b2dc98f2e83347d4f568cc6dba19821af97514264877f39d7c7e990e2
8283c4e2801249a6eac75ff7fe04f9a993925eb1ee94195dbbb
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 4c936db1779a621b6c71475ac3111fd5703a59b713929f36dfd1e892a7fe
814479c93d8b4b6e11d1f6fe5351e51457b665fa7b76074e531f
BlindedElement = 7a016e1db55b147a6e3528d658fb625e5fe8688f65b0d42e401
d9101ed3a40aee6e7ded38da9b1174197a5d5e7d047a8ebbee3a4705286fc
EvaluationElement = 0a364200f4c0b178b453cd844186fae523e82c8f14c383dc
8e65f174679b94bbc875cbea954ae6074eb883306c5c445ad5fa991c32f44ba5
EvaluationProofC = 57f40de1bc71f9e61cc7b17a853d86a535c298a02ec1fddfa
6eb5edb8e4b48fbf403d0fd193cc07b3f4630bbc568cd67e51d168cbad1fd03
EvaluationProofS = 5f9bd0edd8c8aa2f4cd7c72a065f4ec01138c92395f79dadc
e20b6e927f1965741b38915c74cd7dfe0608a8bdbd3453fe9e995157d9bb011
Output = e842759fc7a89da44534fe786912291f77e06d4a0fb6d2559e81d11b594
2bd7c1c84c16df5a8d65664ff241f047de6b699110450039e480b
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 15b3355179392f40c3d5a15f0d5ffc354e340454ec779f575e4573a3886a
b5e57e4da2985cea9e32f6d95539ce2c7189e1bd7462e8c5483a
BlindedElement = 20fa11f455c89e652695743789dfb6d4f5715cb65d31cac02b5
5d5b3cb5b8fbb08e6ae842b7fb7566db7484a66e499e43ac6fc0ce0d10ad6
EvaluationElement = 1a90269a9dd78c98de05e273301730b5d30c3182a2d92a78
62553a12f6c632a50bd38ea2107af804366e7136d5499952c349e3b59ae2f038
EvaluationProofC = 3852755579588106a91628255886ae70f2ad6366c4d578a99
7016d2f0415fd0fbc50669580e3ac69752dff4fc8be8f7d81502cbeb4ba0e22
EvaluationProofS = c51b20e8d554b804ccdcfb672ee75cdd009ecce665bccae80
39ab4b19d8f5cf734578e2f5ecd3258dcf86533621bf04b7446d36eeb7d6f1e
Output = 820020965fa21049d612ae86d3dd3329d10a8c369712957dea511c688d3
4bca43110aca570bc4b3f38ae5147f78b5827fc12299a10b08c22
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 614bb578f29cc677ea9e7aea3e4839413997e020f9377b63c13584156a09
a46dd2a425c41eac0e313a47e99d05df72c6e1d58e6592577a0d,4c115060bca87db
7d73e00cbb8559f84cb7a221b235b0950a0ab553f03f10e1386abe954011b7da62bb
6599418ef90b5d4ea98cc28aff517
BlindedElement = 828fbcda49d1e6adef7794ae2cb7fc9f68bab3546fb2452f913
182531f79a105d2546c9c3adc399e8253eb6d53574067488074954626610f,ba51cd
f5ad661753de5ca4c3668530040d8402f0ee2407e79ebeac565c362877432744096c
d627aa8f1d4713bc2b6319134ac26023de8aee
EvaluationElement = 0a222684975772448e9c3b34e18889936027fba5bfe47869
16d2ca23309f42ab0799a34d659df7b72aa82797976c53f8ad76ad3aa138ac30,d6d
de1ac2a7641a44892beda020a79de37bd1bcb517d670a5128f85dc234b9f27f7b96e
79eb63a21c0a1535d6be55ffac80cc5c088ad155f
EvaluationProofC = 9c1cd17657674b47baa42e0fcb5bfb30c4b0202f7cf19967d
6104ae18f2d83ed622fdc6273b6d738b10062ba57f094689c60735d3bf7ba10
EvaluationProofS = 4deaf8f66026485d7c541430c1fa31cb33ea8a8a7c0978844
bb760853fb98391d5f3fa9952ecb13a127bc7a769dd19778187ac7057f1f30d
Output = e842759fc7a89da44534fe786912291f77e06d4a0fb6d2559e81d11b594
2bd7c1c84c16df5a8d65664ff241f047de6b699110450039e480b,820020965fa210
49d612ae86d3dd3329d10a8c369712957dea511c688d34bca43110aca570bc4b3f38
ae5147f78b5827fc12299a10b08c22
~~~

## OPRF(P-256, SHA-256)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 3516210cce73c18141b9f73caa9cd61b92211d1f6d260e827fdb026541195
141
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 5d9e7f6efd3093c32ecceabd57fb03cf760c926d2a7bfa265babf29ec98a
f0d0
BlindedElement = 02f09475852ef62318680a3ea1319d0474dfabc4402b752ec94
7c8a37c5c1491a2
EvaluationElement = 02ba7d9df4d2a6353787470e538fd95da10bf11ed406ceae
b59cff56e89f53e51c
Output = c4aaadb1b23c48239148e9f287114868b3c285f276fe2dd00cc3b448e9e
2731c
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 825155ab61f17605af2ae2e935c78d857c9407bcd45128d57d338f1671b5
fcbe
BlindedElement = 02589019677db1bca1ca2f94da740691016578952337e2d19e0
7d1de0d26563c4f
EvaluationElement = 02b3825f1a1c06e4b8218e6adf69cb49ab60a2c43da29712
5c089c2815481bac0a
Output = a2bb5fc5fd0dc7b52164bf420a685d1124939d7784ca7ba34c0f7facb37
63db5
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 3516210cce73c18141b9f73caa9cd61b92211d1f6d260e827fdb026541195
141
pkSm = 032b8be546f6c9bf094315689c24aa6b56641f0bf0de31ff451bf34cab747
d5e2a
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = cee64d86fd20ab4caa264a26c0e3d42fb773b3173ba76f9588c9b14779bd
8d91
BlindedElement = 03458b1f2964895be9500419f7252a5f899932a0e1a80dad2a5
8c93205d87c189c
EvaluationElement = 0218c734a4ea623597155cbec768ec3af2184225c58b90b5
f4ff1f0bbcb6f93ad9
EvaluationProofC = af44b00027468a73410fb0ad1354a7a1cac33b3564ae3fbc3
18d22c4186f49f3
EvaluationProofS = 33304afa5ba822740c4e2c7d21d6f5475e6e4876c12c96eb5
5f73156f2197f3f
Output = 025200eba7ce5da8276a76b49f5cd9d351e333d5e403fc5b1c483a5042c
8c8bf
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 5c4b401063eff0bf242b4cd534a79bacfc2e715b2db1e7a3ad4ff8af1b24
daa2
BlindedElement = 02b600c8cd1f859fb7a87a1c9298b68d12902e4d093c9573af0
6b1b376c58e6623
EvaluationElement = 025d8aacccee92954df20159a52dc42175e25748ee2c5f72
223e12f077d0a3ab7f
EvaluationProofC = a0e3acb300c1255530822b2296c4b41fcdddf64ed5991758b
2f7bac2877d01b6
EvaluationProofS = d69f2f0bb07a586d8f27d1a0b41d3ac6c4df9361520d5191b
64815722ca91918
Output = 8bbaf709783a4456ee1285ee67d6e8e920c11565c1fa85dd8ac921f85f1
217fc
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
EvaluationElement = 0323693b6bb35fce13b2eb8ec28859670be8962aa8f0c681
cc89b2fc8d589e4343,02edbda1e214220a46b53be5246596f4faa5a2000aac666d7
6d35eb53bd6556134
EvaluationProofC = 6ec4d0332ed6a2252ea17068adf35a6681ef7b48d4eda5ca0
6540628480b2d67
EvaluationProofS = 4197b49bf76924e9fbdb67b56a80a5e9bb108b4c2954ceadf
f8746ed4e86de47
Output = 025200eba7ce5da8276a76b49f5cd9d351e333d5e403fc5b1c483a5042c
8c8bf,8bbaf709783a4456ee1285ee67d6e8e920c11565c1fa85dd8ac921f85f1217
fc
~~~

## OPRF(P-384, SHA-512)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 6854b5944360c078e5104b2571723f06dbbaa60930fb89016b43527e3f3ea
bfa1aeeef234f3fa0985232fbc76ff37dc0
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 359073c015b92d15450f7fb395bf52c6ea98384c491fe4e4d423b59de7b0
df382902c13bdc9993d3717bda68fc080b99
BlindedElement = 022250ba7604814ab2058e70fdc5dcf2604afb3ab6e15fc97c5
14973bb5e574d586ce518700ad0dd02b54982ce202020e1
EvaluationElement = 03d894ef2fef0adff8bf250b8652dd40719dadded4dd8b54
20fd0349b1c7010d450647080f649eafe6894256ee550a3fff
Output = 87152a004bcfcc7826ac5130c97f09802d7e452de35dad37f0b477af4be
01258f6df03963e1656416c5c1c838bcdfeda46a4e67216e3a1053e9b35e116d534a
5
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 21ece4f9b6ffd01ce82082545413bd9bb5e8f3c63b86ae88d9ce0530b01c
b1c23382c7ec9bdd6e75898e4877d8e2bc17
BlindedElement = 022dd0addbced4c8ea73eaa8e38f43506a7c3f98288ed479725
d596fa3a578f728915414f5df77084cadefcd5e4662f6df
EvaluationElement = 032f0f879998ef26f812818e81b4c2b68249fd2d5a7e36ac
ab4b35e38aec9271dc9a4a2eefa1b5db44d788b8368e9e1257
Output = 017752c3ddc3a711948b2285b3b19c4ddf42f37dfdf2c110ac3a6f6f311
5a1714bdec31af02f50229f9618726b30c7c94beb12f3024dd4d783fd382f75cf36a
5
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 6854b5944360c078e5104b2571723f06dbbaa60930fb89016b43527e3f3ea
bfa1aeeef234f3fa0985232fbc76ff37dc0
pkSm = 021fad17cc0d90ca8022215491aabada57d1bba93e5f0ca6e591ad2fc134e
5a8073dd317a5c3f85685286c336f135a2039
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 102f6338df84c9602bfa9e7d690b1f7a173d07e6d54a419db4a6308f8b09
589e4283efb9cd1ee4061c6bf884e60a8774
BlindedElement = 03c267661f12013daa1e4fe319713adde264a37bea8b91c5cb2
71e9e3ee12e5ed829f5a7a23aa4803704381e638a927e3a
EvaluationElement = 03b1b10b88bdde4c0471eda223ca115d27bf1119c6e7dcaa
ab9d305c64c1bab22a772c08d7c4d21e97bfe827e9c573bd61
EvaluationProofC = 832474103891df7cef90c42abe808df9c84758b2015892de9
771e4ba7fa33c2749d0791245b831439b50701a75da9d60
EvaluationProofS = ba1e8c919e06e39f786a67d4528c423ea3a7b557b48ed8591
da18e6399858659870974ab267c9874714de684fe3ee5c4
Output = 39b11cd8585650663fdca0609dcdc3b3e74f08ba64e1306f6db1c3939b2
d7f5332fb171d809ce34db4526d945a1f5a9388d113ad0b9da26c03db7996cfa2e1e
7
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 8aec1d0c3d16afd032da7ba961449a56cec6fb918e932b06d5778ac7f67b
ecfb3e3869237f74106241777f230582e84a
BlindedElement = 038f7b700d59fe135484a799fa10bb761b622d29a606ef9ecb5
b922409de93473c850bbccfd449a9cd1c352021faed9285
EvaluationElement = 02ebf1638264b68e80d4b4921cd795724e1b12ff6f6925ba
4cc0d681a7cc5f1b1860ca2d9acb70dee76d294c6c13744ad6
EvaluationProofC = 02bb096be483a76a7fa61c51a12ab30fc73f0fc5f5de8f6b6
dde7ed5ebccbf184e5fdfc31e893bb7a575559d37b7c5f7
EvaluationProofS = 8c0e858a226851ab0cdc13d2952dd287be7cb6f4d7de10b7f
c529b1186384b579cbef960230981fada8dd3bfbcb47939
Output = 04ee96be1c1f7a0bae038dc856a1bb2a8c42596021bbf99bbae960700d2
7e8351548a37ebba86b7e79ba6f691afdac340e7311ebdeabf902770bd1dd17d9c31
0
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
EvaluationElement = 034638371cc80d5ca7c4c6b9c580c5611d4ebe22ce08f2bd
9784c95edfd54eb6580758b78866d27d750671ecad0fbaed13,03711df75d299dcca
064a2aa7c974d44fd6be3f319656b32ee3826f9c7cc7559174875c000d75b8fefabb
5e82af95a438a
EvaluationProofC = 0401d8d824f6e0c0b4bb1cf4400867183f34c13ad6aa155f7
8f7d4f485f591d7a3d5ec4e0cb19ccd39509fe360332ad0
EvaluationProofS = 3ab0ab59fe63c7f6849b6a6bce1e92917fdf59532443d1aff
6e32558be39817c230fc8ad1359c46075b00d2d9df9eb47
Output = 39b11cd8585650663fdca0609dcdc3b3e74f08ba64e1306f6db1c3939b2
d7f5332fb171d809ce34db4526d945a1f5a9388d113ad0b9da26c03db7996cfa2e1e
7,04ee96be1c1f7a0bae038dc856a1bb2a8c42596021bbf99bbae960700d27e83515
48a37ebba86b7e79ba6f691afdac340e7311ebdeabf902770bd1dd17d9c310
~~~

## OPRF(P-521, SHA-512)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 01c661149db5597730498fa3002181d8ff5bcaf3af8050444d996d8b7592c
6499a78e9688cb07f89438415d70e20d59d00f347051fbc9211447608c3869073c27
5ca
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
EvaluationElement = 03007f41a83b4384911c4011d214cb927e8936ff4cf37d98
307e677554f09e06991331ec3fd1608ffc7182377facc8d16c044fcb92d9ef1b4176
cd054c0a7f7f27ca54
Output = b7d7d92db63dc6d40f594bf3a5534d90cd68953f6a729008cab3f31bbd4
2370faa546b4a5bc3db111e509cfc53c7954962183abdf45654cf311fbf202100eed
5
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
EvaluationElement = 03002925fd07f8d6521917b15639fe4fc28e039d456469fc
fe012516644ddd708bc1c541fba96f35e0d0a268c3acf18a29c77d6cba034498d1ec
df2e3c856e37b899dd
Output = 102dce4cabd714bc2d2a7ab0f76d40fc6d45414666f2bbf7e5db8215552
644809638c5448958398199a05de026d896da867f6b829e6635e18868c4660a1dd6b
8
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 01c661149db5597730498fa3002181d8ff5bcaf3af8050444d996d8b7592c
6499a78e9688cb07f89438415d70e20d59d00f347051fbc9211447608c3869073c27
5ca
pkSm = 0300bcb6c2fc34fd5f0dcdf33df5de248f14300461997c0a037270d1b726a
4aaf0d1ced81552945bc7cab10b27127f49059c214e04f5027b4264f178a29225626
65c12
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
EvaluationElement = 03018d9a0a379200f980595de1472b749b77e872b12fc515
d0c911562cfec9e470c5c8a5adb84d00fdbddf3130acdd87eeff03200f4aeb9a9f12
b7bb3dc19e17df0fbc
EvaluationProofC = 009b064e3c23733ca2ea414978242a529bcc50fa88e9cfa3a
30ca6234fb2c33732ce923d0b2fcd1d4f72ec8ed5b85ca0be40973f094912fec2e47
ef4c4f8ce4ba9d7
EvaluationProofS = 00946e921086cba7158ab2317186ec63f8ab2f36979fab8d0
18a228cc0964589cad641ea1f7021ea49812143797156d31040bfd963f6786c6efc2
831e4a31da241d5
Output = ac58e69b069115d6045a579c15f6d8acb7b79c9f2e282a04418614acdf4
7c188458bedd62df32723824ec36290b0f3d58a5b6449617c9d9f6c62bbcdedf2a0b
c
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
EvaluationElement = 0201f9e9ced6cc6884d09a13a9003879db318f9ca4d21c78
47ada8ff07d5f6c6282bb798742dab33eee83aa918d7bf1b95411744af8f9ed01248
8a7c7a937948782955
EvaluationProofC = 00c3dfb0f1ceeb63efde4099ada3df76b39f5f6870ea128e0
b7a537119e3018f474149385b3890a06d4efa2c5e4a1c4d52f44bd77931c698fb739
b93f85f10663107
EvaluationProofS = 007bf680d9bf9fc615d4ef572e1848b7706b576022613eae3
ddc98569c9c45312c3b6ed5c2dad5b369473c4cb03d0cba4f03f1e6194a3dc5539b1
1064a50cb36c5a6
Output = 1718de160ae4b4d52cd6e16a31b12b194f73d575dffdd5775247790ee85
0c3f308aeb7a5c25e5ab591d6cd41666d26e39c91d879272cddccee4a359a95e82f5
4
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
EvaluationElement = 02000c06fac6eb3c7f72ae831fd7040c51ff6c4d4d0861d7
c79a29147103cb74be98f117ff896d9aa649a3ce62faddc7cdeee3b22c0ffa6bde7c
86b6bb70b130fd75f3,0200ffacea2081f3e2325b9006fcde2e5ad027d1999192b13
6a79a5d01abf499f4c361b0284bf4c7ff4b58b36bd51c572dfae9560d6a74244fab8
0208685e98ad3ed2f
EvaluationProofC = 01b332952114e5872163edd501ca381a502deb8009ebe578a
8675f3ac65e2fb48e70c76a7d0476a72af12caf5716fbea3ab66fb3cdc3c30c5ac38
2964f8a202f377c
EvaluationProofS = 009e8332567d0ec42ced34b0129688c4d80caa43fefb081f3
6ddf062fcc82dd31ee819b07e70b52e6ad65c419d3f96b3d492191913ff9615371a4
b715091e7f1baea
Output = ac58e69b069115d6045a579c15f6d8acb7b79c9f2e282a04418614acdf4
7c188458bedd62df32723824ec36290b0f3d58a5b6449617c9d9f6c62bbcdedf2a0b
c,1718de160ae4b4d52cd6e16a31b12b194f73d575dffdd5775247790ee850c3f308
aeb7a5c25e5ab591d6cd41666d26e39c91d879272cddccee4a359a95e82f54
~~~
