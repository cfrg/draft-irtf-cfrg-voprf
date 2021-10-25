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
    org: Brave Software
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
  RFC8446:
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
  ECS15:
    title: The pythia PRF service
    target: https://eprint.iacr.org/2015/644.pdf
    date: false
    authors:
      -
        ins: A. Everspaugh
        org: University of Wisconsin–Madison, USA
      -
        ins: R. Chatterjee
        org: University of Wisconsin–Madison, USA
      -
        ins: S. Scott
        org: Royal Holloway, University of London, UK
      -
        ins: A. Juels
        org: Jacobs Institute, Cornell Tech, USA
      -
        ins: T. Ristenpart
        org: Cornell Tech, USA
  TCRSTW21:
    title: A Fast and Simple Partially Oblivious PRF, with Applications
    target: https://eprint.iacr.org/2021/864
    date: false
    authors:
      -
        ins: N. Tyagi
        org: Cornell University, USA
      -
        ins: S. Celi
        org: Cloudflare, Portugal
      -
        ins: T. Ristenpart
        org: Cornell Tech, USA
      -
        ins: N. Sullivan
        org: Cloudflare, USA
      -
        ins: S. Tessaro
        org: University of Washington, UK
      -
        ins: C. Wood
        org: Cloudflare, USA
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
    target: https://www.secg.org/sec1-v2.pdf
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

informative:
  JKX21:
    title: "On the (In)Security of the Diffie-Hellman Oblivious PRF with Multiplicative Blinding"
    target: https://eprint.iacr.org/2021/273
    date: March, 2021
    seriesinfo: PKC'21
    author:
      -
        org: S. Jarecki
        name: Stanislaw Jarecki
      -
        org: H. Krawczyk
        name: Hugo Krawczyk
      -
        org: J. Xu
        name: Jiayu Xu
  keyagreement: DOI.10.6028/NIST.SP.800-56Ar3

--- abstract

An Oblivious Pseudorandom Function (OPRF) is a two-party protocol between
client and server for computing the output of a Pseudorandom Function (PRF).
The server provides the PRF secret key, and the client provides the PRF
input. At the end of the protocol, the client learns the PRF output without
learning anything about the PRF secret key, and the server learns neither
the PRF input nor output. A Partially-Oblivious PRF (POPRF) is an OPRF
that allows client and server to provide public input to the
PRF. OPRFs and POPRFs can also satisfy a notion of 'verifiability'.
In this setting, clients can verify that the server used a specific
private key during the execution of the protocol. This document
specifies a POPRF protocol with optional verifiability instantiated within
standard prime-order groups, including elliptic curves.

--- middle

# Introduction

A Pseudorandom Function (PRF) F(k, x) is an efficiently computable
function taking a private key k and a value x as input. This function is
pseudorandom if the keyed function K(\_) = F(k, \_) is indistinguishable
from a randomly sampled function acting on the same domain and range as
K(). An Oblivious PRF (OPRF) is a two-party protocol between a server
and a client, where the server holds a PRF key k and the client holds
some input x. The protocol allows both parties to cooperate in computing
F(k, x) such that the client learns F(k, x) without learning anything
about k; and the server does not learn anything about x or F(k, x).
A Partially-Oblivious PRF (POPRF) is a variant of an OPRF wherein client
and server interact in computing F(k, x, y), for some PRF F with
server-provided key k, client-provided input x, and public input y {{TCRSTW21}}.
A POPRF with fixed input y is functionally equivalent to an OPRF.
A POPRF is said to be 'verifiable' if the server can prove to the client
that F(k, x, y) was computed using key k, without revealing k to the client.

POPRFs have a variety of applications, including: password-protected secret
sharing schemes {{JKKX16}}, privacy-preserving password stores {{SJKS17}}, and
password-authenticated key exchange or PAKE {{!I-D.irtf-cfrg-opaque}}.
Verifiable POPRFs are necessary in some applications such as Privacy Pass
{{!I-D.davidson-pp-protocol}}. Verifiable POPRFs have also been used for
password-protected secret sharing schemes such as that of {{JKK14}}.

This document introduces a POPRF protocol built upon prime-order groups based on {{TCRSTW21}}.
The protocol supports optional verifiability with the addition of a non-interactive
zero knowledge proof (NIZK). This proof demonstrates correctness of the computation,
using a known public key that serves as a commitment to the server's private
key. The document describes the protocol, application considerations, and its
security properties.

## Change log

[draft-07](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-07):

- Bind blinding mechanism to mode (additive for verifiable mode and
  multiplicative for base mode).
- Add explicit errors for deserialization.
- Document explicit errors and API considerations.
- Adopt SHAKE-256 for decaf448 ciphersuite.
- Normalize HashToScalar functionality for all ciphersuites.
- Refactor and generalize DLEQ proof functionality and domain separation
  tags for use in other protocols.
- Update test vectors.
- Apply various editorial changes.

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
`GF(p)`. This document uses types `Element` and `Scalar` to denote elements
of the group `GG` and its set of scalars, respectively.

We now detail a number of member functions that can be invoked on a
prime-order group `GG`.

- Order(): Outputs the order of `GG` (i.e. `p`).
- Identity(): Outputs the identity element of the group (i.e. `I`).
- HashToGroup(x): A member function of `GG` that deterministically maps
  an array of bytes `x` to an element of `GG`. The map must ensure that,
  for any adversary receiving `R = HashToGroup(x)`, it is
  computationally difficult to reverse the mapping. This function is optionally
  parameterized by a domain separation tag (DST); see {{ciphersuites}}.
- HashToScalar(x): A member function of `GG` that deterministically maps
  an array of bytes `x` to an element in GF(p). This function is optionally
  parameterized by a DST; see {{ciphersuites}}.
- RandomScalar(): A member function of `GG` that chooses at random a
  non-zero element in GF(p).
- SerializeElement(A): A member function of `GG` that maps a group element `A`
  to a unique byte array `buf` of fixed length `Ne`. The output type of
  this function is `SerializedElement`.
- DeserializeElement(buf): A member function of `GG` that maps a byte array
  `buf` to a group element `A`, or fails if the input is not a valid
  byte representation of an element. This function can raise a
  DeserializeError if deserialization fails or `A` is the identity element
  of the group; see {{input-validation}}.
- SerializeScalar(s): A member function of `GG` that maps a scalar element `s`
  to a unique byte array `buf` of fixed length `Ns`. The output type of this
  function is `SerializedScalar`.
- DeserializeScalar(buf): A member function of `GG` that maps a byte array
  `buf` to a scalar `s`, or fails if the input is not a valid byte
  representation of a scalar. This function can raise a
  DeserializeError if deserialization fails; see {{input-validation}}.

Two functions can be used for generating a (V)OPRF key pair (`skS`, `pkS`)
where `skS` is a non-zero integer less than `p` and `pkS = ScalarBaseMult(skS)`:
`GenerateKeyPair` and `DeriveKeyPair`. `GenerateKeyPair` is a randomized function
that outputs a fresh key pair (`skS`, `pkS`) upon every invocation. `DeriveKeyPair`
is a  deterministic  function that generates private key `skS` from a random byte
string `seed`, which SHOULD have at least `Ns` bytes of entropy, and then
computes `pkS = ScalarBaseMult(skS)`.

It is convenient in cryptographic applications to instantiate such
prime-order groups using elliptic curves, such as those detailed in
{{SEC2}}. For some choices of elliptic curves (e.g. those detailed in
{{RFC7748}}, which require accounting for cofactors) there are some
implementation issues that introduce inherent discrepancies between
standard prime-order groups and the elliptic curve instantiation. In
this document, all algorithms that we detail assume that the group is a
prime-order group, and this MUST be upheld by any implementation. That is,
any curve instantiation should be written such that any discrepancies
with a prime-order group instantiation are removed. See {{ciphersuites}}
for advice corresponding to the implementation of this interface for
specific definitions of elliptic curves.

## Notation and Terminology

The following functions and notation are used throughout the document.

- For any object `x`, we write `len(x)` to denote its length in bytes.
- For two byte arrays `x` and `y`, write `x || y` to denote their
  concatenation.
- I2OSP and OS2IP: Convert a byte array to and from a non-negative
  integer as described in {{!RFC8017}}. Note that these functions
  operate on byte arrays in big-endian byte order.
- For any two byte strings `a` and `b`, `CT_EQUAL(a, b)` represents
  constant-time equality between `a` and `b` which returns `true` if
  `a` and `b` are equal and `false` otherwise.

Data structure descriptions use TLS notation {{RFC8446, Section 3}}.

All algorithms and procedures described in this document are laid out
in a Python-like pseudocode.

String values such as "Context-" are ASCII string literals.

The following terms are used throughout this document.

- PRF: Pseudorandom Function.
- OPRF: Oblivious Pseudorandom Function.
- VOPRF: Verifiable Oblivious Pseudorandom Function.
- POPRF: Partially Oblivious Pseudorandom Function.
- Client: Protocol initiator. Learns pseudorandom function evaluation as
  the output of the protocol.
- Server: Computes the pseudorandom function over a private key. Learns
  nothing about the client's input or output.
- NIZK: Non-interactive zero knowledge.
- DLEQ: Discrete Logarithm Equality.

# POPRF Protocol {#protocol}

In this section, we define two POPRF variants: a base mode and verifiable
mode. In the base mode, a client and server interact to compute
`output = F(skS, input, info)`, where `input` is the client's private input,
`skS` is the server's private key, `info` is the public input (or metadata),
and `output` is the POPRF output. The client learns `output` and the server
learns nothing. In the verifiable mode, the client also receives proof that
the server used `skS` in computing the function.

To achieve verifiability, as in the original work of {{JKK14}}, we
provide a zero-knowledge proof that the key provided as input by the
server in the `Evaluate` function is the same key as it used to produce
their public key. As an example of the nature of attacks that this
prevents, this ensures that the server uses the same private key for
computing the verifiable POPRF output and does not attempt to "tag"
individual clients with select keys. This proof does not reveal the
server's private key to the client.

The following one-byte values distinguish between these two modes:

| Mode           | Value |
|:===============|:======|
| modeBase       | 0x00  |
| modeVerifiable | 0x01  |

## Overview {#protocol-overview}

Both participants agree on the mode and a choice of ciphersuite that is
used before the protocol exchange. Once established, the base mode of
the protocol runs to compute `output = F(skS, input, info)` as follows:

~~~
    Client(input, info)                               Server(skS, info)
  ----------------------------------------------------------------------
  blind, blindedElement = Blind(input)

                             blindedElement
                               ---------->

                 evaluatedElement = Evaluate(skS, blindedElement, info)

                             evaluatedElement
                               <----------

  output = Finalize(input, blind, evaluatedElement, blindedElement, info)
~~~

In `Blind` the client generates a blinded element and blinding data. The server
computes the POPRF evaluation in `Evaluate` over the client's blinded element,
and public information `info`. In `Finalize` the client unblinds the server
response and produces the POPRF output.

In the verifiable mode of the protocol, the server additionally computes
a proof in Evaluate. The client verifies this proof using the server's
expected public key before completing the protocol and producing the
protocol output.

## Context Setup

Both modes of the POPRF involve an offline setup phase. In this phase,
both the client and server create a context used for executing the
online phase of the protocol. The key pair (`skS`, `pkS`) should be
generated by calling either `GenerateKeyPair` or `DeriveKeyPair`.

The base mode setup functions for creating client and server contexts are below:

~~~
def SetupBaseServer(suite, skS):
  contextString =
    "VOPRF08-" || I2OSP(modeBase, 1) || I2OSP(suite.ID, 2)
  return ServerContext(contextString, skS)

def SetupBaseClient(suite):
  contextString =
    "VOPRF08-" || I2OSP(modeBase, 1) || I2OSP(suite.ID, 2)
  return ClientContext(contextString)
~~~

The verifiable mode setup functions for creating client and server
contexts are below:

~~~
def SetupVerifiableServer(suite, skS, pkS):
  contextString =
    "VOPRF08-" || I2OSP(modeVerifiable, 1) || I2OSP(suite.ID, 2)
  return VerifiableServerContext(contextString, skS)

def SetupVerifiableClient(suite, pkS):
  contextString =
    "VOPRF08-" || I2OSP(modeVerifiable, 1) || I2OSP(suite.ID, 2)
  return VerifiableClientContext(contextString, pkS)
~~~

Each setup function takes a ciphersuite from the list defined in
{{ciphersuites}}. Each ciphersuite has a two-byte field ID used to
identify the suite.

[[RFC editor: please change "VOPRF08" to "RFCXXXX", where XXXX is the final number, here and elsewhere before publication.]]

## Context APIs {#api}

In this section, we detail the APIs available on the client and server
POPRF contexts. Each API has the following implicit parameters:

- GG, a prime-order group implementing the API described in {{pog}}.
- contextString, a domain separation tag constructed during context setup.

The data types `PrivateInput` and `PublicInput` are opaque byte strings
of arbitrary length no larger than 2^13 octets. `Proof` is a sequence
of two `SerializedScalar` values, as shown below.

~~~
struct {
  SerializedScalar c;
  SerializedScalar s;
} Proof;
~~~

### Server Context

The ServerContext encapsulates the context string constructed during
setup and the POPRF key pair. It has three functions, `Evaluate`,
`FullEvaluate` and `VerifyFinalize` described below. `Evaluate` takes
serialized representations of blinded group elements from the client
as inputs along with public input `info`.

`FullEvaluate` takes PrivateInput values, and it is useful for applications
that need to compute the whole POPRF protocol on the server side only.

`VerifyFinalize` takes PrivateInput values and their corresponding output
digests from `Finalize` as input, and returns true if the inputs match the outputs.

Note that `VerifyFinalize` and `FullEvaluate` are not used in the main POPRF
protocol. They are exposed as an API for building higher-level protocols.

#### Evaluate

~~~
Input:

  Scalar skS
  SerializedElement blindedElement
  PublicInput info

Output:

  SerializedElement evaluatedElement

Errors: DeserializeError

def Evaluate(skS, blindedElement, info):
  R = GG.DeserializeElement(blindedElement)
  context = "Context-" || contextString ||
            I2OSP(len(info), 2) || info
  m = GG.HashToScalar(context)
  t = skS + m
  Z = t^(-1) * R
  evaluatedElement = GG.SerializeElement(Z)

  return evaluatedElement
~~~

#### FullEvaluate

~~~
Input:

  Scalar skS
  PrivateInput input
  PublicInput info

Output:

  opaque output[Nh]

def FullEvaluate(skS, input):
  P = GG.HashToGroup(input)
  context = "Context-" || contextString ||
            I2OSP(len(info), 2) || info
  m = GG.HashToScalar(context)
  t = skS + m
  T = t^(-1) * P
  issuedElement = GG.SerializeElement(T)

  finalizeDST = "Finalize-" || contextString
  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(info), 2) || info ||
              I2OSP(len(issuedElement), 2) || issuedElement ||
              I2OSP(len(finalizeDST), 2) || finalizeDST

  return Hash(hashInput)
~~~

#### VerifyFinalize

~~~
Input:

  Scalar skS
  PrivateInput input
  opaque output[Nh]
  PublicInput info

Output:

  boolean valid

def VerifyFinalize(skS, input, output, info):
  T = GG.HashToGroup(input)
  element = GG.SerializeElement(T)
  E = Evaluate(skS, [element], info)

  finalizeDST = "Finalize-" || contextString
  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(info), 2) || info ||
              I2OSP(len(E), 2) || E ||
              I2OSP(len(finalizeDST), 2) || finalizeDST

  digest = Hash(hashInput)

  return CT_EQUAL(digest, output)
~~~

### VerifiableServerContext

The VerifiableServerContext extends the base ServerContext with an
augmented `Evaluate()` function. This function produces a proof that
`skS` was used in computing the result. It makes use of the helper
functions `GenerateProof` and `ComputeComposites`, described below.

#### Evaluate

~~~
Input:

  Scalar skS
  SerializedElement blindedElement
  PublicInput info

Output:

  SerializedElement evaluatedElement
  Proof proof

Errors: DeserializeError

def Evaluate(skS, blindedElement, info):
  R = GG.DeserializeElement(blindedElement)
  context = "Context-" || contextString ||
            I2OSP(len(info), 2) || info
  m = GG.HashToScalar(context)
  t = skS + m
  Z = t^(-1) * R

  U = ScalarBaseMult(t)
  proof = GenerateProof(t, G, U, Z, R)
  evaluatedElement = GG.SerializeElement(Z)
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
  (M, Z) = ComputeCompositesFast(k, B, Cs, Ds)

  r = GG.RandomScalar()
  t2 = r * A
  t3 = r * M

  Bm = GG.SerializeElement(B)
  a0 = GG.SerializeElement(M)
  a1 = GG.SerializeElement(Z)
  a2 = GG.SerializeElement(t2)
  a3 = GG.SerializeElement(t3)

  challengeDST = "Challenge-" || contextString
  h2Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(a0), 2) || a0 ||
            I2OSP(len(a1), 2) || a1 ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            I2OSP(len(challengeDST), 2) || challengeDST

  c = GG.HashToScalar(h2Input)
  s = (r - c * k) mod p

  proof = GG.SerializeScalar(c) || GG.SerializeScalar(s)
  return proof
~~~

##### Batching inputs

Unlike other functions, `ComputeComposites` takes lists of inputs,
rather than a single input. Applications can take advantage of this
functionality by invoking `GenerateProof` on batches of inputs to
produce a combined, constant-size proof. (In the pseudocode above,
the single inputs `blindedElement` and `evaluatedElement` are passed
as single-item lists to `ComputeComposites`.)

In particular, servers can produce a single, constant-sized proof for N
client inputs sent in a single request, rather than one proof per client
input. This optimization benefits clients and servers since it amortizes
the cost of proof generation and bandwidth across multiple requests.

#### ComputeComposites

The definition of `ComputeComposites` is given below. This function is
used both on generation and verification of the proof.

~~~
Input:

  Element B
  Element Cs[m]
  Element Ds[m]

Output:

  Element M
  Element Z

def ComputeComposites(B, Cs, Ds):
  Bm = GG.SerializeElement(B)
  seedDST = "Seed-" || contextString
  compositeDST = "Composite-" || contextString

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

 return (M, Z)
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

  Element M
  Element Z

def ComputeCompositesFast(k, B, Cs, Ds):
  Bm = GG.SerializeElement(B)
  seedDST = "Seed-" || contextString
  compositeDST = "Composite-" || contextString

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

 return (M, Z)
~~~

### Client Context {#base-client}

The ClientContext encapsulates the context string constructed during
setup. It has two functions, `Blind()` and `Finalize()`, as described
below. It also has an internal function, `Unblind()`, which is used
by `Finalize`. The implementation of these functions varies depending
on the mode.

#### Blind and Unblind

~~~
Input:

  PrivateInput input

Output:

  Scalar blind
  SerializedElement blindedElement

def Blind(input):
  blind = GG.RandomScalar()
  P = GG.HashToGroup(input)
  blindedElement = GG.SerializeElement(blind * P)

  return blind, blindedElement
~~~

The inverse `Unblind` is implemented as follows.

~~~
Input:

  Scalar blind
  SerializedElement evaluatedElement

Output:

  SerializedElement unblindedElement

Errors: DeserializeError

def Unblind(blind, evaluatedElement):
  Z = GG.DeserializeElement(evaluatedElement)
  N = blind^(-1) * Z
  unblindedElement = GG.SerializeElement(N)

  return unblindedElement
~~~

#### Finalize

`Finalize` depends on the internal `Unblind` function. In this mode, `Finalize`
does not include all inputs listed in {{protocol-overview}}. These additional
inputs are only useful for the verifiable mode, described in {{verifiable-finalize}}.

~~~
Input:

  PrivateInput input
  Scalar blind
  SerializedElement evaluatedElement
  PublicInput info

Output:

  opaque output[Nh]

def Finalize(input, blind, evaluatedElement, info):
  unblindedElement = Unblind(blind, evaluatedElement)

  finalizeDST = "Finalize-" || contextString
  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(info), 2) || info ||
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

  (M, Z) = ComputeComposites(B, Cs, Ds)
  c = GG.DeserializeScalar(proof.c)
  s = GG.DeserializeScalar(proof.s)

  t2 = ((s * A) + (c * B))
  t3 = ((s * M) + (c * Z))

  Bm = GG.SerializeElement(B)
  a0 = GG.SerializeElement(M)
  a1 = GG.SerializeElement(Z)
  a2 = GG.SerializeElement(t2)
  a3 = GG.SerializeElement(t3)

  challengeDST = "Challenge-" || contextString
  h2Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(a0), 2) || a0 ||
            I2OSP(len(a1), 2) || a1 ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            I2OSP(len(challengeDST), 2) || challengeDST

  expectedC = GG.HashToScalar(h2Input)

  return CT_EQUAL(expectedC, c)
~~~

#### Verifiable Unblind {#verifiable-unblind}

The inverse `VerifiableUnblind` is implemented as follows. This function
can raise an exception if element deserialization or proof verification
fails.

~~~
Input:

  Scalar blind
  SerializedElement evaluatedElement
  SerializedElement blindedElement
  Element pkS
  Scalar proof
  PublicInput info

Output:

  SerializedElement unblindedElement

Errors: DeserializeError, VerifyError

def VerifiableUnblind(blind, evaluatedElement, blindedElement, pkS, proof, info):
  context = "Context-" || contextString ||
            I2OSP(len(info), 2) || info
  m = GG.HashToScalar(context)

  R = GG.DeserializeElement(blindedElement)
  Z = GG.DeserializeElement(evaluatedElement)

  T = ScalarBaseMult(m)
  U = T + pkS
  if VerifyProof(G, U, Z, R, proof) == false:
    raise VerifyError

  N = blind^(-1) * Z
  unblindedElement = GG.SerializeElement(N)

  return unblindedElement
~~~

#### Verifiable Finalize {#verifiable-finalize}

~~~
Input:

  PrivateInput input
  Scalar blind
  SerializedElement evaluatedElement
  SerializedElement blindedElement
  Element pkS
  Scalar proof
  PublicInput info

Output:

  opaque output[Nh]

def VerifiableFinalize(input, blind, pkS, evaluatedElement, blindedElement, pkS, proof, info):
  unblindedElement = VerifiableUnblind(blind, evaluatedElement, blindedElement, pkS, proof, info)

  finalizeDST = "Finalize-" || contextString
  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(info), 2) || info ||
              I2OSP(len(unblindedElement), 2) || unblindedElement ||
              I2OSP(len(finalizeDST), 2) || finalizeDST
  return Hash(hashInput)
~~~

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
  For HashToScalar, each group specifies an integer order that is used in
  reducing integer values to a member of the corresponding scalar field.
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
    "HashToGroup-" || contextString, and `expand_message` = `expand_message_xmd`
    using SHA-512.
  - HashToScalar(): Compute `uniform_bytes` using `expand_message` = `expand_message_xmd`,
    DST = "HashToScalar-" || contextString, and output length 64, interpret
    `uniform_bytes` as a 512-bit integer in little-endian order, and reduce the integer
    modulo `Order()`.
  - Serialization: Both group elements and scalars are encoded in Ne = Ns = 32
    bytes. For group elements, use the 'Encode' and 'Decode' functions from
    {{!RISTRETTO}}. For scalars, ensure they are fully reduced modulo `Order()`
    and in little-endian order.
- Hash: SHA-512, and Nh = 64.
- ID: 0x0001

## OPRF(decaf448, SHAKE-256)

- Group: decaf448 {{!RISTRETTO}}
  - HashToGroup(): Use hash_to_decaf448
    {{!I-D.irtf-cfrg-hash-to-curve}} with DST =
    "HashToGroup-" || contextString, and `expand_message` = `expand_message_xof`
    using SHAKE-256.
  - HashToScalar(): Compute `uniform_bytes` using `expand_message` = `expand_message_xof`,
    DST = "HashToScalar-" || contextString, and output length 64, interpret
    `uniform_bytes` as a 512-bit integer in little-endian order, and reduce the integer
    modulo `Order()`.
  - Serialization: Both group elements and scalars are encoded in Ne = Ns = 56
    bytes. For group elements, use the 'Encode' and 'Decode' functions from
    {{!RISTRETTO}}. For scalars, ensure they are fully reduced modulo `Order()`
    and in little-endian order.
- Hash: SHAKE-256, and Nh = 64.
- ID: 0x0002

## OPRF(P-256, SHA-256)

- Group: P-256 (secp256r1) {{x9.62}}
  - HashToGroup(): Use hash_to_curve with suite P256_XMD:SHA-256_SSWU_RO\_
    {{!I-D.irtf-cfrg-hash-to-curve}} and DST =
    "HashToGroup-" || contextString.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using L = 48, `expand_message_xmd` with SHA-256,
    DST = "HashToScalar-" || contextString, and
    prime modulus equal to `Order()`.
  - Serialization: Elements are serialized as Ne = 33 byte strings using
    compressed point encoding for the curve {{SEC1}}. Scalars are serialized as
    Ns = 32 byte strings by fully reducing the value modulo `Order()` and in big-endian
    order.
- Hash: SHA-256, and Nh = 32.
- ID: 0x0003

## OPRF(P-384, SHA-384)

- Group: P-384 (secp384r1) {{x9.62}}
  - HashToGroup(): Use hash_to_curve with suite P384_XMD:SHA-384_SSWU_RO\_
    {{!I-D.irtf-cfrg-hash-to-curve}} and DST =
    "HashToGroup-" || contextString.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using L = 72, `expand_message_xmd` with SHA-384,
    DST = "HashToScalar-" || contextString, and
    prime modulus equal to `Order()`.
  - Serialization: Elements are serialized as Ne = 49 byte strings using
    compressed point encoding for the curve {{SEC1}}. Scalars are serialized as
    Ns = 48 byte strings by fully reducing the value modulo `Order()` and in big-endian
    order.
- Hash: SHA-384, and Nh = 48.
- ID: 0x0004

## OPRF(P-521, SHA-512)

- Group: P-521 (secp521r1) {{x9.62}}
  - HashToGroup(): Use hash_to_curve with suite P521_XMD:SHA-512_SSWU_RO\_
    {{!I-D.irtf-cfrg-hash-to-curve}} and DST =
    "HashToGroup-" || contextString.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using L = 98, `expand_message_xmd` with SHA-512,
    DST = "HashToScalar-" || contextString, and
    prime modulus equal to `Order()`.
  - Serialization: Elements are serialized as Ne = 67 byte strings using
    compressed point encoding for the curve {{SEC1}}. Scalars are serialized as
    Ns = 66 byte strings by fully reducing the value modulo `Order()` and in big-endian
    order.
- Hash: SHA-512, and Nh = 64.
- ID: 0x0005

# Application Considerations {#apis}

This section describes considerations for applications, including explicit error
treatment and public metadata representation.

## Error Considerations

Some POPRF APIs specified in this document are fallible. For example, `Finalize`
and `Evaluate` can fail if any element received from the peer fails deserialization.
The explicit errors generated throughout this specification, along with the
conditions that lead to each error, are as follows:

- `VerifyError`: Verifiable POPRF proof verification failed; {{verifiable-unblind}}.
- `DeserializeError`: Group element or scalar deserialization failure; {{pog}}.

The errors in this document are meant as a guide to implementors. They are not
an exhaustive list of all the errors an implementation might emit. For example,
implementations might run out of memory and return a corresponding error.

## Public Metadata

The optional and public `info` string included in the protocol allows clients
and servers to cryptographically bind additional data to the POPRF output. This
metadata is known to both parties at the start of the protocol. It is RECOMMENDED
that this metadata be constructed with some type of higher-level domain separation
to avoid cross protocol attacks or related issues. For example, protocols using
this construction might ensure that the metadata uses a unique, prefix-free encoding.
See {{I-D.irtf-cfrg-hash-to-curve, Section 10.4}} for further discussion on
constructing domain separation values.

# Security Considerations {#sec}

This section discusses the cryptographic security of our protocol, along
with some suggestions and trade-offs that arise from the implementation
of a POPRF.

## Security Properties {#properties}

The security properties of a POPRF protocol with functionality
y = F(k, x, t) include those of a standard PRF. Specifically:

- Pseudorandomness: F is pseudorandom if the output y = F(k, x, t) on any
  input x is indistinguishable from uniformly sampling any element in
  F's range, for a random sampling of k.

In other words, consider an adversary that picks inputs x from the
domain of F and evaluates F on (k, x, t) (without knowledge of randomly
sampled k). Then the output distribution F(k, x, t) is indistinguishable
from the output distribution of a randomly chosen function with the same
domain and range.

A consequence of showing that a function is pseudorandom, is that it is
necessarily non-malleable (i.e. we cannot compute a new evaluation of F
from an existing evaluation). A genuinely random function will be
non-malleable with high probability, and so a pseudorandom function must
be non-malleable to maintain indistinguishability.

A POPRF protocol must also satisfy the following property:

- Partial obliviousness: The server must learn nothing about the client's
  private input or the output of the function. In addition, the client must
  learn nothing about the server's private key. Both client and server learn
  the public input (info).

Essentially, partial obliviousness tells us that, even if the server learns
the client's private input x at some point in the future, then the server will
not be able to link any particular POPRF evaluation to x. This property is
also known as unlinkability {{DGSTV18}}.

Optionally, for any protocol that satisfies the above properties, there
is an additional security property:

- Verifiable: The client must only complete execution of the protocol if
  it can successfully assert that the POPRF output it computes is
  correct. This is taken with respect to the POPRF key held by the
  server.

Any POPRF that satisfies the 'verifiable' security property is known as a
verifiable POPRF. In practice, the notion of verifiability requires that
the server commits to the key before the actual protocol execution takes
place. Then the client verifies that the server has used the key in the
protocol using this commitment. In the following, we may also refer to this
commitment as a public key.

## Cryptographic Security {#cryptanalysis}

Below, we discuss the cryptographic security of the verifiable POPRF
protocol from {{protocol}}, relative to the necessary cryptographic
assumptions that need to be made.

### Protocol Security and Computational Hardness Assumptions {#assumptions}

The POPRF construction in this document is based on the construction known
as 3HashSDHI given by {{TCRSTW21}}. The construction is identical to
3HashSDHI, except that this design can optionally perform multiple POPRF
evaluations in one go, whilst only constructing one NIZK proof object.
This is enabled using an established batching technique.

The cryptographic security of the construction is based on the assumption
that the One-More Gap Strong Diffie-Hellman Inversion (SDHI) assumption from
{{TCRSTW21}} is computationally difficult to solve. {{TCRSTW21}} show that
both the One-More Gap Computational Diffie Hellman (CDH)
assumption and the One-More Gap SDHI assumption reduce to the q-DL assumption
in the algebraic group model, for some q number of `Evaluate` queries.
(The One-More Gap CDH assumption was the hardness assumption used to
evaluate the 2HashDH-NIZK construction from {{JKK14}}, which is a predecessor
to the design in this specification.)

### Static q-DL Assumption

A side-effect of the POPRF design is that it allows instantiation of an oracle for
retrieving "strong-DH" evaluations, in which an adversary can query a group element
B and scalar c, and receive evaluation output 1/(k+c)\*B. This type of oracle allows
an adversary to form elements of "repeated powers" of the server-side secret. This
"repeated powers" structure has been studied in terms of the q-DL problem which
asks the following: Given G1, G2, h\*G2, (h^2)\*G2, ..., (h^Q)\*G2; for G1 and G2
generators of GG. Output h where h is an element of GF(p)

For example, consider an adversary that queries the strong-DH oracle provided by the
POPRF on a fixed scalar c starting with group element G2, then passes the received
evaluation group element back as input for the next evaluation. If we set h = 1/(k+c),
such an adversary would receive exactly the evaluations given in the q-DL problem: h\*G2,
(h^2)\*G2, ..., (h^Q)\*G2.

{{TCRSTW21}} capture the power of the strong-DH oracle in the One-More Gap SDHI assumption
and show, in the algebraic group model, the security of this assumption can be reduced to
the security of the q-DL problem, where q is the number of queries made to the blind
evaluation oracle.

The q-DL assumption has been well studied in the literature, and there exist a number of
cryptanalytic studies to inform parameter choice and group instantiation (for example,
{{BG04}} and {{Cheon06}}).

### Implications for Ciphersuite Choices

The POPRF instantiations that we recommend in this document are informed
by the cryptanalytic discussion above. In particular, choosing elliptic
curves configurations that describe 128-bit group instantiations would
appear to in fact instantiate a POPRF with 128-(log\_2(Q)/2) bits of
security. Moreover, such attacks are only possible for those certain
applications where the adversary can query the POPRF directly.
In applications where such an oracle is not made available this security loss does not apply.

In most cases, it would require an informed and persistent attacker to
launch a highly expensive attack to reduce security to anything much
below 100 bits of security. We see this possibility as something that
may result in problems in the future. Applications that admit the
aforementioned oracle functionality, and that cannot tolerate discrete
logarithm security of lower than 128 bits, are RECOMMENDED to only
implement ciphersuites 0x0002, 0x0004, and 0x0005.

## Proof Randomness

It is essential that a different `r` value is used for every invocation
of GenerateProof. Failure to do so may leak `skS` as is possible in Schnorr
or (EC)DSA scenarios where fresh randomness is not used.

## Domain Separation {#domain-separation}

Applications SHOULD construct input to the protocol to provide domain
separation. Any system which has multiple POPRF applications should
distinguish client inputs to ensure the POPRF results are separate.
Guidance for constructing info can be found in {{!I-D.irtf-cfrg-hash-to-curve, Section 3.1}}.

## Element and Scalar Validation {#input-validation}

The DeserializeElement function recovers a group element from an arbitrary
byte array. This function validates that the element is a proper member
of the group and is not the identity element, and returns an error if either
condition is not met.

For P-256, P-384, and P-521 ciphersuites, this function performs partial
public-key validation as defined in Section 5.6.2.3.4 of {{keyagreement}}.
This includes checking that the coordinates are in the correct range, that
the point is on the curve, and that the point is not the point at infinity.
If these checks fail, deserialization returns an error.

For ristretto255 and decaf448, elements are deserialized by invoking the Decode
function from {{RISTRETTO, Section 4.3.1}} and {{RISTRETTO, Section 5.3.1}}, respectively,
which returns false if the element is invalid. If this function returns false,
deserialization returns an error.

The DeserializeScalar function recovers a scalar field element from an arbitrary
byte array. Like DeserializeElement, this function validates that the element
is a member of the scalar field and returns an error if this condition is not met.

For P-256, P-384, and P-521 ciphersuites, this function ensures that the input,
when treated as a big-endian integer, is a value between 0 and `Order()`. For
ristretto255 and decaf448, this function ensures that the input, when treated as
a little-endian integer, is a valud between 0 and `Order()`.

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

# Acknowledgements

This document resulted from the work of the Privacy Pass team
{{PrivacyPass}}. The authors would also like to acknowledge helpful
conversations with Hugo Krawczyk. Eli-Shaoul Khedouri provided
additional review and comments on key consistency. Daniel Bourdrez,
Tatiana Bradley, Sofia Celi, Frank Denis, Kevin Lewi, and Bas Westerbaan
also provided helpful input and contributions to the document.

--- back

# Test Vectors

This section includes test vectors for the (V)OPRF protocol specified
in this document. For each ciphersuite specified in {{ciphersuites}},
there is a set of test vectors for the protocol when run in the base
mode and verifiable mode. Each test vector lists the batch size for
the evaluation. Each test vector value is encoded as a hexadecimal
byte string. The label for each test vector value is described below.

- "Input": The private client input, an opaque byte string.
- "Info": The public info, an opaque byte string.
- "Blind": The blind value output by `Blind()`, a serialized `Scalar`
  of `Ns` bytes long.
- "BlindedElement": The blinded value output by `Blind()`, a serialized
  `Element` of `Ne` bytes long.
- "EvaluatedElement": The evaluated element output by `Evaluate()`,
  a serialized `Element` of `Ne` bytes long.
- "Proof": The serialized `Proof` output from `GenerateProof()` (only
  listed for verifiable mode test vectors), composed of two serialized
  `Scalar` values each of `Ns` bytes long.
- "ProofRandomScalar": The random scalar `r` computed in `GenerateProof()`
  (only listed for verifiable mode test vectors), a serialized `Scalar` of
  `Ns` bytes long.
- "Output": The OPRF output, a byte string of length `Nh` bytes.

Test vectors with batch size B > 1 have inputs separated by a comma
",". Applicable test vectors will have B different values for the
"Input", "Blind", "BlindedElement", "EvaluationElement", and
"Output" fields.

Base mode and verifiable mode uses multiplicative blinding.

The server key material, `pkSm` and `skSm`, are listed under the mode for
each ciphersuite. Both `pkSm` and `skSm` are the serialized values of
`pkS` and `skS`, respectively, as used in the protocol. Each key pair
is derived from a `seed`, which is listed as well, using the following
implementation of `DeriveKeyPair`:

~~~
def DeriveKeyPair(mode, suite, seed):
  skS = GG.HashToScalar(seed, DST = "HashToScalar-" || contextString)
  pkS = ScalarBaseMult(skS)
  return skS, pkS
~~~

## OPRF(ristretto255, SHA-512)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 74db8e13d2c5148a1181d57cc06debd730da4df1978b72ac18bc48992a0d2
c0f
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf
8e03
BlindedElement = 744441a5d3ee12571a84d34812443eba2b6521a47265ad655f0
1e759b3dd7d35
EvaluationElement = 4254c503ee2013262473eec926b109b018d699b8dd954ee8
78bc17b159696353
Output = 9aef8983b729baacb7ecf1be98d1276ca29e7d62dbf39bc595be018b66b
199119f18579a9ae96a39d7d506c9e00f75b433a870d76ba755a3e7196911fff89ff
3
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037
e50b
BlindedElement = f4eeea4e1bcb2ec818ee2d5c1fcec56c24064a9ff4bea5b3dd6
877800fc28e4d
EvaluationElement = 185dae43b6209dacbc41a62fd4889700d11eeeff4e83ffbc
72d54daee7e25659
Output = f556e2d83e576b4edc890472572d08f0d90d2ecc52a73b35b2a8416a72f
f676549e3a83054fdf4fd16fe03e03bee7bb32cbd83c7ca212ea0d03b8996c2c268b
2
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = ad08ad9c7107691d792d346d743e8a79b8f6ae0673d58cbf7389d7003598c
903
pkSm = 7a5627aec2f2209a2fc62f39f57a8f5ffc4bbfd679d0273e6081b2b621ee3
b52
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e326
3503
BlindedElement = 56c6926e940df23d5dfe6a48949c5a9e5b503df3bff36454ba4
821afa1528718
EvaluationElement = 523774950001072a4fb1f1f3300f7feb1eeddb5b8304baa9
c3d463c11e7f0509
Proof = c973c8cfbcdbb12a09e7640e44e45d85d420ed0539a18dc6c67c189b4f28
c70dd32f9b13717ee073e1e73333a7cb17545dd42ed8a2008c5dae11a3bd7e70260d
ProofRandomScalar = 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9d
bcec831b8c681a09
Output = 2d9ed987fdfa623a5b4d5e445b127e86212b7c8f2567c175b424c59602f
bba7c36975df5e4ecdf060430c8b1b581fc97e953535fd82089e15afbafcf310b339
9
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd4171
ea02
BlindedElement = 5cd133d03df2e1ff919ed85501319c2039853dd7dc59da73605
fd5791b835d23
EvaluationElement = c0ba1012cbfb0338dadb435ef1d910eb179dc18c0d0a341f
0249a3a9ff03b06e
Proof = 156761aee4eb6a5e1e32bc0adb56ea46d65883777e152d4c607a3a3b8abf
3b036ecebae005d3f26222a8da0a3924cceed8a1a7c707ef4ba077456c3e80f8c40f
ProofRandomScalar = 74ae06fd50d5f26c2519bd7b184f45dd3ef2cb50197d42df
9d013f7d6c312a0b
Output = f5da1276b5ca3de4591534cf2d96f7bb49059bd374f40259f42dca89d72
3cac69ed3ae567128aaa2dfdf777f333615524aec24bc77b0a38e200e6a07b6c638e
b
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 80513e77795feeec6d2c450589b0e1b178febd5c193a9fcba0d27f0a06e0
d50f,533c2e6d91c934f919ac218973be55ba0d7b234160a0d4cf3bddafbda99e2e0
c
BlindedElement = 1c7ee9c1b4145dabeba9ad159531432a20718cb44a86f79dc73
f6f8671c9bf5e,7c1ef37881602cb6d3cf995e6ee310ed51e39b80ce0a825a316bc6
21d0580a14
EvaluationElement = a8a66348d351408cb7e2d26341a1258ba91c1a7d1b380f62
15bdfc242500991b,5a4b72bee9d2ca80ea220571690e2f92fadd0c13635b2888bc1
ff255f8fee975
Proof = caad28bac17ce71d59b43956e8d80f3edde3d0c317144bef3d10d9733ef1
cf09fd910c663ea85ad7cfaf641d73314694fe18d3f6b89cfe001b18163ff908d10a
ProofRandomScalar = 3af5aec325791592eee4a8860522f8444c8e71ac33af5186
a9706137886dce08
Output = 2d9ed987fdfa623a5b4d5e445b127e86212b7c8f2567c175b424c59602f
bba7c36975df5e4ecdf060430c8b1b581fc97e953535fd82089e15afbafcf310b339
9,f5da1276b5ca3de4591534cf2d96f7bb49059bd374f40259f42dca89d723cac69e
d3ae567128aaa2dfdf777f333615524aec24bc77b0a38e200e6a07b6c638eb
~~~

## OPRF(decaf448, SHAKE-256)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 82c2a6492e1792e6ccdf1d7cff410c717681bd53ad47da7646b14ebd05885
53e4c034e02b3ae5e724600a17a638ad528c04f793df56c2618
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = d1080372f0fcf8c5eace50914e7127f576725f215cc7c111673c635ce668
bbbb9b50601ad89b358ab8c23ed0b6c9d040365ec9d060868714
BlindedElement = 1c354d6d31500c7c5ae6fb10901ac87552ea3af1824e79871e2
596ef537f86abac64859cf6f35911ab74f0b09a06ecc757a65a104e9e49fb
EvaluationElement = 9e5bbf27b2312a493b2f2f1d051b7cdf3801769ec5dc0724
51b68c4d0d4ed9303979ec4798261a01fabd8d25540f48a11dd8342fded95383
Output = 5f8c28d5e760786cbd000ac58444bd216141472b9370b058408a714da5e
3dd51fc572f96c99a9338bc8569abc991bc1523fa1467cd3a0de3aef7f154bd65d92
e
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = aed1ffa44fd8f0ed16373606a3cf7df589cca86d8ea1abbf5768771dbef3
d401c74ae55ba1e28b9565e1e4018eb261a14134a4ce60c1c718
BlindedElement = e8111f22d50595f68f01a6a9135f50e8702c90794c2637fbe00
9046f0c455884cc77ee7a87f3abf494afe780b3620ab0e7fb65c65ba902b2
EvaluationElement = 0ec625f99914ba702f0e6bc5d0f837cb4deaf7ab3ac55458
7182c3dfe1dad6d1540964f9581d26e8ef0a47b61c5f145109a5fffe04ad528e
Output = 7f0e40c08d8220f88c0961925f764ee0e4e08909d497f462a97a2030b40
b44986fa76d344efb9b0acab23db81356fc8c380b80701a61a5fa76097a5d2ea7aa9
e
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 5d295b55d1d6e46411bbb4151d154dc61711012ff2390255b3345988f8e3c
458089d52e9b1d837049898f9e4e63a4534f0ed3b3a47c7051c
pkSm = 8e623ef9b65ef2ce148ce56249ee5e69ed6acd3e504a07905cc4c09312551
8d30ae7d6de274438b822d5a55a4365216ac588a4c400fbf6ff
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 4c936db1779a621b6c71475ac3111fd5703a59b713929f36dfd1e892a7fe
814479c93d8b4b6e11d1f6fe5351e51457b665fa7b76074e531f
BlindedElement = 74bb2406b15a86ba94b0686901545f8ddc23e64918de47c76fa
0bf812387021392c73e01068ac9cc07c7647b3d0d4e648c27bb3880ddb8e5
EvaluationElement = 90997b495c19f16561a3286a7bcba9a4ee6e12bab4d580d5
004ae5064d90a389124e81066f3f1dbf9a729ab46ed674c3292f56d54a0d5641
Proof = 668f6ef88b249d51b6c94bfe82f2bec35ab7386bc9f3d14209d0247a5b6e
bedec4c333947fff96d322f516f4674cc07638b8e854c52be7045d83d65aff518104
60ec43417a6c6efbfb67ba7b0257b1237c64e6792195e338474d09df32b076c0b702
ec8c639b34c29878b87aad70d63c
ProofRandomScalar = 1b3f5a55b2f18f8c53d4ecf2e1c27e1028f1c345bb504486
4aa9dd8439d7520a7ba6183d50ef08bdf6c781aa465660c93e8195a8d231b62f
Output = 7db8c49354861f2d71c8175681c9cc930a00251330b2acc5c321f9833fe
d4113a1cb3e05a3840082c24e8d49470474dd1c7586f3663f32f66dc3888c63dc0e6
e
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 15b3355179392f40c3d5a15f0d5ffc354e340454ec779f575e4573a3886a
b5e57e4da2985cea9e32f6d95539ce2c7189e1bd7462e8c5483a
BlindedElement = ea3418614d71144ac4ecbd2c63c30ce34718b739ba0a5dd3585
efd9800b9debdad4cffc25dcc39b4691aaffba19ead8a425d7d50f016f57e
EvaluationElement = 7e12ab491c3787a1f17118f7a0308f8c41f4cd6e850cf7fa
ba030b6c1bf1888337149e7c2fc88068626a0107be18e8b9e29f41c8d1510049
Proof = 91ed184bf518a155749a99d39bed3f9dc9895054e55fab0ebd0ce4270e84
52fcc8da055e8c2f75f2306ecacaa594de592e0d0b059b8eb30e15d5c3132b71ebc4
933596c563ee8ce8681e0e40534e92ce487a0e33e341f02a9aaa1f750d9efa7545a0
008b2f8dde5047ce68d00c2e962e
ProofRandomScalar = 2f2e9955be83a4b25743ebd3618d4fad8b7288477da50bed
9befa58af639ddd950fec34205f8a4f166fadcb8fa71a3ffdd2e98f4c8ef5e26
Output = 66125718c5d651c88ab57dda67c52a506d436600f1521b7684c869b9a2b
3e67d1b41c47593e79fd6b70aaae8d3689536897ae8964ffcd433c0884c12c94929d
c
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 614bb578f29cc677ea9e7aea3e4839413997e020f9377b63c13584156a09
a46dd2a425c41eac0e313a47e99d05df72c6e1d58e6592577a0d,4c115060bca87db
7d73e00cbb8559f84cb7a221b235b0950a0ab553f03f10e1386abe954011b7da62bb
6599418ef90b5d4ea98cc28aff517
BlindedElement = 909b0b8bcb900bd9e70f27258d7264015c50f3717361afff22d
16ad84758d2c6b7a1963263d0d035f63b88df8b473f9365c53abcec34b201,726315
ee47e217344da7036a24f806177e221c9f6eae5763f9089b16bada69b85aec56c3ca
83b6f5f1091640ea3fe3e9429ff2aa7772efef
EvaluationElement = 46d8dec85a27698b4b69a67299eab1da0ec2bbed013a3a59
b932e2938e2e2c5bcc8274febf49b7903419c18b895f17c4a9a504737d7a3fdc,fe4
7eca9d06b400c80cc2b749284312c6f97c7b5d88055fe56b068c441e053fe909c6c2
2bb7cd646a932e2d3838b7b3e2e883cfe0ed1a2a1
Proof = 1f63637de4f945f5937ac015a508420f119f7b6a8e001439a1923a1705ce
ee704ad17664ff4c72f89566f83ceccee3001d44d849ac4dad2bc05b9bc718ba787f
c3c5b09198c4ab244455bac64a9a231b18c4682c0e6e30ae5398f5c041ee2c5b02c6
19b7497c5bf070fdb4656353de1d
ProofRandomScalar = a614f1894bcf6a1c7cef33909b794fe6e69a642b20f4c911
8febffaf6b6a31471fe7794aa77ced123f07e56cc27de60b0ab106c0b8eab127
Output = 7db8c49354861f2d71c8175681c9cc930a00251330b2acc5c321f9833fe
d4113a1cb3e05a3840082c24e8d49470474dd1c7586f3663f32f66dc3888c63dc0e6
e,66125718c5d651c88ab57dda67c52a506d436600f1521b7684c869b9a2b3e67d1b
41c47593e79fd6b70aaae8d3689536897ae8964ffcd433c0884c12c94929dc
~~~

## OPRF(P-256, SHA-256)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = c15d9e9ab36d495d9d62954db6aafe06d3edabf41600d58f9be0737af2719
e97
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 5d9e7f6efd3093c32ecceabd57fb03cf760c926d2a7bfa265babf29ec98a
f0d0
BlindedElement = 03e9097c54d2ea05f99424bdf984ea30ecc3614029bd5f1139e
70c4e1ae3bdbd92
EvaluationElement = 0202e4d1a338659c211900c39855f30025359928d261e6c9
558d667b3fbbc811cd
Output = 15b96275d06b85741f491fe0cad5cb835baa6c39066cbea73132dcf95e8
58e1c
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 825155ab61f17605af2ae2e935c78d857c9407bcd45128d57d338f1671b5
fcbe
BlindedElement = 03fa1ea45dd58d6b516c1252f2791610bf5ff1828c93be8af66
786f45fb4d14db5
EvaluationElement = 02657822553416d91bb3d707040fd0d5a0555f5cbae7519d
f3a297747a3ad1dd57
Output = e97f3f451f3cfce45a530dec0a0dec934cd78c5b656771549072ee236ce
070b9
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 7f62054fcd598b5e023c08ef0f04e05e26867438d5e355e846c9d8788d5c7
a12
pkSm = 03d6c3f69cfa683418a533fc52143a377f166e571ae50581abcb97ffd4e71
24395
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = cee64d86fd20ab4caa264a26c0e3d42fb773b3173ba76f9588c9b14779bd
8d91
BlindedElement = 029e103c4003ab9bf4a42e2003dd180922c8517927a68320058
178fee56c6ac8a0
EvaluationElement = 02856ac0748085d250d842b8b8fff6c1a9f688c961de52c4
a1e6c004c48196a123
Proof = 2a95bd827cf47873c886967ef6c17fe0e46efddd3b5f639927215cb7592a
4bf12a29117174a1af5899d64855352690e416b37f2a95580846a6bec445d82364fc
ProofRandomScalar = 70a5204b2b606f5a28328916e1e5ea5a17862d7a261fdd6d
959759758d5e34ac
Output = 14afc50acf64589445991da5b60add8b3f71205d53a983023d3cdaf8c95
c300d
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 5c4b401063eff0bf242b4cd534a79bacfc2e715b2db1e7a3ad4ff8af1b24
daa2
BlindedElement = 0323aabcfa93e9570524253671b3ce083144b183cecb562ec8f
8a8472fc8cf341b
EvaluationElement = 03087bc7e00b8ad80b8a27484b91f8bf824a5d896a703135
4edfa3269866493d9f
Proof = fe55ecc9a92f940d4a56207a58e5554c6976b9425c917d24237b0a35c312
bdcdea778a5c56690309ff28f26cc8bc5994e85868e3c870e5a32c0a559d80deccb8
ProofRandomScalar = 3b9217801b5d51cef66d9fdbd94a53533e7c5057e09e2200
65ea8c257c0dd606
Output = 533c79459ee0ffa8844ac37572f3616e10a1074dcbf945ce37b0c651cbb
5775f
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = f0c7822ba317fb5e86028c44b92bd3aedcf6744d388ca013ef33edd36930
4eda,3b9631be9f8b274d9aaf671bfb6a775229bf435021b89c683259773bc686956
b
BlindedElement = 021af4563c31cf1513bc5ae0b89c5b527c7ac70614b9d31c44c
eb292ab49c91cc4,03f7e7ebe5610710c360df40cbd90dc52c2da500664e879f2afb
78e71f815abee1
EvaluationElement = 03c8678cdb95e2f0eac027932c51893a20326b774ef23531
bcd95def84060d240d,02b68c3891314a9696b5dff5df4b4e5b325938e2c5cb90f5f
b9ba6a1133aa4dd14
Proof = 6efbde69d36e3f9d53a79a73ce46d5d8ef31f0df2fb3f6f2c882b21fdf0e
d76dcd755e42f35f00daaa6e964f48125cf1d642b1cea2e5faa2fb868584a8752bf2
ProofRandomScalar = 8306b863276ae74049615162a416d507a6532c99c1ea3f03
d05f6e78dc1edabe
Output = 14afc50acf64589445991da5b60add8b3f71205d53a983023d3cdaf8c95
c300d,533c79459ee0ffa8844ac37572f3616e10a1074dcbf945ce37b0c651cbb577
5f
~~~

## OPRF(P-384, SHA-384)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = b9ff42e68ef6f8eaa3b4d15d15ceb6f3f36b9dc332a3473d64840fc7b4462
6c6e70336bdecbe01d9c512b7e7d7e6af21
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 359073c015b92d15450f7fb395bf52c6ea98384c491fe4e4d423b59de7b0
df382902c13bdc9993d3717bda68fc080b99
BlindedElement = 0285d803c65fda56993a296b99e8f4944e45cccb9b322bbc265
c91a21d2c9cd146212aefbf3126ed59d84c32d6ab823b66
EvaluationElement = 026061a4ccfe38777e725855c96570fe85303cd70567007e
489d0aa8bfced0e47579ecbc290e5150b9e84bf25188294f7e
Output = bc2c3c895f96d769703aec18359cbc0e84b41248559f0bd44f1e5467522
3c77e00874bbe61c1c320d3c95aee5a8c752f
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 21ece4f9b6ffd01ce82082545413bd9bb5e8f3c63b86ae88d9ce0530b01c
b1c23382c7ec9bdd6e75898e4877d8e2bc17
BlindedElement = 0211dd06e40b902006c33a92dc476a7c708b6b46c990656239c
d6867ff0be5867d859517eaf7ea9bad10702b80a9dc6bdc
EvaluationElement = 03a1d34b657f6267b29338592e3c769db5d3fc8713bf2eb7
238efb8138d5af8c56f9437315a5c58761b35cbfc0e1d2511d
Output = ee37530d0d7b20635fbc476317343b257750ffb3e83a2865ce2a46e5959
1f854b8301d6ca7d063322314a33b953c8bd5
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 42c4d1c15d27be015844404088967afe48c8ae96d4f00ce48e4d38ecabfb8
feb5b748de625cdf81ab076745d6211be95
pkSm = 0389ad5e50eebf9617ae3a5778e4f0665b56aa9066919e1fa5580d8dd781d
560824e0e78aae816af6eff8abe2ad0585a0d
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 102f6338df84c9602bfa9e7d690b1f7a173d07e6d54a419db4a6308f8b09
589e4283efb9cd1ee4061c6bf884e60a8774
BlindedElement = 02ae8990d580dcd52b6bc273bc6d0fd25be50b057511b953d9c
c95bb27cb3e1fd3249ae19744ed496c6e4104ebc1ed48f1
EvaluationElement = 024cffdae0cae5fa4d6a68246ae797dbe06508284b65e0f0
9046977ab5d52a8b38f0245607db74979e5276fc636332cdee
Proof = 128ad4f987ce1e3a9aab1e487df15d8c8000d5c4c9f14bd7fd699fabdb8d
a3f577d91625fabb0d9cf6069f8af6d9cc232dd63cd161be84a1e146e0110dc741e6
26a082193aa0a26e03118b662f1b903667f6e6fba51d69a2d65982a3b64ecb35
ProofRandomScalar = 90f67cafc0ffaa7a1e1d1ced3c477fea691e696032c8709c
86cbcda2b184ad0029d29abeabede9788d11782429bff297
Output = 8a0b4829bc8422b1a2301d5471256892883c5e3fe27b998d1010225a706
545637336a20a76f842d8a22e591d382c77e4
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 8aec1d0c3d16afd032da7ba961449a56cec6fb918e932b06d5778ac7f67b
ecfb3e3869237f74106241777f230582e84a
BlindedElement = 02a384f2d9635adffcc5482344c519036c019f3cc0918ec737c
67cdda10ac0f73a9fe348835531f1900ea2c1f06dacdce4
EvaluationElement = 0306f0f71b58d53ae0973538a7bf2ce8fba7143efc88d2ef
ca6cf1f98fb8399b16840d1fbbe7897807db930f67916418ae
Proof = 2c47297ee0093061ca2c87b430b2851a860aaae76c2bdba48779ba4294e7
de0556ede3e6b881a04970b68a6126e2fa197d69e6784fbbd173604501c0edd21696
628f0fd7cb13be28f94e5e15c042ffccadd780b2448d7d9d528e9615e4e70539
ProofRandomScalar = bb1876a7f7165ac7ec79bfd5213ea2e374252f29a6e19915
f81b0c7dcea93ce6580e089ede31c1b6b5b33494581b4868
Output = 8c52d40c1f6cc80208bd610178a5034d6c4a05584e19b69617f846b09a8
545443c63c8aa4d85bf0aad368e0591b1216a
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 41fabd4722d92472d858051ce9ad1a533176a862c697b2c392aff2aeb77e
b20c2ae6ba52fe31e13e03bf1d9f39878b23,51171628f1d28bb7402ca4aea6465e2
67b7f977a1fb71593281099ef2625644aee0b6c5f5e6e01a2b052b3bd4caf539b
BlindedElement = 02d4e6186c9ffa92565055f43f27bb1e2c4103c3325bba0b499
adb99a157987d20fb374096814e438a6b483efa8f2a3307,033a3b052416a8a6d842
a0baea6f5fab99d36645a70c89897a536970d34038eca35afac24906294cb7925b1b
05e4327c8f
EvaluationElement = 037bf8e28a0607b1f8aa59363380b5a7450b66b98017cf03
3797f6c6c74e7625a445f71ace1bea7836ea5baa75d54eb5bd,03b793a9cb2d76991
f1d6cd822abfbfa89fdfa1a06ef42b0bc8ade161e1996ed08c288a08366d4140c762
7bba4e3472bcf
Proof = 27240901b6855d2b58ce84afefa91dd11819d7d5df73f94865a9d7e19020
41200eb732b60b57fa0daf6e456402bb1ccb1aed901af35d3d790cd7c618604b766b
b9271010354da9e4e5507e0468adf177977143db2ddb94d9b70e837ad7578275
ProofRandomScalar = 1b538ff23749be19e92df82df1acd3f606cc9faa9dc7ab25
1997738a3a232f352c2059c25684e6ccea420f8d0c793fa0
Output = 8a0b4829bc8422b1a2301d5471256892883c5e3fe27b998d1010225a706
545637336a20a76f842d8a22e591d382c77e4,8c52d40c1f6cc80208bd610178a503
4d6c4a05584e19b69617f846b09a8545443c63c8aa4d85bf0aad368e0591b1216a
~~~

## OPRF(P-521, SHA-512)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 00a2f8572ee764d2ec34363fb62ef9e8ff48883b5357b6802f43fffe5c5fd
0d11f766bf7086aab33e2dce02cc71d77250ef6ed360a3fd56244abb6bdbc3aa6534
da1
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 01b983705fcc9a39607288b935b0797ac6b3c4b2e848823ac9ae16b3a3b5
816be03432370deb7c3c17d9fc7cb4e0ce646e04e42d638e0fa7a434ed340772a8b5
d626
BlindedElement = 03006ce4a27e778a624d943cf4db48f9d393d3d4dd9cd44b78a
cf2d5b668a12f0ca587962de8c82b5aaa1f0166eb60d511f060aaab895fc6c519332
77bc945add6d74a
EvaluationElement = 030055f7cd3ee3b1734e73ad8bbd4baca72ae8d051160c27
7ee329f23fa2365f9f138b38e6e2c59cc287242eeca01fae83d0c7cc3bb19724ac59
8a188816e7cfe1ca88
Output = aa59060a41ec8ca7b6c47f9c5a31883a44ffd95869a09dbe845ea8ce20c
b290dba0b57c505824a0dcf6f961a2baeb8e6b49df8c158761a3fdb46f39e8e7fcb8
b
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 01a03b1096b0316bc8567c89bd70267d35c8ddcb2be2cdc867089a2eb5cf
471b1e6eb4b043b9644c8539857abe3a2022e9c9fd6a1695bbabe8add48bcd149ff3
b841
BlindedElement = 0201459ba64ad0e0f9f689f0ad5ab29ca5b960f5c9da3aef412
6d2d547b871e754b17971fd45e0d64bdcfc8d256c342a141f04e2640705c38936c8c
f53c22ea6b13966
EvaluationElement = 030094036457e8e5bf77719b11f01dd4aa2959efdb3329c3
e3b25493efc3ab572c2e7db104cd5922645320ef51bbb282f84e5f6b08e9b49354f9
d6a9f3a4327a1de6e4
Output = 5efe6f00f45ec4e87e4c9b89aeaec61313c15c0a0a21ee2e41362d6af54
536adf2f68d23c729b92b6fa8d5611764b0272be6cc153d47a0256c8cb44bd740037
a
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 0064799c2f9c0f9e6b9ac2aca5c42687cf15742fb73e086c4954aa0bdc8b8
25911ff03712e8d308c0a6ff5435375036f189391234bf21aac57fa73df155d70da4
7bd
pkSm = 03013e587a7750213bb7c2b338a4507635f1ba60ece346de32ad975373e56
fbabd878f9956996aac83a550ed5f5ba98fcc56817f6230cc7e84cb7eb2a1e1db51d
bfc1b
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 00bbb82117c88bbd91b8954e16c0b9ceed3ce992b198be1ebfba9ba970db
d75beefbfc6d056b7f7ba1ef79f4facbf2d912c26ce2ecc5bb8d66419b379952e96b
d6f5
BlindedElement = 02002ff3ef3f2411aa0358936f852be710af790c9affbced8c3
9b018fd97de0a45d80c66cbf0dbda690ee4f594e0795627e6c6f37a500f223c30f31
c24e73501532e7c
EvaluationElement = 0300769fd56c5174c4e3922900fcefdd5a89c9592f4d8e8f
2396678fa72c01d4f8551ec92d4b5287ca673dc29d8db9bb05d2396121a6b8732b68
ebf310fc2620059d67
Proof = 011fd92f54f6a955a333648d843807bd88f644d235a7d592189da42d721e
a6f7b55ec813146f35982487910aa15bbf5ce90653edb6a1b48c0bfd15758e9358aa
731601baa67a3a59db301f41caa020986ae9e93a80d6c06d92e8c5eef6056fa6f342
6b6054d118dc9fecb77fdcb4fc86b9857ada6de18394ff7d6c574cbd08d746b9dde0
ProofRandomScalar = 00ce4f0d824939827888f4c28773466f3c0a05741260040b
c9f302a4fea13f1d8f2f6b92a02a32d5eb06f81de7960470f06169bee12cf47965b7
2a59946ca3879670
Output = a647c5a940aa19d767ab0e163d1357ca068206b2b78f9e8e1021c0bb0f3
27d20cb8fadf996199d86d4cc0a08ac314493319979e1c2a98a96085b8fabff9f0d0
7
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 009055c99bf9591cb0eab2a72d044c05ca2cc2ef9b609a38546f74b6d688
f70cf205f782fa11a0d61b2f5a8a2a1143368327f3077c68a1545e9aafbba6a90dc0
d40a
BlindedElement = 0301e2ecf7313820e9d47763e12633ce6acf9b3dec89928c83b
de1ede2180dc73553af1317408846af5c53ebfed00d19a4125f4ffb7df9f4260ccc0
84a6f7482414a9d
EvaluationElement = 02000e69591ab605652cb3310e774edf79417e102cf89005
c2c7f2bd3a06060d740817802f2cf484748d93df5b281a4bd835617a97ec9809519d
474ca53bba15cdf014
Proof = 0076fa4275414acb9f87dc9e4f20971d51fcd0d38a980854ac2ad1bd5737
eec23bfb4599d021881f7b3872d2e90d9b47e4219f490cf7f0235b2f0859cb2ef15d
dfd401acb6b0844edf066a5767b4b85536bfee69bdf472acf7a59254cf6578f9f35e
ba51bb58c6428d6b7c9e5c9af97edc66d98886fda9544048bf9ceea6fc745bf970da
ProofRandomScalar = 00b5dfc19eb96faba6382ec845097904db87240b9dd47b1e
487ec625f11a7ba2cc3de74c5078a81806f74dd65065273c5bd886c7f87ff8c5f39f
90320718eff747e3
Output = 8d109503ccced41cbec087dab86c607763020be93bdd5ec8508cb078607
1a2b22a7b06150242bcaf6ea1b555a994e0266647eb72914caf73cabe53ddfb0f940
d
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 01c6cf092d80c7cf2cb55388d899515238094c800bdd9c65f71780ba85f5
ae9b4703e17e559ca3ccd1944f9a70536c175f11a827452672b60d4e9f89eba28104
6e29,00cba1ba1a337759061965a423d9d3d6e1e1006dc8984ad28a4c93ecfc36fc2
171046b3c4284855cfa2434ed98db9e68a597db2c14728fade716a6a82d600444b26
e
BlindedElement = 0201e22c01df5ac0502842fad603f7a1e1183bcc79a5cb04bb7
befdea870a9a6ea96fbccd752ea9927a9e1e28438098f693461e81832a3f690616bf
983fced079f3a33,0300b49216dd8ba5ba1275d8345679f70fbc6baf4f4b32a03e91
7165a18afa9fad849c48eecb4bae965057ef7c215b52b42ca53c8d5f650633e0bb70
97f2bd809d09ea
EvaluationElement = 03002949c2478249b918a0cf2cd870226541a81d2f3e88c4
7119f732301e749c3dea317c11174a18b89d1b9d2aa4f6ae92ae724e03a4800a26b7
c827b00199f1114bcd,0300924ab017ea6e6328a0b0f341bbeb7d209c67ac169fa4e
f7b04055c66b92aa9657f5d83b0b1ee9c79f3f0198519c97fef07dbecf3f6d477755
0242a1c87953f9461
Proof = 01f5d3c3f835d91aa88202f0fe8728180eeffe7fbc66ffe3f7a7dd958696
a7cd3d47b3c0ec6cd59e9ee23090137293e6f42269923f3d4a1659bc706fd9762070
7d230028cd4b0aa237b91a352fce81248936826ba99e7bd5103a871715126014b8d4
7447e5f20192ed377a7431516fbd82763098ba23f9d15b84fe24fb1126beb0d46f03
ProofRandomScalar = 00d47b0d4ca4c64825ba085de242042b84d9ebe3b2e9de07
678ff96713dfe16f40f2c662a56ed2db95e1e7bf2dea02bd1fa76e953a630772f68b
53baade9962d1646
Output = a647c5a940aa19d767ab0e163d1357ca068206b2b78f9e8e1021c0bb0f3
27d20cb8fadf996199d86d4cc0a08ac314493319979e1c2a98a96085b8fabff9f0d0
7,8d109503ccced41cbec087dab86c607763020be93bdd5ec8508cb0786071a2b22a
7b06150242bcaf6ea1b555a994e0266647eb72914caf73cabe53ddfb0f940d
~~~
