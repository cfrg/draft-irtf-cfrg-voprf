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
  blind, blindedElement, inputElement = Blind(input)

                             blindedElement
                               ---------->

                 evaluatedElement = Evaluate(skS, blindedElement, info)

                             evaluatedElement
                               <----------

  output = Finalize(inputElement, blind, evaluatedElement, blindedElement, info)
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
    "VOPRF07-" || I2OSP(modeBase, 1) || I2OSP(suite.ID, 2)
  return ServerContext(contextString, skS)

def SetupBaseClient(suite):
  contextString =
    "VOPRF07-" || I2OSP(modeBase, 1) || I2OSP(suite.ID, 2)
  return ClientContext(contextString)
~~~

The verifiable mode setup functions for creating client and server
contexts are below:

~~~
def SetupVerifiableServer(suite, skS, pkS):
  contextString =
    "VOPRF07-" || I2OSP(modeVerifiable, 1) || I2OSP(suite.ID, 2)
  return VerifiableServerContext(contextString, skS)

def SetupVerifiableClient(suite, pkS):
  contextString =
    "VOPRF07-" || I2OSP(modeVerifiable, 1) || I2OSP(suite.ID, 2)
  return VerifiableClientContext(contextString, pkS)
~~~

Each setup function takes a ciphersuite from the list defined in
{{ciphersuites}}. Each ciphersuite has a two-byte field ID used to
identify the suite.

[[RFC editor: please change "VOPRF07" to "RFCXXXX", where XXXX is the final number, here and elsewhere before publication.]]

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

  inputElement = GG.SerializeElement(P)
  issuedElement = GG.SerializeElement(T)

  finalizeDST = "Finalize-" || contextString
  hashInput = I2OSP(len(inputElement), 2) || inputElement ||
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
  P = GG.HashToGroup(input)
  inputElement = GG.SerializeElement(P)
  issuedElement = Evaluate(skS, [element], info)

  finalizeDST = "Finalize-" || contextString
  hashInput = I2OSP(len(inputElement), 2) || inputElement ||
              I2OSP(len(info), 2) || info ||
              I2OSP(len(issuedElement), 2) || issuedElement ||
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
  SerializedElement inputElement

def Blind(input):
  blind = GG.RandomScalar()
  P = GG.HashToGroup(input)

  blindedElement = GG.SerializeElement(blind * P)
  inputElement = GG.SerializeElement(P)

  return blind, blindedElement, inputElement
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

  SerializedElement inputElement
  Scalar blind
  SerializedElement evaluatedElement
  PublicInput info

Output:

  opaque output[Nh]

def Finalize(inputElement, blind, evaluatedElement, info):
  unblindedElement = Unblind(blind, evaluatedElement)

  finalizeDST = "Finalize-" || contextString
  hashInput = I2OSP(len(inputElement), 2) || inputElement ||
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

  SerializedElement inputElement
  Scalar blind
  SerializedElement evaluatedElement
  SerializedElement blindedElement
  Element pkS
  Scalar proof
  PublicInput info

Output:

  opaque output[Nh]

def VerifiableFinalize(inputElement, blind, pkS, evaluatedElement, blindedElement, pkS, proof, info):
  unblindedElement = VerifiableUnblind(blind, evaluatedElement, blindedElement, pkS, proof, info)

  finalizeDST = "Finalize-" || contextString
  hashInput = I2OSP(len(inputElement), 2) || inputElement ||
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
skSm = eeadc25cf9d7b7648aa7aeef6516adc94ab62b6a3fc64dbfbfe386879e691
90d
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf
8e03
BlindedElement = c24453f6e15491ea5142c49d787f1d7920cf0f199d292176e42
36d46df94a42f
EvaluationElement = deab70b76e3263d0c742d479e6db12d8a44aef052cc3078f
b379406dbc9cc06d
Output = 1e2767391b0fcf27dd672facf0c27fc51b8f39268621c1b70eb665f2f0c
281102aa0a31050b8beebb81bd179239c1e57067febee8b37a53cd631f5f1d79ec43
6
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037
e50b
BlindedElement = 3826dd8ca04ecd8999b183a70be1acbc21c67acfaf6b21b478d
f31a25a0d0e25
EvaluationElement = d85bcf78ad7fa5bd0a4222e6abb7a99eb9e23c81d86f8074
0f4576c9c4b72a3b
Output = 03e1e386a73574eb8b8882cb1881af16bfbee10c89ffa57d9c4cb29e240
5cd030b4c5a8cf4c668e3b54533201d9b6a4314a183b616394da81e04e0c191797b3
b
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 2260a3b9106ca71cfc104c96848a0e2e0925a619e397c52875f44a35c16b6
10e
pkSm = d042a8bfcf51744f4ae5efdb9d1b6ef5a450e1b59d561a7a7b1e7260dbc1b
d4b
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e326
3503
BlindedElement = 6669343e2182377888134b7fa54163c64e9ebf8e34528cc4ffd
e4b1d0990e83f
EvaluationElement = 9614deda4b7aab665851a1c63be49c3430a319468b5c0fdd
b80154e3d94add61
Proof = 379f3ba84af07e21f78a69b5e62f61c4cd75b55e18153bbc84059266a567
8102a8d4b8a4a6d8bfe64496b19a695b0a9d515a239f84d2db28bd330521e65d6409
ProofRandomScalar = 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9d
bcec831b8c681a09
Output = 704d9947c94d43a3fba912c6bdbee26522782ea76b85ecfa9e5693a4299
9b6cd4e7390b1be87a8bb89665fe5c433ccedd98f985c68ba7569ecfbe794439f422
d
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd4171
ea02
BlindedElement = aeaeabfe3cdef8b69e5703744c40b363449ffee5aad64f61f6a
adc86f9d80022
EvaluationElement = f6a1347598719bffd122ff91325c8320556a3ab0ab444e6f
432854d0afbf5d5b
Proof = ad78433f1c29b96d87b8d4dfa991115cebdef2d1d56cde027367b95c26f1
31044e2fdb2583ff02dff72962bfb1603114595e14c4c1e87ef92fd45962a999e00c
ProofRandomScalar = 74ae06fd50d5f26c2519bd7b184f45dd3ef2cb50197d42df
9d013f7d6c312a0b
Output = 7274df94b247bb44d36ee9db6aa1eadf70e848af0a7a2f58a73e4d4250b
eb5135064c765fc76a66dfa6dada23cd15e443bbf672d20d9ff6ce10cd036d36ba20
3
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 80513e77795feeec6d2c450589b0e1b178febd5c193a9fcba0d27f0a06e0
d50f,533c2e6d91c934f919ac218973be55ba0d7b234160a0d4cf3bddafbda99e2e0
c
BlindedElement = 3c3ae5dda33a23272ec45d54fb7636217a55174582946ed69ca
e3b6cd82c9717,824475155456864dfc8dda8a83a2ed9372483017312003ebda03e8
4a3bb59f64
EvaluationElement = b41465c6806f1dc19b412383d406a60e76f450a87f7541ec
7c81fe4b362e035d,8c3c1f0a2ed111a9aa3f0b3fda289e4ff19a0bd0b6d70171ad9
1ebc76efa6c47
Proof = e67d62fa6f8adc258500085f974d0d8c327bf163c7d6679897161419e81b
3202d22c944c7d7051a851af021ed489968e2128f37fc95bcf94151c8550ddf90301
ProofRandomScalar = 3af5aec325791592eee4a8860522f8444c8e71ac33af5186
a9706137886dce08
Output = 704d9947c94d43a3fba912c6bdbee26522782ea76b85ecfa9e5693a4299
9b6cd4e7390b1be87a8bb89665fe5c433ccedd98f985c68ba7569ecfbe794439f422
d,7274df94b247bb44d36ee9db6aa1eadf70e848af0a7a2f58a73e4d4250beb51350
64c765fc76a66dfa6dada23cd15e443bbf672d20d9ff6ce10cd036d36ba203
~~~

## OPRF(decaf448, SHAKE-256)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 9519bf9d8a1914b4f4e90df9b822d9d3c23086a3954704565386ec3f6eb10
edee9596ccd5a7af36f82bd9d0caceac861320fd565fe55e73d
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = d1080372f0fcf8c5eace50914e7127f576725f215cc7c111673c635ce668
bbbb9b50601ad89b358ab8c23ed0b6c9d040365ec9d060868714
BlindedElement = 2c696404f6b665a20ed237d436b39eb1ac0616d27f833c3830e
b42613d6a0f33b64c9092e322532087ec52c0b592ee44b0b3c1977b8ceea7
EvaluationElement = 927561fa4c3baab29145ea84b88c18fa94eac4f914c9e9cf
bbd72a6df11c28110bdbc2493c3889269c5684d76af0de351efc9653c7d872e8
Output = 5aeaf145c012b3e156794064ee9003550d303b4d469b5e39364d71087ef
b2ee87f175ebe40faf458557e3ac4687beaf03cbddae0f4d93921198a7e3e920a1f2
3
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = aed1ffa44fd8f0ed16373606a3cf7df589cca86d8ea1abbf5768771dbef3
d401c74ae55ba1e28b9565e1e4018eb261a14134a4ce60c1c718
BlindedElement = 4ea2054ff32cce38027335d1f7751dda56203c3396f493ede7d
ca5c5f3308fd0d9eee3c8460391f4a731721b2f49959d4fa9431ff5f0a6cf
EvaluationElement = 82755a7a5595a22a22b89a8c00bf7d61e837a1ae2aa2299a
6b83ac8321ce8447cb76755da35fc75e93a310f3d68a1668140bcec0d73894be
Output = 32541641ced4350bd15b0a5510fc5227dc1c8361c17d0778812992dbe24
af8d214d324ef4a8b16030ba421a8aed993b2699cec57c9b6ba66ad2a823c767d7db
4
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = cb8a8d24250d8872ccc69f771a54f2ad5c597b84e3138f1ce75130f1243b5
15ff7ba58b970a53887affc28479e96329b71760d5eb6606800
pkSm = e4d40a19c254f1ebaa027456d7e5cd03e4f82eeaff9d3417d4e870b3b3202
2480f3477e95f4fe3215bfada56f7eea1855b2331d5292986de
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 4c936db1779a621b6c71475ac3111fd5703a59b713929f36dfd1e892a7fe
814479c93d8b4b6e11d1f6fe5351e51457b665fa7b76074e531f
BlindedElement = 149de065c3eca02afa0f60027e03d4c6452fc3df4724aa165ff
074078fbace155a229248ef92cb7cfe9c47bbaee23658e58d7a3100054964
EvaluationElement = da16039bdb916231947840c7a8417053f30a4614b368748d
5c2fc4c1ef03a3db9549803412443dee3d38023da01a95a487cb8363bcdc3aaa
Proof = 85b56c1069a69d5024004491b7eef6f3441c5c9408d6e02cebe4a5d289da
9e27ef653815eb0494347b75d01cb5a8e6384c821441e06f6c2502910c00c3294f67
58fa93917950b058b0624eda6e1720517b6ef917aa5bd2004d434d4d24d37498c2ae
e795f553e5f714ca24455a788231
ProofRandomScalar = 1b3f5a55b2f18f8c53d4ecf2e1c27e1028f1c345bb504486
4aa9dd8439d7520a7ba6183d50ef08bdf6c781aa465660c93e8195a8d231b62f
Output = 3aa840cab167388e7d677a0f4d5b63e635f57fbf01cb7c17ebc9408e7c4
4dacd73a83e7c237b3789df6b25981ecd06d6148fc8469113637db652114d827381d
1
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 15b3355179392f40c3d5a15f0d5ffc354e340454ec779f575e4573a3886a
b5e57e4da2985cea9e32f6d95539ce2c7189e1bd7462e8c5483a
BlindedElement = 6a46d2d6135f16e3d35c145efc0de2f81ec61001dfa9d212d94
50cbef798309425f15574efa30556f3e0edfa7dffca3b01454bdf90c419d2
EvaluationElement = a68a2a9549ea7ed41b50fb231383a4dc6aefcc051d8c84a4
5f33ee8e9ebe76d23d3e95e8dc291b0bf5945f18ff042bf3870b12f0664aa0b4
Proof = 9e950e172baee7f78e40b4ac4ff8fc67e68bcde2001562b7aa6368a06e44
aad4a4961fe9121ee8882e0b97b413422cfba981da9fce6fae14778114365ac71958
de84795633b9cb6ddccebf326d6e12298da9f235529da9006a2d600eabadbeee58fc
1000d07768704f57d3d92bfe6f27
ProofRandomScalar = 2f2e9955be83a4b25743ebd3618d4fad8b7288477da50bed
9befa58af639ddd950fec34205f8a4f166fadcb8fa71a3ffdd2e98f4c8ef5e26
Output = c8a4d02603302c8bf8c04efcae6d0f5df2c98f425f81481fb6ae3cb3e25
de046b1d672fe051e675bab158d253f26a6616e5f3d9e8bc6d0385e8fef53f974cb7
e
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 614bb578f29cc677ea9e7aea3e4839413997e020f9377b63c13584156a09
a46dd2a425c41eac0e313a47e99d05df72c6e1d58e6592577a0d,4c115060bca87db
7d73e00cbb8559f84cb7a221b235b0950a0ab553f03f10e1386abe954011b7da62bb
6599418ef90b5d4ea98cc28aff517
BlindedElement = f0a3016486a9a6bcc24eb979cb238f703646c18e14e2051c8c9
36b81b65d9456634ed74333433c5bb1e0350fa67156ecad0a6c233ad3478d,5427b2
cea8a1b085ad5b8f81b9722c63e628eac81b9563f1d934cb2df776bceb5197b002ee
f613602ed78611b228163d0321333b02d05ace
EvaluationElement = 988a19dcf7d7ff61f098c0bca095897b4cb25b67762f87d7
10eda8a80e62128a91c5e062e15916ed45194826f1ea6913cb0a885ddd7958ff,ace
88169eb5de30faf2a9d2e4a65ba084dc7246ba1fc5409eb93978590a45620ab7a801
002f333d24113a8b7313d4edd3033e42072ee1f29
Proof = 2260694e78187bc3560ef2afa608d9402958407646ebff4245f33ea856d2
65fd79295b160e5bd3842e4f36974fac888c008a06bd6ec34d00a81decbb972d18c3
80c94ffeec595f4a0aa3102c7ef37ba37886d4be746ad0bb282bf8b14b13f6225df4
777ea12d4650d625560286684c3c
ProofRandomScalar = a614f1894bcf6a1c7cef33909b794fe6e69a642b20f4c911
8febffaf6b6a31471fe7794aa77ced123f07e56cc27de60b0ab106c0b8eab127
Output = 3aa840cab167388e7d677a0f4d5b63e635f57fbf01cb7c17ebc9408e7c4
4dacd73a83e7c237b3789df6b25981ecd06d6148fc8469113637db652114d827381d
1,c8a4d02603302c8bf8c04efcae6d0f5df2c98f425f81481fb6ae3cb3e25de046b1
d672fe051e675bab158d253f26a6616e5f3d9e8bc6d0385e8fef53f974cb7e
~~~

## OPRF(P-256, SHA-256)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = e6231be4b17bd4385111d3f4ffe544c9bd093fe4b548b3716d238e7123522
5b1
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 5d9e7f6efd3093c32ecceabd57fb03cf760c926d2a7bfa265babf29ec98a
f0d0
BlindedElement = 02f8f28633d27018ff8223fa9bece2104b37caa48a1c26537a7
c743ad32ec0e6b7
EvaluationElement = 02ae4f282c520e6139092fec761a2ecf7d699be9b3a3252f
8705d5f5a4d7b1bd1d
Output = ae2059ed9ba8983928067421fd0b0311f8591d322585fe3201880d54dd4
90afe
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 825155ab61f17605af2ae2e935c78d857c9407bcd45128d57d338f1671b5
fcbe
BlindedElement = 03ee6f76d863773e9064b9d2485efab1aab3d2024048f8f497f
797e7ebf596c526
EvaluationElement = 038eeb780e2a3f2b91da34a3a1e0bf10d1050c23b63b0bbb
b99d39c678b872a91a
Output = 195c36e6d67d8450a8afc469f83540bdf65af25e1856e3fa6d8d6e87faf
bc75a
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 45158e1ad16ca1188e72d1b4a67bb80bbc44f150f5949d56ddf0f0c165465
08f
pkSm = 036c700af0961a0187bc0b444923507940b7b53c9e96566c1fabcf5e9a106
fec96
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = cee64d86fd20ab4caa264a26c0e3d42fb773b3173ba76f9588c9b14779bd
8d91
BlindedElement = 02b177925263cd669f30a1bedb7cc5de52119d8af7e527b9e4e
9f9a5342ce73f5f
EvaluationElement = 024703c02f2a686b8875cbaabae996015c9a5f44d21873a7
50f0c3e07abb757ce9
Proof = ec3fce841692c0493dea56ab572cc52e18503426c870162b681ddfa02b92
7795f47e2f4309ffa3704701d1da29f49f1effae25197445bc0998a768b3a11de005
ProofRandomScalar = 70a5204b2b606f5a28328916e1e5ea5a17862d7a261fdd6d
959759758d5e34ac
Output = efee95517664a4d65cdbce9b62a82b0ca8b96779612b1f0126db1ec80b0
fc793
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 5c4b401063eff0bf242b4cd534a79bacfc2e715b2db1e7a3ad4ff8af1b24
daa2
BlindedElement = 0254a3fc3bc40ec83c9adfc53e6941c2643f36868c079008838
519b9c5dcde5cf5
EvaluationElement = 03a5ce7c79d14a889415eb88289b666e6e1a557699f1e91c
ae1c660b65405985f8
Proof = 1da0f94d816d30a0727f0326528e8465f5bbe1b7df1b871ad525fdb79acb
aae8f0c923237c37aa88328f497b830404a6fb0b41e0e4d16ee6695cf7bae1ba26a0
ProofRandomScalar = 3b9217801b5d51cef66d9fdbd94a53533e7c5057e09e2200
65ea8c257c0dd606
Output = c6d9c900538edb21e4c095290db991b7fddb4e346047137cf2d8ae8b986
6e1e3
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = f0c7822ba317fb5e86028c44b92bd3aedcf6744d388ca013ef33edd36930
4eda,3b9631be9f8b274d9aaf671bfb6a775229bf435021b89c683259773bc686956
b
BlindedElement = 031eb04d80ae94752165fc6853627ff8be5d6b4de4ec60cf915
83eb64dd4d89094,03abf04923ff9b52e4030b6c3b7d7f3873441ef527f8fbc43428
7a7fd6cf27f8c7
EvaluationElement = 026d5c1f693bd948a4c0a997322ad9923970165d6cf77c58
80c28a7c2e37322082,020fc096a51fa822d03d2125a47786a66ffc918b4ad5d441c
5b110cc01cdc26a91
Proof = ea0f7fa070174fd1bb1f31bcb627b3b83547f2ba12ae89e31e8cf5057636
46048410912ffe95b2f15751360fec8723514c7cf62c72bfc9847f402ea985ed0872
ProofRandomScalar = 8306b863276ae74049615162a416d507a6532c99c1ea3f03
d05f6e78dc1edabe
Output = efee95517664a4d65cdbce9b62a82b0ca8b96779612b1f0126db1ec80b0
fc793,c6d9c900538edb21e4c095290db991b7fddb4e346047137cf2d8ae8b9866e1
e3
~~~

## OPRF(P-384, SHA-384)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = a391131f6c611cb7e26017cac1864b4411586c1eec8b41a9f1873e49081f7
3268aa1ef5f15c232854e7f8da2a6689366
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 359073c015b92d15450f7fb395bf52c6ea98384c491fe4e4d423b59de7b0
df382902c13bdc9993d3717bda68fc080b99
BlindedElement = 0262a6c2b839e1a3b22687c77b4d173d97c09e5925af362ac9c
cc4b50a9d0d34e75cac2eff0eb03349dfe93889f9fdc37f
EvaluationElement = 02f8cb545855af82820cd6a4a6063f7f9b2423e087b439fd
6f67b427220c54dbe7bd1a936a0fc7406604d8e3d40f3a06d6
Output = 97783b9012ab8a5b2b7a45966d99c1f607574bece5a58dda2e0d31221c5
431e097d500e6d2e1dfb7c5420202e5c3e2b9
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 21ece4f9b6ffd01ce82082545413bd9bb5e8f3c63b86ae88d9ce0530b01c
b1c23382c7ec9bdd6e75898e4877d8e2bc17
BlindedElement = 03ec0dc95f7424ec68d0154c29fa7f147b0b76cfdff40687c74
4d7baf37fb3f4df3e1b2cab8966dc9836c4e7dcfc0479da
EvaluationElement = 02f9fc09ba4064c90866a11a6a9ae62845d5c6b18341e834
8fe8487b39c43932a8545477fff47a44b9be624eeab605157d
Output = a3e28225290dacf76569f125d8c62104555d82d1c63ef603e07e1817c40
a1c836bd6ef818db60d4366d028f1aed2ea92
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = a4e61d55708ab6b7ecb3240a447c01b74833809b11bd07ea12600363392fe
199b59aedf8af2ff2ba357372d0a658a262
pkSm = 025ae0767eca0314c17451ca831e306a1d52d5c523d30398c591d37903122
4cb790884b19a0829462016bcc8d90782281d
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 102f6338df84c9602bfa9e7d690b1f7a173d07e6d54a419db4a6308f8b09
589e4283efb9cd1ee4061c6bf884e60a8774
BlindedElement = 02b7de8ae525a9b895e163de33778197997dfbbca899f6b2791
f3d732d51174c05bfe2bda1f4213b7b45b09f958f47f1ad
EvaluationElement = 02905159952f93d4e1ff1a0910e1ce989cd46f064236581d
9e45274c83e02bbb85e8f5fc08653f2d99946d7c09e4ddd61f
Proof = 75ba5a01c38aee31c53f98d8519362cded3d82c5f14a271d190b618c10a4
7435baa8dabaa3c11bddfb80622a438b0e36c49674c5b8924865d32456c175f76f0b
8992c1ae64eef15bc2290a31258457f869df55ae5e543b7d823fe3fc4b48f69c
ProofRandomScalar = 90f67cafc0ffaa7a1e1d1ced3c477fea691e696032c8709c
86cbcda2b184ad0029d29abeabede9788d11782429bff297
Output = b0cd59bfe09fedd48eeec667bfbf2eda4252ae698e5d63d298328cb6921
0a342ad53f19d1d208afbc484b24f56d898cf
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 8aec1d0c3d16afd032da7ba961449a56cec6fb918e932b06d5778ac7f67b
ecfb3e3869237f74106241777f230582e84a
BlindedElement = 028a370b9d37a6f773f6cfa345749c83d81b8b15fe2f3590d63
3b407cbfc9a3a4a882bf8fff5f4e09807bb6b4e98a29c4b
EvaluationElement = 02ffeaa89dd1e202a7941a997bce292bc8fbdc7a65cf0956
d36b1d805af3387165e59a7b7d8bae0c1bd4db5e4f3e949437
Proof = bc368c71dcf3dee3129437d6e06f9a7b9671cc5159ce1e6d75040c899599
b0cc002217e0325de9de69d978cd34e10c92e1e679d9927a3381260ef7455cd9ac23
407e693b2882f0f2590feb445f3217fa9ce052452d062b284ae4f8847021f824
ProofRandomScalar = bb1876a7f7165ac7ec79bfd5213ea2e374252f29a6e19915
f81b0c7dcea93ce6580e089ede31c1b6b5b33494581b4868
Output = 9c664da29851c6368e3e00c7c06dabc2e67f8c2edff4ca7db06caaba344
19b2085dc0f773ebc112fc6a81bc40f308ecc
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 41fabd4722d92472d858051ce9ad1a533176a862c697b2c392aff2aeb77e
b20c2ae6ba52fe31e13e03bf1d9f39878b23,51171628f1d28bb7402ca4aea6465e2
67b7f977a1fb71593281099ef2625644aee0b6c5f5e6e01a2b052b3bd4caf539b
BlindedElement = 02d790e26ace47007e7c5ef8b026cb210bbef0e18f5ad475c14
9dd3f4fdd5a4fa63fb54443b84ee61ddfd3dddd255cd5ea,02453672030afd070326
e0003e5315bc93733581fb2ebb7f93f23dbb5215b81f98428f20ceb03681bbbb457b
8c320aa39a
EvaluationElement = 039eac8b180dd73c08c1d41c87e86b921e952f4e35c87323
f1599a0f06875507b78f54dda4e4cdec6ae0ef96d411d1c3d0,033d1a7db460c054c
9fb97a014de536a644c43757a2ce230b1305c677380c5b6de57d28d91422d2783f30
47629ef7fa25c
Proof = e39a4e9c82c03e3a223e231272e67a4be567665fee1e5b905c0e58ebbd91
55690f9a3b05825abe8c8311f4a4a8e112f95ef52a6c7a2893cb27e0499d05c5f1d1
1dbcecc46ff0d0b2d620c9af4dea3e798377b93988a623229b4c21403a5f6c1d
ProofRandomScalar = 1b538ff23749be19e92df82df1acd3f606cc9faa9dc7ab25
1997738a3a232f352c2059c25684e6ccea420f8d0c793fa0
Output = b0cd59bfe09fedd48eeec667bfbf2eda4252ae698e5d63d298328cb6921
0a342ad53f19d1d208afbc484b24f56d898cf,9c664da29851c6368e3e00c7c06dab
c2e67f8c2edff4ca7db06caaba34419b2085dc0f773ebc112fc6a81bc40f308ecc
~~~

## OPRF(P-521, SHA-512)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 01367625394276c0e3e17ec229a580b868834459324cc2dcd455c1f9e78c1
f13bebf491be9f1b48768ded38c92b7c76f9fbd57052175193a4adda519bab5ee579
4ac
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 01b983705fcc9a39607288b935b0797ac6b3c4b2e848823ac9ae16b3a3b5
816be03432370deb7c3c17d9fc7cb4e0ce646e04e42d638e0fa7a434ed340772a8b5
d626
BlindedElement = 02007fd7ade68a3ede2cb6ef9275db6d49efb1191e6011b4c42
c0a3aa448ac92340ffbef716b8770d02b74df14b1cd68bb324704e575c2ce7220a9d
b82865e4086fed3
EvaluationElement = 020098f5073e120a5aa9068117b3c1ed73b280a9590e2cdb
6e71e792f9ff8bef492aaea772e5acc3ad268d8b1e38b1fa961be91b746fa08c8429
ba5e55630bfeb11382
Output = c18b036eba070044f393837729d34304f59ad8821c87e77f8ddc1d16314
7b92d37c975327b1cca6a9bc7825c0a40a5ca3905eb79fa214008336beeae1a33c25
2
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 01a03b1096b0316bc8567c89bd70267d35c8ddcb2be2cdc867089a2eb5cf
471b1e6eb4b043b9644c8539857abe3a2022e9c9fd6a1695bbabe8add48bcd149ff3
b841
BlindedElement = 0301238215be28cf3bc68807e5894f9526d4a9788c1bb537db5
895261987fd1995a1787e312a970532a3c93b4215655a8a8f2e163d6f8f84dc6a0dd
ca55762da328f66
EvaluationElement = 02014f146651ecd08dce85e1723e875f35f7dfa04523a620
4916c06d7880846dd6dcaedf22482d840778db6210d76d42c09bdb7dce7665c342bf
6a4cb77aec6bb1f74c
Output = 8085d25b073b98d10ee203fb7a94953af6066dd77b309dc38fbcf764a2e
5570a47de3219fd4a21b8119f357fd4678d9e8b1b73ab160f00de4d955695dd93e40
2
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 004f272ebe2801a85c0d84b70c75c1a592434a8d7b221e71f846752c7f341
653207060a39e650f4e0a068c5a6089d52fa52f8f4bccfe8f5a0fa365498d2e72c49
1a2
pkSm = 020097f6212b0e701218d064bd53fd00f6e0fac480304dc1f53addfd34eb1
ea6c7a741ad9eacc221ba54422dd714cdb6b01c78b9fe9a3b7a47fc956b20526a6a2
4fc5f
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 00bbb82117c88bbd91b8954e16c0b9ceed3ce992b198be1ebfba9ba970db
d75beefbfc6d056b7f7ba1ef79f4facbf2d912c26ce2ecc5bb8d66419b379952e96b
d6f5
BlindedElement = 02005b961b30cfdfc0f1cccda1d6a432052e37b00130e69bb2f
73b7c038d21791504512deb17771623b055e0e0a5efe970c064f3c559a8d944d7201
54b9b5339b7a0fe
EvaluationElement = 03006509b6de2d28c135bf06bd0b7115fc97d0e83b65543f
ecdd9c4196587cf28acca1d6b6a3ef84ca3ca3ebd0002dffa8d77438be5c5e27ac68
da67946724cc0133fa
Proof = 017989de446dd77e1f140719ae4e2890bcb2af79d24a1543d8c7dfad212f
dff0ef130febcc1c0e980717961ed15ebc2bc55777726786e3da23c9a73815323e94
a2b5005f1c402187595d90f98502747b45830d8f53acf9099cbf7a0cdc26914c2016
57987d46a5c19d48b6d30377f993958d618ef02443642d6424a2cd89f523d4e63776
ProofRandomScalar = 00ce4f0d824939827888f4c28773466f3c0a05741260040b
c9f302a4fea13f1d8f2f6b92a02a32d5eb06f81de7960470f06169bee12cf47965b7
2a59946ca3879670
Output = 4a1f71e10ac3c4e009aa1bcfa7f146aa7a5b384d6a601bfaf4989591571
dde114f0650cf37ba02c8f824e64c9eadea18a5ccd09841c838948ac845696da079b
2
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 009055c99bf9591cb0eab2a72d044c05ca2cc2ef9b609a38546f74b6d688
f70cf205f782fa11a0d61b2f5a8a2a1143368327f3077c68a1545e9aafbba6a90dc0
d40a
BlindedElement = 0300717b705123a3754b1b0181f6a81e094dd08ab9efc39a421
b824ae44bcf03ef29e5a9b222bfa0f9878a63957670e5c2348a58ce699e298f30dd7
6dd9628c8434c95
EvaluationElement = 0201e18820b09b7538eb8fdb6f563f17a99b856e012e4a6e
1e9dbb6a8a96d4ba1fbed9312b0dead4893db2a5040bfdfad1a60b1981d358d11178
f4bda7555984aac32a
Proof = 00bb4e09f497d8965e85201c7c8b25330aff24388c31bf0eed87cf5389b7
c6d38d9f4eddc9452f7b3b953dd081d820de076e8fbd74d8238c28d17daa48bccc93
2227011df33a9d35db7be6ec52aba1af6ff056c609a07742ea9683c444e9d9b8d3b8
f8eb9b5c168a29480dfc381543f27c01b460ce24a802291a2ea093bce893cfcca046
ProofRandomScalar = 00b5dfc19eb96faba6382ec845097904db87240b9dd47b1e
487ec625f11a7ba2cc3de74c5078a81806f74dd65065273c5bd886c7f87ff8c5f39f
90320718eff747e3
Output = 4350fd37154e1016169deebbbfa62f8f134a3246c53002a34806db67268
01ac12dc07d2645d7a6032d06de7173989db1680d38f509b153a129da6e68e727331
8
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
BlindedElement = 0200fccc9ee895a61bc29bc4ea5024e14fab2fc64725bc62afb
0242957d758e82cd5d2688816adf8e46a33b70c031d617bffa4aca4212a138c4d732
8dc78b2ba09fd50,030023e2c174c0bf9db75a172db0dd7f8ef5fbd6d51263fccd6e
61d79aa1791c77cfb5891a59cb84bd047e0b762371718d739a50a6a5f25f1fa05070
044c10f5036880
EvaluationElement = 0200abd8889c74861383e25ab82ae7226d6507ebe65377a7
61c7f78949621204e1744fe6f3efb8031ee7ee54b3255023dc65fc0a2de646a80992
781194347443840565,0300766e547423244d075cf3133df65c1481d4558d7244ebd
5f07a21558ca427dbcaec216080cb5f30640f111f43f4e22704838dcda36ddb77338
32c22f88f1fab2ff6
Proof = 0100bda998b28aa8e303418c2967de2811d803c4ce8846bf261205a10d5d
bc77a50a9f9ece8ab69017bdc6837a3eea79b3069aba34e74d6edc93ddd61999e5a3
638d0042a989cc311644b3f3326f883d4b89e59195b86e8ed22942ac188132c31677
d8b72336c76b6a6aeaec0755044f38dc0dad1c5c8b852567d373308a2e842202a610
ProofRandomScalar = 00d47b0d4ca4c64825ba085de242042b84d9ebe3b2e9de07
678ff96713dfe16f40f2c662a56ed2db95e1e7bf2dea02bd1fa76e953a630772f68b
53baade9962d1646
Output = 4a1f71e10ac3c4e009aa1bcfa7f146aa7a5b384d6a601bfaf4989591571
dde114f0650cf37ba02c8f824e64c9eadea18a5ccd09841c838948ac845696da079b
2,4350fd37154e1016169deebbbfa62f8f134a3246c53002a34806db6726801ac12d
c07d2645d7a6032d06de7173989db1680d38f509b153a129da6e68e7273318
~~~
