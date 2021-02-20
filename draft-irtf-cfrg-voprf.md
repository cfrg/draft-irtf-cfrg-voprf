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

- Certify public key during VerifiableFinalize
- Remove protocol integration advice
- Add text discussing how to perform domain separation
- Drop OPRF_/VOPRF_ prefix from algorithm names
- Make prime-order group assumption explicit
- Changes to algorithms accepting batched inputs
- Changes to construction of batched DLEQ proofs
- Updated ciphersuites to be consistent with hash-to-curve and added
  OPRF specific ciphersuites

[draft-02](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-02):

- Added section discussing cryptographic security and static DH oracles
- Updated batched proof algorithms

[draft-01](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-01):

- Updated ciphersuites to be in line with
  https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04
- Made some necessary modular reductions more explicit

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

## Prime-order group API {#pog}

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
element A with itself `r-1` times, this is denoted as `r*A = A + ... +
A`. For any element `A`, the equality `p*A=I` holds. Scalar base multiplication
is equivalent to the repeated application of the group operation on the
base point with itself `r-1` times, this is denoted as `ScalarBaseMult(r)`.
The set of scalars corresponds to `GF(p)`.

We now detail a number of member functions that can be invoked on a
prime-order group.

- Order(): Outputs the order of GG (i.e. `p`).
- Identity(): Outputs the identity element of the group (i.e. `I`).
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

## Other conventions

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
online phase of the protocol. Prior to this phase, keys (`skS`, `pkS`)
should be generated by calling a `KeyGen` function. `KeyGen`
generates a private and public key pair (`skS`, `pkS`), where `skS` is a
non-zero element chosen at random from the scalar field of the
corresponding group and `pkS = ScalarBaseMult(skS)`.

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

##### Fresh randomness

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
    "VOPRF06-HashToGroup-" || contextString, where contextString is that which is
    computed in the Setup functions, and `expand_message` = `expand_message_xmd`
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

## Security properties {#properties}

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

## Cryptographic security {#cryptanalysis}

Below, we discuss the cryptographic security of the (V)OPRF protocol
from {{protocol}}, relative to the necessary cryptographic assumptions
that need to be made.

### Computational hardness assumptions {#assumptions}

Each assumption states that the problems specified below are
computationally difficult to solve in relation to a particular choice of
security parameter `sp`.

Let GG = GG(sp) be a group with prime-order p, and let GF(p) be a finite
field of order p.

#### Discrete-log (DL) problem {#dl}

Given G, a generator of GG, and H = hG for some h in GF(p); output h.

#### Decisional Diffie-Hellman (DDH) problem {#ddh}

Sample uniformly at random d in {0,1}. Given (G, aG, bG, C), where

- G is a generator of GG;
- a,b are elements of GF(p);
- if d == 0: C = abG; else: C is sampled uniformly at random from GG.

Output d' == d.

### Protocol security {#protocol-sec}

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

### Q-strong-DH oracle {#qsdh}

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

### Implications for ciphersuite choices

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

## Hashing to curve

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

## Key rotation {#key-rotation}

Since the server's key is critical to security, the longer it is exposed
by performing (V)OPRF operations on client inputs, the longer it is
possible that the key can be compromised. For example, if the key is kept
in circulation for a long period of time, then it also allows the
clients to make enough queries to launch more powerful variants of the
Q-sDH attacks from {{qsdh}}.

To combat attacks of this nature, regular key rotation should be
employed on the server-side. A suitable key-cycle for a key used to
compute (V)OPRF evaluations would be between one week and six months.

# Additive blinding {#blinding}

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
`pkS` and `skS`, respectively, as used in the protocol.

## OPRF(ristretto255, SHA-512)

### Base Mode

~~~
skSm = c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8
e03
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037
e50b
BlindedElement = 5cccd309ec729aebe398c53e19c0ab09c24a29f01036960bdad
109852e7bdb44
EvaluationElement = 86bd5eeabf29a87cb4a5c7207cb3ade5297e65f9b74c979b
d3551891f4b21515
Output = efd97b5a95b3b55ad7582d5ebd5dbc6cc1ca0aaca8cf5f942929e4e5b3f
53c716cdd4d6ce59ce1a21f066da1611d6e46ae6ce33ce6cc1b90f2f98aab8e52d32
3
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e326
3503
BlindedElement = 227d63ca69e93bd062193c1e97fff3d5ebf628f646009d77c4e
22ba6429be154
EvaluationElement = 063b91a12e7cbb98dfeb75d8a7eeb83aacf9fd6df7e0b419
7466fb77a27fa631
Output = 74d7355d722567ae5f58b2413ab082966a366edabda98a159c25da1cf9e
5547a352d015c2d1be2276fe768f77fa6388f85b2150405fd67739958ad3819d9d41
8
~~~

### Verifiable Mode

~~~
skSm = 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9dbcec831b8c681
a09
pkSm = eee7a9c7fec3460c27c160c683d46a4fd18f537c055c3998748b8e4cd8f29
b3e
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 89c61a42c8191a5ca41f2fe959843d333bcf43173b7de4c5c119e0e0d8b0
e707
BlindedElement = 78a09c84ecf234df4a46c3695f1be3b9c045476b6826bc7bc78
27c29a4978022
EvaluationElement = 5679669e01363a05e3da803c0b0cd76bffecd8048ec81eee
b391b7301e93aa2e
EvaluationProofC = 3f715285aa128ae3f444dc8b4572c3313ebd6cba9459974b7
d662210643cba07
EvaluationProofS = 3133eafd6928f41e87ada92ea7e8ec1b6a195b572c6379c6e
3dec0a250e0290a
Output = 0f4a4c8f18d4e4d926166b01e90fad9a12ae94ce512cd6ae792b985a1e4
fa599d5c403915d2f781b2961b41248f2055c642f6c10af9840f7ba32bb2812ed9c6
b
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 8d665022e9ad52b74c04a426f8af36205e81997c2175079b22a0b0a16270
c909
BlindedElement = 8e7060a2608dbbb1ba03922d7c633daca752400da8ee75af792
5e1affcf99871
EvaluationElement = a8208b606a6af1f7e2c5b155f908197aa786aba72585103b
ba35fa9ad703f426
EvaluationProofC = 7b6cc2cd2d3a0078045b9ba84b4451106e74e33980a0fe960
3447219cbab2804
EvaluationProofS = d5f25c13a61be0d9f2ddeb11cb55d3a8a2453d879630467f2
ffafb75d26d3b01
Output = c0b33cad9d19b3edee74ab75e0925871d96daeec9a1b30bbdafe1947dd9
d508b92da6179f9e0ee0d794bc165801bc689494cb3a9f4eeda4c55ba1f275112252
9
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 3af5aec325791592eee4a8860522f8444c8e71ac33af5186a9706137886d
ce08,8bcb0b70dac18de24eef12e737d6b28724d3e37774e0b092f9f70b255defaf0
4
BlindedElement = b8a0b4d0c056628131cd8ed1ea87cacecf6e09740c14a32c3e0
a2820e43afb3c,50a6b8dc62e95ac34320d7ceac08f4002710fdc49e56bde78b092d
01cad93e50
EvaluationElement = 12619d1c02de52189fa92f312eabe3062f627f0a75ccacd4
16d6dd2b71286e31,0093e963653200cacd9215833086a59e333db4b5f260db6a44c
81e8c7de59a5e
EvaluationProofC = 7abd23ea7e56b8272dc2876a22efe312331d614ff6e68a605
d10a9612bcce803
EvaluationProofS = 215cc766f8d0c492a3b5ff94b350fb5667a3be26d37fec3cb
a08773e2c55f908
Output = 0f4a4c8f18d4e4d926166b01e90fad9a12ae94ce512cd6ae792b985a1e4
fa599d5c403915d2f781b2961b41248f2055c642f6c10af9840f7ba32bb2812ed9c6
b,c0b33cad9d19b3edee74ab75e0925871d96daeec9a1b30bbdafe1947dd9d508b92
da6179f9e0ee0d794bc165801bc689494cb3a9f4eeda4c55ba1f2751122529
~~~

## OPRF(decaf448, SHA-512)

### Base Mode

~~~
skSm = c4d5a15f0d5ffc354e340454ec779f575e4573a3886ab5e57e4da2985cea9
e32f6d95539ce2c7189e1bd7462a21723e92e2e9955ef20a92c
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 5843ebd3618d4fad8b7288477da50bed9befa58af639ddd950fec34205f8
a4f166fadcb8fa71a3ffdd2e98f422bf7b99be19f7da1fab583c
BlindedElement = 84be45bb776f8f15e8ed716663a010773cb44ad3b2c4dc66948
c2972bac99913308f160737e3f32a44349584a4b6ef4adf924f5fcc192d17
EvaluationElement = a6cf272ceb18e8f6abcf9216819b0b2265ad10502633d087
1b102b5ea7f574d9c6852af32f1082b578878bd09709df1897aa064f52b16414
Output = 78185ecde195c20d313ff81ad9236d8df4c64727df049bf3b3f01e9d046
a9a1c4b3a3784864659558a98b861ac03191652e150a038bd1ed4d3d1d7c0bc9d3c0
6
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 5a9d35a225ec6340149a0aaf99870019c3d002aa4cfcf281657cf36fe562
bc60d9133e0e72a74432f685b2b620a55561604bb5783ca7f11d
BlindedElement = f0d1f1eb43b85e6dde38c0526151db3745b672667bef97bb0a3
553e191ad47f8c04e4a4c1588f028afecc170f15baeea2d44e86fe67982f8
EvaluationElement = f60cf47549fa62e72ae7253a4d42a8fc6ca70e0ac0ddc319
30627692eb3096792cf988115f792c99c03b08b0a5d07f2a2b7141dcb8c73cb9
Output = 7192f9f36b32b3f7280d6e66d942ddab204d4ccc5a1ddb82bce119e9f8b
b7d4ebe2d086ea2d395eebcbd9f7b047562efca7f1ef9b214ad21cd540b93462bae2
f
~~~

### Verifiable Mode

~~~
skSm = eb9e7aea3e4839413997e020f9377b63c13584156a09a46dd2a425c41eac0
e313a47e99d05df72c6e1d58e654a5ee9354b1150602f6adf2d
pkSm = 3ae16a2f8c506ebef74fafa9190e19447b07772e3077300b758411b941d8d
61f6b1840b35a73578f6aeb09e1a302a9d68f1db1cb34e90014
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = d83e00cbb8559f84cb7a221b235b0950a0ab553f03f10e1386abe954011b
7da62bb6599418ef90b5d4ea98cca1bcd65fa514f189d2b31a07
BlindedElement = 54c5fd05a11cd041f09a80db5e8a327b654d24563178b25a128
b549d32857167062e3ba259de5e938e3635af9d17fdb3cc38fe43d21951b5
EvaluationElement = 5e284dc6fecae55bb6263a03ca772979ea559b28c8ba316d
4fe3e8c6c38649455982f31f84679aa5db3264613671ab238a9950a28b5d6471
EvaluationProofC = 4a4cf011f145c9cbcf2a32ac6c7a87a3fc47d0b4dd376984e
7b8dd766d848dfdcafd042f43d95ca5ae9f7a1a81339e3344bbd16e912b312c
EvaluationProofS = b14fe0bb2978ebfe1eabb6630a795a1d139fab8a242a23b1c
ffb467a58c784fc4ce7d79b9c5db88b001486a69baef55da0656fa226065d36
Output = bcc27beaf945f2120ec04fb5d2833db486a2b0c5bfab88ccb449da0c635
ec0924607dabf51047abc41fead961a31620d8ac8206842594b056408b201a278417
a
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = ec86c5379228da260159dc24f7c5c2483a81aff8d9ff676ebd81db28eb1e
147561c478a3f84cbf77037f010272fd51abcff08ac9a7fcea16
BlindedElement = 9ca39b9c495b8fb1824923cd4b564a37e3921c7c6eeb799d448
9038f8b24388e858e67a461b776318eeb7fc1c59eb7e3f32b341a5b5d2308
EvaluationElement = ecf902b012dbd2cdf5de49ca99e2251948c93d345f7d4a6d
42b5ea5cd321ccdded0f89cfd63b3c77afe22924924814299e595a8656c2f56b
EvaluationProofC = 9e1460ad05a95cb1de937a848d425b9af54bd194fdc3681b6
79f9284b0c4ceac3800d31605f5ce8110b71ca4958b83188d146970e137c330
EvaluationProofS = 54e749430642257b68c347ccd2d95ecdda4a36fcc076e29f5
635a195616076e294f066286a156894594192fd1eeaf266111a297691bad80f
Output = a54b5c9b302e40e25fd61e3d80cd92d552d3c9465d24caffe4c07a3822a
d2fbea2644b895e7d6d44e7975fdb8ab2382d9c1735d770c6a7e26b0bb4096ab4c62
a
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 5b6f602b4b20a570a697452b3ddbb7d0e29363adebbcb5673294396b0b4e
7edc4adfc97a75132d92a1da241baff84fada3e7b12d569c0b3f,ad9ba734d54c2b2
4bff0ef6310404b5c05d60d7c258cea6500229ee057507c3e53534ad9db9f6df6ce5
15d1b8017923b65cada19e7a49a18
BlindedElement = ae30869b3292b406ffae15145f8d056232cc6c6b6ea9d49004f
d3a2492aa2770e28b0ee344ad438180deacf501ec54cae7c1f8b0c4e6958b,54fbd3
7ead128577c7536a862d018b29c3dbc9da09e6cbb9d7a96013b6ac8f9d0b1599cfd5
9292ea9ef95240c9e8796b41e49b3037b4984c
EvaluationElement = 92fe4293f5dad22e44e91659b20ee0e5fdf5f805d9148ee4
9573081aea607cf9e05ce16c802cf76db06b3f95d40175829c2950fd5ad1a82d,e60
a930f90ab1eca807b057200fb997c68808aab811cbde365451f86c4132684e613410
b00f39b7f080fd37ed4149cf3df5e7152ff8004b1
EvaluationProofC = cb3e9835b6765b0bec4de6a1f974c0331139d12135179f20b
4ea731847fc63a9a2779894f0ee4c48fefa9db1f12bcf14e94f937c318b4f11
EvaluationProofS = e2f7e4268d8f8a8d4ce93e38078cc531fdb44845b8d0ab640
f0d49983d9d57ceb6611f05e112ff9504d503c1972a1d2383d39180c0f70b2e
Output = bcc27beaf945f2120ec04fb5d2833db486a2b0c5bfab88ccb449da0c635
ec0924607dabf51047abc41fead961a31620d8ac8206842594b056408b201a278417
a,a54b5c9b302e40e25fd61e3d80cd92d552d3c9465d24caffe4c07a3822ad2fbea2
644b895e7d6d44e7975fdb8ab2382d9c1735d770c6a7e26b0bb4096ab4c62a
~~~

## OPRF(P-256, SHA-256)

### Base Mode

~~~
skSm = 2902c13bdc9993d3717bda68fc080b9802ae4effd5dc972d9f9fb3bbbf106
ade
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 359073c015b92d15450f7fb395bf52c6ea98384c491fe4e4d423b59de7b0
df39
BlindedElement = 03774b90bbb29af011e08dcb31ec7aa5f902afe02338f96d6b8
17400f7d77d987f
EvaluationElement = 02350c80b07aa03da012f7d9162645673bd3535a89b96bf5
2f4f0d9b026610b325
Output = 0155ea41ae88b027bf002fbc4594017e2c4d6e17be3335cad3573f3f4fd
5be05
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = b5e8f3c63b86ae88d9ce0530b01cb1c23382c7ec9bdd6e75898e4877d8e2
bc17
BlindedElement = 03ec4301d1d42a4582588a9258413a28cd997de3468e198f463
eadbffcc2adeaa5
EvaluationElement = 03807af5cbdbf6c56842f866b87c69f7b9fc4ab8d891353d
f97395f63145c9aea2
Output = 86bd7d240512bc81d570a5be62e75dd22d31ab01390df0c941a1d1215d9
57aeb
~~~

### Verifiable Mode

~~~
skSm = 4283efb9cd1ee4061c6bf884e60a877321ece4f9b6ffd01ce82082545413b
d9c
pkSm = 03c335d2eebd0ccbd5b8a145c9c2ee7452f401dcd4301ab138b0b56fc1c72
769cb
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 102f6338df84c9602bfa9e7d690b1f7a173d07e6d54a419db4a6308f8b09
589f
BlindedElement = 024829172675a0f6036657cd5d9eb0cfb97cad2eae79dfe5166
095d4db0fe4a49c
EvaluationElement = 02fef714dc9464983baca86fee8857a6afec020a9ea9440d
31f141c5957e04f494
EvaluationProofC = 1d634901d3367160384e2188b4283f61dcceab99c909c2ac4
58546c6e18e63b8
EvaluationProofS = 329b745b933ba604e2b7111784a35d3263bad600bfea3a6df
e8ec4509bb2be69
Output = 8d62e8d4d7de18a9bd39c5ecd1619b2ebc9a6f7159bcf3615be47be977c
40e3e
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 076f08753056c186437ded8ee22f96e44bd5b6ec07cb131d51cf1324c123
8699
BlindedElement = 03de136afec7e193e73d28d83e84a2b31b4532da77b8ee9a053
ad209873e3841cb
EvaluationElement = 03e2ce505dcac913ed1e29c1dd34cc3e3079887ee5775420
1e0642ede25538e27e
EvaluationProofC = e8ba14bd64a05295c4a2e416c284c0e6c9e7ffd5eeb9f9ac0
3702f35bc6c5187
EvaluationProofS = 70bb13362e796e3b87881f6226a5d76a406fc2ba876b41d9b
df69e323c9d6d38
Output = ffb8749294f1abe1dbc235593849a2f744de37f2a059da039ee3a7de781
3a894
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = bb1876a7f7165ac7ec79bfd5213ea2e374252f29a6e19915f81b0c7dcea9
3ce7,e04f47e8d2554a5ebd83679b4c1e67ed82f2891751aa7094602be672c324929
b
BlindedElement = 0245a57f9e991bb3661c3343772cdb16cc16217d441e0847c7d
4ae8eaad41a980f,0375e7898d32f42e0479a8bd7017378604df8d3eddee91f3a5e7
0df7126fe8050d
EvaluationElement = 030eb61d8599b8703ae0cd1c5b988d4dc9bf77645c2ce9b5
0f6e8bcee1149cd5a5,03f6055d4cb2471940ed0ee2b647a0cf89a283484c29febbf
2d49a7d77e7f23c4c
EvaluationProofC = b300cd485b9330bf1d5629230c30d1c04ae80597f95751ee6
87c3c269f174661
EvaluationProofS = 62352632de2e1eafae5d3fe820ff15733a095b256c59ac730
4f0bb49264fda1e
Output = 8d62e8d4d7de18a9bd39c5ecd1619b2ebc9a6f7159bcf3615be47be977c
40e3e,ffb8749294f1abe1dbc235593849a2f744de37f2a059da039ee3a7de7813a8
94
~~~

## OPRF(P-384, SHA-512)

### Base Mode

~~~
skSm = 06cc9faa9dc7ab251997738a3a232f352c2059c25684e6ccea420f8d0c793
f9f51171628f1d28bb7402ca4aea6465e27
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = ae86286729214a1ba9a359ab01833477b8cb91932d0c81667a0e3244b896
ac141b538ff23749be19e92df82df1acd3f7
BlindedElement = 0256ec771e8a7b770ff9ab40efb499279ed9a71d36ab6bc7d40
cd64565c66c2db285b8fe58f47e68bf3c02b98c90684aaa
EvaluationElement = 02bdf50a96769acb293d3ba11a124c6b784e921d2d3d3112
eb696a998a0a3464c9c27f6eddf8a270ac721678e75e7df344
Output = c36238cbfef6bfb73039547e24eaa9ff83c3bf2e052c4568d8c8c7a4a63
6b00af968e6698238081bffc431acc87d05baefc5901487e0e8eea8e0e90365dc9bd
f
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 523eff8db014d9b8b53ad7b0e149b0938b45f65717a40c38f671d326e196
e8a21bf6cfd40327a95f1ccfc82a9f83a75e
BlindedElement = 03a4badb8d617e78f7df557e183d01e1284920f5e84bc916b41
85b20f57129a09a301e57d4ea93463f398c31b52934e91c
EvaluationElement = 029fffdcadf404bec3ac2a120a0e4df38c6563e691cd256c
6fe6adaabb0362097b6026ae3c6e2995cf5f0c18548e6706af
Output = 7aaad5e12a9c614f284b57ac4e1de8dd869e53a3f41cbb13323b486da53
12ea11fa312400b132e056687b0444df821c714913c1ee873a6b1a3a1681ad3b3b0c
8
~~~

### Verifiable Mode

~~~
skSm = 32370deb7c3c17d9fc7cb4e0ce646e04e42d638e0fa7a434ed340772a8b5d
6253d35895f4cff282d86b2358d89a82ee7
pkSm = 023112a158597bf66974ec2391209063aa489fc1e98fec51be3a81aeeac03
b94dea1deee98515dc73c060a1432913d1a5d
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = bbabe8add48bcd149ff3b840dc8a5d2483705fcc9a39607288b935b0797a
c6b3c4b2e848823ac9ae16b3a3b5816be035
BlindedElement = 0255b8e051b51b644548304894e2f41b012075a807d5dc27169
7322cc057e19834c6f47e24309e2e102e44c92c321694a0
EvaluationElement = 03fbffe94ed4b87bbee72fbdc3d7698bc7f9e39af32a1612
ba1c4c2d626678754c0675644a67d7a9e6fdcb2da882018328
EvaluationProofC = ef1370d6f92b65902a100a6f0f3fb17be2964dcdb82588955
f3bf46e301f48bdedf4862d9ea34a9eff1d969fe7b63fa1
EvaluationProofS = bdab7b5892ac9b3f3e7c059abece91c84d75b5e8d4a72c60f
c21f9761baa4d38018a7a8422ba5c0653e249dd5c014c56
Output = 9a15b632ae81fd8eeb8b7d8517b34793fc0951f5278d1ec8b33bbc59b12
b94d7ad1123a149dbadd66ae4206e4f91c3240ec211d9d0c42284278831fdd99a9b6
1
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0470f06169bee12cf47965b72a59946ca387966f5d8331eab82117c88bbd
91b8954e16c0b9ceed3ce992b198be1ebfbb
BlindedElement = 0358930b1c57b54bf884d0b76904f11a4a139935e94ddc55287
678f041e9a9dc1f435a68f74df8c9d5febd1a4d910ad9fa
EvaluationElement = 02636fea7f2b916749f2eab123a9eff087688d8e5a7c2d95
df91b6defe1e0180c5272c9866ae95ad9697ae96c70967cc84
EvaluationProofC = 7e63181b843ed63cbb1c1c544a63314d4228da2e9810cd10f
febf36361942430d56d051f241a8f312f8a4c8ca2649792
EvaluationProofS = c355e9d57d928b5a79eb343a9e826a911e065c71f6ef2f380
47bf0a717959066f3cba79d5a5d0fa7c8991395132d0f6d
Output = cf65ed58228db965b697f704ca0665035519318ce12672e2141ba92f5e6
0bb73110e4a910c3644744c01a9d45a3959416faafad2cad9c497b1d3ee7dae7013c
4
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = a0d61b2f5a8a2a1143368327f3077c68a1545e9aafbba6a90dc0d4094ba4
283237211e139f306fc904c2d4fe4cc69c0b,90320718eff747e2482562df55c99bf
9591cb0eab2a72d044c05ca2cc2ef9b609a38546f74b6d688f70cf205f782fa12
BlindedElement = 0332a05819c8b2c1165d104b43e0b3e2fd49b17dd5e2a3c84bd
a805dbcebf20860d3a063d552f1190c6f79e64f01e6aee5,0337e5bd41e1b763aac3
39f488b158014a31addc5a8c69cdd4fcdc11305dca89fce402fd0ea27f5a6effc82d
bfb8fc7557
EvaluationElement = 03085806170058c5189010e315013a68259e862c08e6ef21
c40b9068dabc4187f611a303c57db80cdc3d9b4e537fcda75c,02936ab564ff79eea
ff16c3fdc176ba71c5351d60ec067daca44b7ebb3c106439ac0aaecaf9f8974a8326
90b8e17907150
EvaluationProofC = 0308322161e38b31d93998cb5c8f7bfefade3a78d1ca47ec9
a9b302ef1bce8e776556c202497ebedb490d17dadf728b3
EvaluationProofS = 9a2d60c36bf6e076cd17099b23c04463fd31af8eb9c64e7c3
e778b2dc40a42ca1b4ac0f12b24d32a65f846af40d634a4
Output = 9a15b632ae81fd8eeb8b7d8517b34793fc0951f5278d1ec8b33bbc59b12
b94d7ad1123a149dbadd66ae4206e4f91c3240ec211d9d0c42284278831fdd99a9b6
1,cf65ed58228db965b697f704ca0665035519318ce12672e2141ba92f5e60bb7311
0e4a910c3644744c01a9d45a3959416faafad2cad9c497b1d3ee7dae7013c4
~~~

## OPRF(P-521, SHA-512)

### Base Mode

~~~
skSm = 01b68fade716a6a82d600444b26de335ba38cf092d80c7cf2cb55388d8995
15238094c800bdd9c65f71780ba85f5ae9b4703e17e559ca3ccd1944f9a70536c175
f12
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 00dd0772f68b53baade9962d164565d8c0e3a1ba1a337759061965a423d9
d3d6e1e1006dc8984ad28a4c93ecfc36fc2171046b3c4284855cfa2434ed98db9e68
a598
BlindedElement = 0200c90f3a3d634131d2c6c28fb3c68cd4a2fcf645e02bf5dda
da3cd3400fe1a9b11c8149f74e97f305c6bbed99e4bf1d0e4e15648db2f7ca4d377f
d5e063767d8b878
EvaluationElement = 02015d9c192d77d428e77486ba09239c9e9666e3de62d578
7cade4d92e9017993607041fade15f90d8f6b45847b5f5a2c5355d7aa8696aa2a8a4
aef3b1f565c3c8010e
Output = 9681170a311adcf0a7af297b00a921ff1539f2497d7e2aba33843c9dbc0
74ac65d05fb967b8484685db483c4caa0946e1274ab19620190c174afa5d53d3dab5
7
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 00e8bea293aa8a69353b023f4a0e6a39eef47b0d4ca4c64825ba085de242
042b84d9ebe3b2e9de07678ff96713dfe16f40f2c662a56ed2db95e1e7bf2dea02bd
1fa8
BlindedElement = 02013e9e1424ad951f402f53dfea37908bba1e03bcb39984803
6620779fd2cab5d2d300e78600fcd256cb2d14ccaea3864561d848d561785ddabb3b
01b27155aae312a
EvaluationElement = 02014ccf9eeefaca351b8ddebe68b2682c98279a5222fe74
0cff6be1cd85c349bdea0e8be5bdb0e25ffa56f222076eaa823a625354809e34b08c
a8e7e7afd8465cfb14
Output = 57ab3b8d4f90c872686083d9cf20beb3ed2da3455cc9cc7c95568087a33
1c6245a12722bdea91872e242045400f42547817d1bfb1a9be8d2f09fb1740ae934a
8
~~~

### Verifiable Mode

~~~
skSm = 01449bb3b4ef3d5c65b55a1b8960563b3420d7764097502850c445ccd86e2
d20d7e4ec77617a4238835743037876080d2e3e27bc3ce7b5fb6a1107ffedeaedb37
177
pkSm = 02010dc16a63cb3e75fb306038b8364f55a1fff4e168538c4667cb1511260
ecae34fe14916ca1d19a0f2e208f537ae634751a9b85d80b33e9c02563de40c86d13
47679
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 0086b18e24c9a40ed5eec262bf51dc970d63acb5ab74318e54223c759e97
47f59c0d4ecbc087302667fabefa647b1766accb7c82a46aa3fc6caecbb9e935f0bf
b00f
BlindedElement = 03007023e7afe67d3c5a912bdc703e11822e3d72519a7724139
1958603e5356029f8a5ad66a71dd14054ffe6f5b5c5055a151dfcbaf36784c2cec4a
c3802681982afe2
EvaluationElement = 0301286ee7068eca78bff9786df0deba99abd288058f41fa
d91ba57cb5e946f37da2fb2486c70cc1570230b04b97fa1e732ff898ca032bb0fb11
955b70a226715368d5
EvaluationProofC = 014e49f4f4c068864269f45ada8115ae3212d2746b69c6a6d
ff73b432f556692f805fdaa7371df13a91dfeaee9045acdd6fb3be3d8db877ae6c71
128c729238452d5
EvaluationProofS = 00b84312491df1c68d228019f810e36017f6faf01e3b58e6c
3058692785771245abc565eb1aca32b912934cfd043334e258f87d5f8f4e6340fc66
a14e2640204b852
Output = d4b9cd4e38d00825dd2728e989cada729d245238955c429ecd3ee149ba2
8be6a6f080484e83d101e4958d81ecb211a8fedd23883775127c8d7df140a8b5b86f
8
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 00b9f3ad744eb5baf418275e45ab31ade30669dbae98fb0879524fb9234e
93a8bd048ad9f44b428026396a810328c405a354e666f086fa0ea4754fb56527be01
0297
BlindedElement = 0200df8a5b7753f5a6a640e6db207649cb07e3a76931a40e9c4
0e54dce933c26f0450461b2885eab5a202485ba35ae2ff006964b88af4069b68b9c1
554c3e940e0b943
EvaluationElement = 0200736c0d07ce6ccda8f0a8e31218ed844f7729c9943881
1f0d91a3cab6b0cde7b726cd65f9622e757d06bd8dad2894601e1635b3d345193a7c
e47e2d58b5bfb5ffa3
EvaluationProofC = 01be64214777cc5ac4113051e6859ff3cafe22eab039ff649
1376bbf4404c19eeb4434412bba527bd56a94e415beafb5717079796c0b7f05b6ebd
222988b1c1589bb
EvaluationProofS = 00e03d002ca56a92791f5b817e26718fa144f7e9d0db700ff
338e393dd949a57c94bcbbcfed037abd778c7e70c3fad4c6ac2413e7a336b7efe72a
b49281265bc18a2
Output = cb0b0295d81dc7feab24db72acd33225fc6bbb94df56408350bc9276961
0838ccf55c9358f82e34f298dfe8637eb2d2249f905e378b1ac3b42d1d293f57f4e0
0
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 01daf5685928c72d9dab8ddfe45de734ce0d4ff5823d2e40c4fcf880e9a8
272b46eea593b1095e7d38ba6ff37c42b3c4859761247a74d0c62c98ddff1365bb9b
82b3,00b96540574e2bc92534ac475d6a3649f3e9cdf20a7e882066be571714f5db0
73555bc1bfebe1d50a04fd6656a439cf465109653bf8e484c01c5f8516f98f3159b4
0
BlindedElement = 0300d45e787f24a39c52cc290f0b202c03d320b1213a9dd4429
df6b7f455a954b85815b5b379db5b4b9d665abaaf26366c91b8cd4884a2cddbf5be0
7420726de773fb7,030122ca1ad84feb6dc2832373011608a6d7f7f8e632c66cc6e1
34de50aa4317caa9c9b11cb281ae7dea4286a7c217cb9937d470f28a8c800dce277a
759342dd9a3e0d
EvaluationElement = 0301d8af9135b69b174238acd802e31323e84f9f66c7d3ca
68659ccd4456f16af156c15d48c8d7003f64fc8d814d09e5e4f0bf54dfd719ddaf10
19f667ea0f9e58afed,0300e253175c05483e6696eb6447f4e3ae87c0764909749a6
4c902dbe11a8d575e59d13c86f499483f99d707d5485ca441e48cc9e0f78fbb22225
b91c8870f8d094aae
EvaluationProofC = 005e5a1e175167da1912e87e6fac6fb0e4f20827a5ce1563b
211a128dc7777504ccdfeb314fe03477c87ed8337c25380761239ab0eb6c49cddbb9
723bd58e641375e
EvaluationProofS = 003a50338d747a86c7812a1a55a9e4628ecc839436e94e3ff
5c7f7f4c1d1db391865054c9aa127ffa9b3f7b6d32de2f48969381794da9a5493fa0
db8c68407e8b41c
Output = d4b9cd4e38d00825dd2728e989cada729d245238955c429ecd3ee149ba2
8be6a6f080484e83d101e4958d81ecb211a8fedd23883775127c8d7df140a8b5b86f
8,cb0b0295d81dc7feab24db72acd33225fc6bbb94df56408350bc92769610838ccf
55c9358f82e34f298dfe8637eb2d2249f905e378b1ac3b42d1d293f57f4e00
~~~
