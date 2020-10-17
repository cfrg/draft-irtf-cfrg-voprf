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
    org: Cloudflare
    street: County Hall
    city: London, SE1 7GP
    country: United Kingdom
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
  RFC2104:
  RFC2119:
  RFC5869:
  RFC7748:
  I-D.irtf-cfrg-hash-to-curve:
  draft-davidson-pp-protocol:
    title: "Privacy Pass: The Protocol"
    target: https://tools.ietf.org/html/draft-davidson-pp-protocol-00
    author:
      ins: A. Davidson
      org: Cloudflare Portugal
  NIST:
    title: Keylength - NIST Report on Cryptographic Key Length and Cryptoperiod (2016)
    target: https://www.keylength.com/en/4/
    date: false
  PrivacyPass:
    title: Privacy Pass
    target: https://github.com/privacypass/challenge-bypass-server
    date: false
  ChaumPedersen:
    title: Wallet Databases with Observers
    target: https://chaum.com/publications/Wallet_Databases.pdf
    date: false
    authors:
        -
          ins: D. Chaum
          org: CWI, The Netherlands
        -
          ins: T. P. Pedersen
          org: Aarhus University, Denmark
  ChaumBlindSignature:
    title: Blind Signatures for Untraceable Payments
    target: http://sceweb.sce.uhcl.edu/yang/teaching/csci5234WebSecurityFall2011/Chaum-blind-signatures.PDF
    date: false
    authors:
      -
        ins: D. Chaum
        org: University of California, Santa Barbara, USA
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
  JKKX17:
    title: >
      TOPPSS: Cost-minimal Password-Protected Secret Sharing based on Threshold OPRF
    target: https://eprint.iacr.org/2017/363
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
  RISTRETTO:
    title: The ristretto255 Group
    target: https://tools.ietf.org/html/draft-hdevalence-cfrg-ristretto-01
    date: false
    authors:
      -
        ins: H. de Valence
      -
        ins: J. Grigg
      -
        ins: G. Tankersley
      -
        ins: F. Valsorda
      -
        ins: I. Lovecruft
  DECAF:
    title: Decaf, Eliminating cofactors through point compression
    target: https://www.shiftleft.org/papers/decaf/decaf.pdf
    date: false
    authors:
      -
        ins: M. Hamburg
        org: Rambus Cryptography Research
  OPAQUE:
    title: The OPAQUE Asymmetric PAKE Protocol
    target: https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-02
    date: false
    authors:
      -
        ins: H. Krawczyk
        org: IBM Research
  SHAKE:
    title: SHA-3 Standard, Permutation-Based Hash and Extendable-Output Functions
    target: https://www.nist.gov/publications/sha-3-standard-permutation-based-hash-and-extendable-output-functions?pub_id=919061
    date: false
    authors:
      -
        ins: Morris J. Dworkin
        org: Federal Inf. Process. Stds. (NIST FIPS)
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
  keytrans:
    title: "Security Through Transparency"
    target: https://security.googleblog.com/2017/01/security-through-transparency.html
    date: false
    authors:
      -
        ins: Ryan Hurst
        org: Google
      -
        ins: Gary Belvin
        org: Google
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
pseudorandom if the keyed function K(_) = F(K, _) is indistinguishable
from a randomly sampled function acting on the same domain and range as
K(). An oblivious PRF (OPRF) is a two-party protocol between a server
and a client, where the server holds a PRF key k and the client holds
some input x. The protocol allows both parties to cooperate in computing
F(k, x) such that: the client learns F(k, x) without learning anything
about k; and the server does not learn anything about x. A Verifiable
OPRF (VOPRF) is an OPRF wherein the server can prove to the client that
F(k, x) was computed using the key k.

The usage of OPRFs has been demonstrated in constructing a number of
applications: password-protected secret sharing schemes {{JKKX16}};
privacy-preserving password stores {{SJKS17}}; and
password-authenticated key exchange or PAKE {{OPAQUE}}. The usage of a
VOPRF is necessary in some applications, e.g., the Privacy Pass protocol
{{draft-davidson-pp-protocol}}, wherein this VOPRF is used to generate
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

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}.

# Preliminaries

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
A`. For any element `A`, the equality `p*A=I` holds. The set of scalars
corresponds to `GF(p)`.

We now detail a number of member functions that can be invoked on a
prime-order group.

- Order(): Outputs the order of the group (i.e. `p`).
- Generator(): Outputs a fixed generator `G` for the group.
- Identity(): Outputs the identity element of the group (i.e. `I`).
- Serialize(A): A member function of `GG` that maps a group element `A`
  to a unique byte array `buf`.
- Deserialize(buf): A member function of `GG` that maps a byte array
  `buf` to a group element `A`.
- HashToGroup(x): A member function of `GG` that deterministically maps
  an array of bytes `x` to an element of `GG`. The map must ensure that,
  for any adversary receiving `R = HashToGroup(x)`, it is
  computationally difficult to reverse the mapping. Examples of hash to
  group functions satisfying this property are described for prime-order
  (sub)groups of elliptic curves, see {{I-D.irtf-cfrg-hash-to-curve}}.
- HashToScalar(x): A member function of `GG` that deterministically maps
  an array of bytes `x` to a random element in GF(p). A recommended method
  for its implementation is instantiating the hash to field function,
  defined in {{I-D.irtf-cfrg-hash-to-curve}}, but setting the order of
  the group as the modulus of a prime field.
- RandomScalar(): A member function of `GG` that generates a random,
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
for advice corresponding to implementation of this interface for
specific definitions of elliptic curves.

## Other conventions

- We use the notation `x <-$ Q` to denote sampling `x` from the uniform
  distribution over the set `Q`.
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
returns a boolean `true` if `a` and `b` are equal, and `false`
otherwise.

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

## Overview

Both participants agree on the mode and a choice of ciphersuite that is
used before the protocol exchange. Once established, the core protocol
runs to compute `output = F(skS, input)` as follows:

~~~
   Client(pkS, input, info)                 Server(skS, pkS)
  ----------------------------------------------------------
    token, blindToken = Blind(input)

                         blindToken
                        ---------->

                         evaluation = Evaluate(skS, pkS, blindToken)

                         evaluation
                        <----------

    issuedToken = Unblind(pkS, token, blindToken, evaluation)
    output = Finalize(input, issuedToken, info)
~~~

In `Blind` the client generates a token and blinding data. The server
computes the (V)OPRF evaluation in `Evaluation` over the client's
blinded token. In `Unblind` the client unblinds the server response (and
verifies the server's proof if verifiability is required). In
`Finalize`, the client outputs a byte array corresponding to its input.

Note that in the final output, the client computes Finalize over some
auxiliary input data `info`. This parameter SHOULD be used for domain
separation in the (V)OPRF protocol. Specifically, any system which has
multiple (V)OPRF applications should use separate auxiliary values to to
ensure finalized outputs are separate. Guidance for constructing info
can be found in {{I-D.irtf-cfrg-hash-to-curve}}; Section 3.1.

## Context Setup

Both modes of the OPRF involve an offline setup phase. In this phase,
both the client and server create a context used for executing the
online phase of the protocol. The base mode setup functions for creating
client and server contexts are below:

~~~
def SetupBaseServer(suite):
  (skS, _) = KeyGen(GG)
  contextString = I2OSP(modeBase, 1) || I2OSP(suite.ID, 2)
  return ServerContext(contextString, skS)

def SetupBaseClient(suite):
  contextString = I2OSP(modeBase, 1) || I2OSP(suite.ID, 2)
  return ClientContext(contextString)
~~~

The `KeyGen` function used above takes a group `GG` and generates a
private and public key pair (skX, pkX), where skX is a random, non-zero
element in the scalar field `GG` and pkX is the product of skX and the
group's fixed generator.

For base mode, servers do not need the public key `pkS` produced by KeyGen.

The verifiable mode setup functions for creating client and server
contexts are below.

~~~
def SetupVerifiableServer(suite):
  (skS, pkS) = KeyGen(GG)
  contextString = I2OSP(modeVerifiable, 1) || I2OSP(suite.ID, 2)
  return VerifiableServerContext(contextString, skS), pkS

def SetupVerifiableClient(suite, pkS):
  contextString = I2OSP(modeVerifiable, 1) || I2OSP(suite.ID, 2)
  return VerifiableClientContext(contextString, pkS)
~~~

For verifiable modes, servers MUST make the resulting public key `pkS`
accessible for clients. (Indeed, it is a required parameter when
configuring a verifiable client context.)

Each setup function takes a ciphersuite from the list defined in
{{ciphersuites}}. Each ciphersuite has two-byte identifier, referred to
as `suite.ID` in the pseudocode above, that identifies the suite.
{{ciphersuites}} lists these ciphersuite identifiers.

## Data Structures {#structs}

The following is a list of data structures that are defined for
providing inputs and outputs for each of the context interfaces defined
in {{api}}. Each data structure description uses TLS notation
(see {{?RFC8446}}, Section 3).

The following types are a list of aliases that are used throughout the
protocol.

A `ClientInput` is a byte array.

~~~
opaque ClientInput<1..2^16-1>;
~~~

A `SerializedElement` is also a byte array, representing the unique
serialization of an `Element`.

~~~
opaque SerializedElement<1..2^16-1>;
~~~

A `Token` is an object created by a client when constructing a (V)OPRF
protocol input. It is stored so that it can be used after receiving the
server response.

~~~
struct {
  opaque data<1..2^16-1>;
  Scalar blind<1..2^16-1>;
} Token;
~~~

An `Evaluation` is the type output by the `Evaluate` algorithm. The
member `proof` is added only in verifiable contexts.

~~~
struct {
  SerializedElement element;
  Scalar proof<0...2^16-1>; /* only for modeVerifiable */
} Evaluation;
~~~

Evaluations may also be combined in batches with a constant-size proof,
producing a `BatchedEvaluation`. These carry a list of
`SerializedElement` values and proof. These evaluation types are only
useful in verifiable contexts which carry proofs.

~~~
struct {
  SerializedElement elements<1..2^16-1>;
  Scalar proof<0...2^16-1>; /* only for modeVerifiable */
} BatchedEvaluation;
~~~

## Context APIs {#api}

In this section, we detail the APIs available on the client and server
OPRF contexts. This document uses the types `Element` and `Scalar` to
denote elements of the group `GG` and its underlying scalar field `GF(p)`,
respectively. For notational clarity, `PublicKey` is an item of type
`Element` and `PrivateKey` is an item of type `Scalar`.

### Server Context

The ServerContext encapsulates the context string constructed during
setup and the OPRF key pair. It has two functions, `Evaluate` and
`VerifyFinalize`, described below. `Evaluate` takes serialized
representations of blinded group elements from the client as inputs.
`VerifyFinalize` takes ClientInput values and their corresponding output
digests from `Verify` as input, and returns true if the inputs match the outputs.
Note that `VerifyFinalize` is not used in the main OPRF protocol. It is
exposed as an API for building higher-level protocols.

#### Evaluate

~~~
Input:

  PrivateKey skS
  SerializedElement blindToken

Output:

  Evaluation Ev

def Evaluate(skS, blindToken):
  BT = GG.Deserialize(blindToken)
  Z = skS * BT
  serializedElement = GG.Serialize(Z)

  Ev = Evaluation{ element: serializedElement }

  return Ev
~~~

#### VerifyFinalize

~~~
Input:

  PrivateKey skS
  ClientInput input
  opaque info<1..2^16-1>
  opaque output<1..2^16-1>

Output:

  boolean valid

def VerifyFinalize(skS, input, info, output):
  T = GG.HashToGroup(input)
  element = GG.Serialize(T)
  issuedElement = Evaluate(skS, [element])
  E = GG.Serialize(issuedElement)

  finalizeDST = "RFCXXXX-Finalize-" || client.contextString
  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(E), 2) || E ||
              I2OSP(len(info), 2) || info ||
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

  PrivateKey skS
  PublicKey pkS
  SerializedElement blindToken

Output:

  Evaluation Ev

def Evaluate(skS, pkS, blindToken):
  BT = GG.Deserialize(blindToken)
  Z = skS * BT
  serializedElement = GG.Serialize(Z)

  proof = GenerateProof(skS, pkS, blindToken, serializedElement)
  Ev = Evaluation{ element: serializedElement, proof: proof }

  return Ev
~~~

The helper functions `GenerateProof` and `ComputeComposites` are defined
below.

#### GenerateProof

~~~
Input:

  PrivateKey skS
  PublicKey pkS
  SerializedElement blindToken
  SerializedElement element

Output:

  Scalar proof[2]

def GenerateProof(skS, pkS, blindToken, element)
  G = GG.Generator()

  blindTokenList = [blindToken]
  elementList = [element]

  (a1, a2) = ComputeComposites(pkS, blindTokenList, elementList)

  M = GG.Deserialize(a1)
  r = GG.RandomScalar()
  a3 = GG.Serialize(r * G)
  a4 = GG.Serialize(r * M)

  challengeDST = "RFCXXXX-challenge-" || self.contextString
  h2Input = I2OSP(len(pkS), 2) || pkS ||
            I2OSP(len(a1), 2) || a1 ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            I2OSP(len(a4), 2) || a4 ||
            I2OSP(len(challengeDST), 2) || challengeDST

  c = GG.HashToScalar(h2Input)
  s = (r - c * skS) mod p

  return (c, s)
~~~

##### Batching inputs

Unlike other functions, `ComputeComposites` takes lists of inputs,
rather than a single input. It is optimized to produce a constant-size
output. This functionality lets applications batch inputs together to
produce a constant-size proofs from `GenerateProof`. Applications can
take advantage of this functionality by invoking `GenerateProof` on
batches of inputs. (Notice that in the pseudocode above, the single
inputs `blindToken` and `element` are translated into lists before
invoking `ComputeComposites`. A batched `GenerateProof` variant would
permit lists of inputs, and no list translation would be needed.)

Note that using batched inputs creates a `BatchedEvaluation` object as
the output of `Evaluate`.

##### Fresh randomness

We note here that it is essential that a different r value is used for
every invocation. If this is not done, then this may leak `skS` as is
possible in Schnorr or (EC)DSA scenarios where fresh randomness is not
used.

#### ComputeComposites

~~~
Input:

  PublicKey pkS
  SerializedElement blindTokens[m]
  SerializedElement elements[m]

Output:

  SerializedElement composites[2]

def ComputeComposites(pkS, blindTokens, elements):
  seedDST = "RFCXXXX-seed-" || self.contextString
  compositeDST = "RFCXXXX-composite-" || self.contextString
  h1Input = I2OSP(len(pkS), 2) || pkS ||
            I2OSP(len(blindTokens), 2) || blindTokens ||
            I2OSP(len(elements), 2) || elements ||
            I2OSP(len(seedDST), 2) || seedDST

  seed = Hash(h1Input)
  M = GG.Identity()
  Z = GG.Identity()
  for i = 0 to m:
    h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
              I2OSP(len(compositeDST), 2) || compositeDST
    di = GG.HashToScalar(h2Input)
    Mi = GG.Deserialize(blindTokens[i])
    Zi = GG.Deserialize(elements[i])
    M = di * Mi + M
    Z = di * Zi + Z
 return [GG.Serialize(M), GG.Serialize(Z)]
~~~

### Client Context

The ClientContext encapsulates the context string constructed during
setup. It has three functions, `Blind()`, `Unblind()`, and `Finalize()`,
as described below.

#### Blind

We note here that the blinding mechanism that we use can be modified
slightly with the opportunity for making performance gains in some
scenarios. We detail these modifications in {{blinding}}.

~~~
Input:

  ClientInput input

Output:

  Token token
  SerializedElement blindToken

def Blind(input):
  r = GG.RandomScalar()
  P = GG.HashToGroup(input)
  blindToken = GG.Serialize(r * P)

  token = Token{ data: input, blind: r }

  return (token, blindToken)
~~~

#### Unblind

~~~
Input:

  Token token
  Evaluation Ev

Output:

  SerializedElement issuedToken

def Unblind(token, Ev):
  r = token.blind
  Z = GG.Deserialize(Ev.element)
  N = (r^(-1)) * Z

  issuedToken = GG.Serialize(N)

  return issuedToken
~~~

#### Finalize

~~~
Input:

  Token token
  SerializedElement issuedToken
  opaque info<1..2^16-1>

Output:

  opaque output<1..2^16-1>

def Finalize(token, issuedToken, info):
  finalizeDST = "RFCXXXX-Finalize-" || self.contextString
  hashInput = I2OSP(len(token.data), 2) || token.data ||
              I2OSP(len(issuedToken), 2) || issuedToken ||
              I2OSP(len(info), 2) || info ||
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
  SerializedElement blindToken
  Evaluation Ev

Output:

  boolean verified

def VerifyProof(pkS, blindToken, Ev):
  G = GG.Generator()

  blindTokenList = [blindToken]
  elementList = [Ev.element]

  (a1, a2) = ComputeComposites(pkS, blindTokenList, elementList)

  A' = (Ev.proof[1] * G + Ev.proof[0] * pkS)
  B' = (Ev.proof[1] * M + Ev.proof[0] * Z)
  a3 = GG.Serialize(A')
  a4 = GG.Serialize(B')

  challengeDST = "RFCXXXX-challenge-" || self.contextString
  h2Input = I2OSP(len(pkS), 2) || pkS ||
            I2OSP(len(a1), 2) || a1 ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            I2OSP(len(a4), 2) || a4 ||
            I2OSP(len(challengeDST), 2) || challengeDST

  c  = GG.HashToScalar(h2Input)

  return CT_EQUAL(c, Ev.proof[0])
~~~

#### Unblind

~~~
Input:

  PublicKey pkS
  Token token
  SerializedElement blindToken
  Evaluation Ev

Output:

  SerializedElement issuedToken

def Unblind(pkS, token, blindToken, Ev):
  if VerifyProof(pkS, blindToken, Ev) == false:
    ABORT()

  r = token.blind
  Z = GG.Deserialize(Ev.element)
  N = (r^(-1)) * Z

  issuedToken = GG.Serialize(N)

  return issuedToken
~~~

# Ciphersuites {#ciphersuites}

A ciphersuite (also referred to as 'suite' in this document) for the protocol
wraps the functionality required for the protocol to take place. This
ciphersuite should be available to both the client and server, and agreement
on the specific instantiation is assumed throughout. A ciphersuite contains
instantiations of the following functionalities:

- `GG`: A prime-order group exposing the API detailed in {{pog}}.
- `Hash`: A cryptographic hash function that is indifferentiable from a
  Random Oracle.

This section specifies supported VOPRF group and hash function
instantiations. For each group, we specify the HashToGroup, HashToScalar,
and Serialize functionalities. The Deserialize functionality is the inverse
of the corresponding Serialize functionality.

We only provide ciphersuites in the elliptic curve setting as these
provide the most efficient way of instantiating the OPRF.

Applications should take caution in using ciphersuites targeting P-256
and curve25519. See {{cryptanalysis}} for related discussion.

[[OPEN ISSUE: Replace Curve25519 and Curve448 with Ristretto and Decaf]]

## OPRF(curve25519, SHA-512)

- Group:
  - Elliptic curve name: curve25519 {{RFC7748}}
  - Generator(): Return the point with the following affine coordinates:
    - x = `09`
    - y =
      `5F51E65E475F794B1FE122D388B72EB36DC2B28192839E4DD6163A5D81312C14`
  - Order(): Returns
  `1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED`
  - HashToGroup(): curve25519_XMD:SHA-512_ELL2_RO_
    {{I-D.irtf-cfrg-hash-to-curve}} with DST
    "RFCXXXX-curve25519_XMD:SHA-512_ELL2_RO_"
  - HashToScalar(): Use hash_to_field from {{I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L=48, and expand_message_xmd with
    SHA-512.
  - Serialization: The standard 32-byte representation of the public key
    {{!RFC7748}}
  - Addition: Adding curve points directly corresponds to the group
    addition operation.
  - Deserialization: Implementers must check for each untrusted input
    point whether it's a member of the big prime-order subgroup of the
    curve. This can be done by scalar multiplying the point by Order()
    and checking whether it's zero.
- Hash: SHA-512
- ID: 0x0001

## OPRF(curve448, SHA-512)

- Group:
  - Elliptic curve name: curve448 {{RFC7748}}
  - Generator(): Return the point with the following affine coordinates:
    - x = `05`
    - y =
      `7D235D1295F5B1F66C98AB6E58326FCECBAE5D34F55545D060F75DC28DF3F6EDB8027E2346430D211312C4B150677AF76FD7223D457B5B1A`
  - Order(): Returns `3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3`
  - HashToGroup(): curve448_XMD:SHA-512_ELL2_RO_
    {{I-D.irtf-cfrg-hash-to-curve}} with DST
    "RFCXXXX-curve448_XMD:SHA-512_ELL2_RO_"
  - HashToScalar(): Use hash_to_field from {{I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L=84, and expand_message_xmd with
    SHA-512.
  - Serialization: The standard 56-byte representation of the public key
    {{!RFC7748}}
  - Addition: Adding curve points directly corresponds to the group
    addition operation.
  - Deserialization: Implementers must check for each untrusted input
    point whether it's a member of the big prime-order subgroup of the
    curve. This can be done by scalar multiplying the point by Order()
    and checking whether it's zero.
- Hash: SHA-512
- ID: 0x0002

## OPRF(P-256, SHA-512)

- Group:
  - Elliptic curve name: P-256 (secp256r1) {{x9.62}}
  - Generator(): Return the point with the following affine coordinates:
    - x =
      `6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296`
    - y =
      `4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5`
  - Order(): Returns
  `FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551`
  - HashToGroup(): P256_XMD:SHA-256_SSWU_RO_
    {{I-D.irtf-cfrg-hash-to-curve}} with DST
    "RFCXXXX-P256_XMD:SHA-256_SSWU_RO_"
  - HashToScalar(): Use hash_to_field from {{I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L=48, and expand_message_xmd with
    SHA-512.
  - Serialization: The compressed point encoding for the curve {{SEC1}}
    consisting of 33 bytes.
  - Addition: Adding curve points directly corresponds to the group
    addition operation.
  - Scalar multiplication: Scalar multiplication of curve points
    directly corresponds with scalar multiplication in the group.
- Hash: SHA-512
- ID: 0x0003

## OPRF(P-384, SHA-512)

- Group:
  - Elliptic curve name: P-384 (secp384r1) {{x9.62}}
  - Generator(): Return the point with the following affine coordinates:
    - x =
      `AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7`
    - y =
      `3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F`
  - Order(): Returns
  `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973`
  - HashToGroup(): P384_XMD:SHA-512_SSWU_RO_
    {{I-D.irtf-cfrg-hash-to-curve}} with DST
    "RFCXXXX-P384_XMD:SHA-512_SSWU_RO_"
  - HashToScalar(): Use hash_to_field from {{I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L=72, and expand_message_xmd with
    SHA-512.
  - Serialization: The compressed point encoding for the curve {{SEC1}}
    consisting of 49 bytes.
  - Addition: Adding curve points directly corresponds to the group
    addition operation.
  - Scalar multiplication: Scalar multiplication of curve points
    directly corresponds with scalar multiplication in the group.
- Hash: SHA-512
- ID: 0x0004

## OPRF(P-521, SHA-512)

- Group:
  - Elliptic curve name: P-521 (secp521r1) {{x9.62}}
  - Generator(): Return the point with the following affine coordinates:
    - x =
      `00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66`
    - y =
      `011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650`
  - Order(): Returns
  `1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409`
  - HashToGroup(): P521_XMD:SHA-512_SSWU_RO_
    {{I-D.irtf-cfrg-hash-to-curve}} with DST
    "RFCXXXX-P521_XMD:SHA-512_SSWU_RO_"
  - HashToScalar(): Use hash_to_field from {{I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L=98, and expand_message_xmd with
    SHA-512.
  - Serialization: The compressed point encoding for the curve {{SEC1}}
    consisting of 67 bytes.
  - Addition: Adding curve points directly corresponds to the group
    addition operation.
  - Scalar multiplication: Scalar multiplication of curve points
    directly corresponds with scalar multiplication in the group.
- Hash: SHA-512
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

Let GG = GG(sp) be a group with prime-order p, and let FFp be the finite
field of order p.

#### Discrete-log (DL) problem {#dl}

Given G, a generator of GG, and H = hG for some h in FFp; output h.

#### Decisional Diffie-Hellman (DDH) problem {#ddh}

Sample a uniformly random bit d in {0,1}. Given (G, aG, bG, C), where:

- G is a generator of GG;
- a,b are elements of FFp;
- if d == 0: C = abG; else: C is sampled uniformly GG(sp).

Output d' == d.

### Protocol security {#protocol-sec}

Our OPRF construction is based on the VOPRF construction known as
2HashDH-NIZK given by {{JKK14}}; essentially without providing
zero-knowledge proofs that verify that the output is correct. Our VOPRF
construction is identical to the {{JKK14}} construction, except that we
can optionally perform multiple VOPRF evaluations in one go, whilst only
constructing one NIZK proof object. This is enabled using an established
batching technique.

Consequently the cryptographic security of our construction is based on
the assumption that the One-More Gap DH is computationally difficult to
solve.

The (N,Q)-One-More Gap DH (OMDH) problem asks the following.

~~~
    Given:
    - G, k * G, G_1, ... , G_N where G, G_1, ... G_N are elements of GG;
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

    Output ( (1/(k+c))*G1, c ) where c is an element of FFp
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
client that submit Q queries to the OPRF can use the aforementioned
attacks to reduce security of the group instantiation by log_2(Q) bits.

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
uniformly chosen points in the curve.

In the security proof of the construction Hash is modeled as a random
oracle. This implies that any instantiation of `GG.HashToGroup` must be
pre-image and collision resistant. In {{ciphersuites}} we give
instantiations of this functionality based on the functions described in
{{I-D.irtf-cfrg-hash-to-curve}}. Consequently, any OPRF implementation
must adhere to the implementation and security considerations discussed
in {{I-D.irtf-cfrg-hash-to-curve}} when instantiating the function.

## Timing Leaks

To ensure no information is leaked during protocol execution, all
operations that use secret data MUST be constant time. Operations that
SHOULD be constant time include all prime-order group operations and
proof-specific operations (`GenerateProof()` and `VerifyProof()`).

## Key rotation {#key-rotation}

Since the server's key is critical to security, the longer it is exposed
by performing (V)OPRF operations on client inputs, the longer it is
possible that the key can be compromised. For example,if the key is kept
in circulation for a long period of time, then it also allows the
clients to make enough queries to launch more powerful variants of the
Q-sDH attacks from {{qsdh}}.

To combat attacks of this nature, regular key rotation should be
employed on the server-side. A suitable key-cycle for a key used to
compute (V)OPRF evaluations would be between one week and six months.

# Additive blinding {#blinding}

Let `H` refer to the function `GG.HashToGroup`, in {{pog}} we assume
that the client-side blinding is carried out directly on the output of
`H(x)`, i.e. computing `r * H(x)` for some `r <-$ GF(p)`. In the
{{OPAQUE}} document, it is noted that it may be more efficient to use
additive blinding (rather than multiplicative) if the client can
preprocess some values. For example, a valid way of computing additive
blinding would be to instead compute `H(x) + (r * G)`, where `G` is the
fixed generator for the group `GG`.

The advantage of additive blinding is that it allows the client to
pre-process tables of blinded scalar multiplications for `G`. This may
give it a computational efficiency advantage (due to the fact that a
fixed-base multiplication can be calculated faster than a variable-base
multiplication). Pre-processing also reduces the amount of computation
that needs to be done in the online exchange. Choosing one of these
values `r * G` (where `r` is the scalar value that is used), then
computing `H(x) + (r * G)` is more efficient than computing `r * H(x)`.
Therefore, it may be advantageous to define the OPRF and VOPRF protocols
using additive blinding (rather than multiplicative) blinding. In fact,
the only algorithms that need to change are Blind and Unblind (and
similarly for the VOPRF variants).

We define the variants of the algorithms in {{api}} for performing
additive blinding below, along with a new algorithm `Preprocess`. The
`Preprocess` algorithm can take place offline and before the rest of the
OPRF protocol. The Blind algorithm takes the preprocessed values as
inputs, but the signature of Unblind remains the same.

## Preprocess

~~~
struct {
  Scalar blind;
  SerializedElement blindedGenerator;
  SerializedElement blindedPublicKey;
} PreprocessedBlind;
~~~

~~~
Input:

  PublicKey pkS

Output:

  PrepocessedBlind preproc

def Preprocess(pkS):
  PK = GG.Deserialize(pkS)
  r = GG.RandomScalar()
  blindedGenerator = GG.Serialize(r * GG.Generator())
  blindedPublicKey = GG.Serialize(r * PK)

  preproc = PrepocessedBlind{
    blind: r,
    blindedGenerator: blindedGenerator,
    blindedPublicKey: blindedPublicKey,
  }

  return preproc
~~~

## Blind

~~~
Input:

  ClientInput input
  PreprocessedBlind preproc

Output:

  Token token
  SerializedElement blindToken

def Blind(input, preproc):
  Q = GG.Deserialize(preproc.blindedGenerator) /* Q = r * G */
  P = GG.HashToGroup(input)

  token = Token{
    data: input,
    blind: preproc.blindedPublicKey
  }
  blindToken = GG.Serialize(P + Q)           /* P + r * G */

  return (token, blindToken)
~~~

## Unblind

~~~
Input:

  Token token
  Evaluation ev
  SerializedElement blindToken

Output:

 SerializedElement unblinded

def Unblind(token, ev, blindToken):
  PKR = GG.Deserialize(token.blind)
  Z = GG.Deserialize(ev.element)
  N := Z - PKR

  issuedToken = GG.Serialize(N)

  return issuedToken
~~~

Let `P = GG.HashToGroup(x)`. Notice that Unblind computes:

~~~
Z - PKR = k * (P + r * G) - r * pkS
        = k * P + k * (r * G) - r * (k * G)
        = k * P
~~~

by the commutativity of scalar multiplication in GG. This is the same
output as in the `Unblind` algorithm for multiplicative blinding.

Note that the verifiable variant of `Unblind` works as above but
includes the step to `VerifyProof`, as specified in
{{verifiable-client}}.

### Parameter Commitments

For some applications, it may be desirable for server to bind tokens to
certain parameters, e.g., protocol versions, ciphersuites, etc. To
accomplish this, server should use a distinct scalar for each parameter
combination. Upon redemption of a token T from the client, server can
later verify that T was generated using the scalar associated with the
corresponding parameters.

# Contributors

- Alex Davidson         (alex.davidson92@gmail.com)
- Nick Sullivan         (nick@cloudflare.com)
- Chris Wood            (caw@heapingbits.net)
- Eli-Shaoul Khedouri   (eli@intuitionmachines.com)
- Armando Faz Hernandez (armfazh@cloudflare.com)

# Acknowledgements

This document resulted from the work of the Privacy Pass team
{{PrivacyPass}}. The authors would also like to acknowledge the helpful
conversations with Hugo Krawczyk. Eli-Shaoul Khedouri provided
additional review and comments on key consistency.

--- back
