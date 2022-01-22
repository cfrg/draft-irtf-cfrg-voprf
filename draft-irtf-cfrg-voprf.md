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
    org: Cloudflare, Inc.
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: armfazh@cloudflare.com
 -
    ins: N. Sullivan
    name: Nick Sullivan
    org: Cloudflare, Inc.
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: nick@cloudflare.com
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare, Inc.
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: caw@heapingbits.net

normative:
  RFC2119:

informative:
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
  ChaumPedersen:
    title: "Wallet Databases with Observers"
    target: https://chaum.com/publications/Wallet_Databases.pdf
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
  keyagreement: DOI.10.6028/NIST.SP.800-56Ar3

--- abstract

An Oblivious Pseudorandom Function (OPRF) is a two-party protocol between
client and server for computing the output of a Pseudorandom Function (PRF).
The server provides the PRF secret key, and the client provides the PRF
input. At the end of the protocol, the client learns the PRF output without
learning anything about the PRF secret key, and the server learns neither
the PRF input nor output. An OPRF can also satisfy a notion of 'verifiability',
called a VOPRF. A VOPRF ensures clients can verify that the server used a
specific private key during the execution of the protocol. A VOPRF can also
be partially-oblivious, called a POPRF. A POPRF allows clients and servers
to provide public input to the PRF computation. This document specifies an OPRF,
VOPRF, and POPRF instantiated within standard prime-order groups, including
elliptic curves.

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
A Verifiable OPRF (VOPRF) is an OPRF wherein the server can prove to
the client that F(k, x) was computed using the key k. A Partially-Oblivious
PRF (POPRF) is a variant of a VOPRF wherein client and server interact
in computing F(k, x, y), for some PRF F with server-provided key k,
client-provided input x, and public input y, and client receives proof
that F(k, x, y) was computed using k. A POPRF with fixed input y is
functionally equivalent to a VOPRF.

OPRFs have a variety of applications, including: password-protected secret
sharing schemes {{JKKX16}}, privacy-preserving password stores {{SJKS17}}, and
password-authenticated key exchange or PAKE {{!I-D.irtf-cfrg-opaque}}.
Verifiable POPRFs are necessary in some applications such as Privacy Pass
{{!I-D.davidson-pp-protocol}}. Verifiable POPRFs have also been used for
password-protected secret sharing schemes such as that of {{JKK14}}.

This document specifies OPRF, VOPRF, and POPRF protocols built upon
prime-order groups based on the 2HashDH {{JKKX16}} and 3HashSDHI {{TCRSTW21}}
designs, respectively. The document describes each protocol variant,
along with application considerations, and their security properties.

## Change log

[draft-08](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-08):

- Adopt partially-oblivious PRF construction from {{TCRSTW21}}.
- Update P-384 suite to use SHA-384 instead of SHA-512.
- Update test vectors.
- Apply various editorial changes.

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

For serialization, all data structure descriptions use TLS notation {{RFC8446, Section 3}}.

All algorithms and procedures described in this document are laid out
in a Python-like pseudocode. The data types `PrivateInput` and `PublicInput`
are opaque byte strings of arbitrary length no larger than 2^13 octets.

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

# Preliminaries

The protocols in this document have two primary dependencies:

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

## Discrete Log Equivalence Proofs {#dleq}

Another important piece of the OPRF protocols in this document is proving
that the discrete log of two values is identical in zero knowledge, i.e.,
without revealing the discrete logarithm. This is referred to as a discrete
log equivalence (DLEQ) proof. This section describes functions
for non-interactively proving and verifying this type of statement,
built on a Chaum-Pedersen {{ChaumPedersen}} proof. It is split into
two sub-sections: one for generating the proof, which is done by servers
in the verifiable protocols, and another for verifying the proof, which is
done by clients in the protocol.

### Proof Generation

Generating a proof is done with the `GenerateProof` function, defined below.
This function takes four Elements, A, B, C, and D, and a single
group Scalar k, and produces a proof that `k*A == B` and `k*C == D`.
The output is a value of type Proof, which is a tuple of two Scalar
values.

~~~
GenerateProof

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

  h2Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(a0), 2) || a0 ||
            I2OSP(len(a1), 2) || a1 ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            "Challenge"

  c = GG.HashToScalar(h2Input)
  s = (r - c * k) mod p

  return [c, s]
~~~

The helper function ComputeCompositesFast is as defined below.

~~~
ComputeCompositesFast

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
              "Composite"

    di = GG.HashToScalar(h2Input)
    M = di * Cs[i] + M

  Z = k * M

 return (M, Z)
~~~

`ComputeCompositesFast` takes lists of inputs, rather than a single input.
Applications can take advantage of this functionality by invoking `GenerateProof`
on batches of inputs to produce a combined, constant-size proof.
In particular, servers can produce a single, constant-sized proof for N DLEQ inputs,
rather than one proof per DLEQ input. This optimization benefits
clients and servers since it amortizes the cost of proof generation
and bandwidth across multiple requests.

### Proof Verification

Verifying a proof is done with the `VerifyProof` function, defined below.
This function takes four Elements, A, B, C, and D, along with a Proof value
output from `GenerateProof`. It outputs a single boolean value indicating whether
or not the proof is valid for the given DLEQ inputs.

~~~
VerifyProof

Input:

  Element A
  Element B
  Element C
  Element D
  Proof proof

Output:

  boolean verified

Errors: DeserializeError

def VerifyProof(A, B, C, D, proof):
  Cs = [C]
  Ds = [D]

  (M, Z) = ComputeComposites(B, Cs, Ds)
  c = proof[0]
  s = proof[1]

  t2 = ((s * A) + (c * B))
  t3 = ((s * M) + (c * Z))

  Bm = GG.SerializeElement(B)
  a0 = GG.SerializeElement(M)
  a1 = GG.SerializeElement(Z)
  a2 = GG.SerializeElement(t2)
  a3 = GG.SerializeElement(t3)

  h2Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(a0), 2) || a0 ||
            I2OSP(len(a1), 2) || a1 ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            "Challenge"

  expectedC = GG.HashToScalar(h2Input)

  return expectedC == c
~~~

The definition of `ComputeComposites` is given below.

~~~
ComputeComposites

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
              "Composite"

    di = GG.HashToScalar(h2Input)
    M = di * Cs[i] + M
    Z = di * Ds[i] + Z

 return (M, Z)
~~~

As with the proof generation case, proof verification can be batched. `ComputeComposites`
is defined in terms of a batch of inputs. Implementations can take advantage of this
behavior by also batching inputs to `VerifyProof`, respectively.

# Protocol {#protocol}

In this section, we define three OPRF protocol variants -- a base mode,
verifiable mode, and partially-oblivious mode -- with the following properties.

In the base mode, a client and server interact to compute `output = F(skS, input)`,
where `input` is the client's private input, `skS` is the server's private key,
and `output` is the OPRF output. The client learns `output` and the server learns nothing.
This interaction is shown below.

~~~
    Client                                                  Server(skS)
  ---------------------------------------------------------------------
  blind, blindedElement = Blind(input)

                             blindedElement
                               ---------->

                           evaluatedElement = Evaluate(blindedElement)

                             evaluatedElement
                               <----------

  output = Finalize(input, blind, evaluatedElement, blindedElement)
~~~
{: #fig-oprf title="OPRF protocol overview"}

In the verifiable mode, the client additionally receives proof that the server used `skS` in
computing the function. To achieve verifiability, as in the original work of {{JKK14}}, the
server provides a zero-knowledge proof that the key provided as input by the server in
the `Evaluate` function is the same key as it used to produce the server's public key, `pkS`,
which the client receives as input to the protocol. This proof does not reveal the server's
private key to the client. This interaction is shown below.

~~~
    Client(pkS)            <---- pkS ------                 Server(skS)
  ---------------------------------------------------------------------
  blind, blindedElement = Blind(input)

                             blindedElement
                               ---------->

                     evaluatedElement, proof = Evaluate(blindedElement)

                         evaluatedElement, proof
                               <----------

  output = Finalize(input, blind, evaluatedElement,
                    blindedElement, proof)
~~~
{: #fig-voprf title="VOPRF protocol overview with additional proof"}

The partially-oblivious mode extends the VOPRF mode such that the client and
server can additionally provide a public input `info` that is used in computing
the pseudorandom function. That is, the client and server interact to compute
`output = F(skS, input, info)`. To support additional public input, the client
and server augment the `pkS` and `skS`, respectively, using the `info` value,
as in {{TCRSTW21}}.

~~~
    Client(pkS, info)        <---- pkS ------        Server(skS, info)
  ---------------------------------------------------------------------
  blind, blindedElement = Blind(input)

                             blindedElement
                               ---------->

               evaluatedElement, proof = Evaluate(blindedElement, info)

                         evaluatedElement, proof
                               <----------

  output = Finalize(input, blind, evaluatedElement,
                    blindedElement, proof, info)
~~~
{: #fig-poprf title="POPRF protocol overview with additional public input"}

Each protocol consists of an offline setup phase and an online phase,
described in {{offline}} and {{online}}, respectively. Configuration details
for the offline phase are described in {{configuration}}.

## Configuration

Each of the three protocol variants are identified with a one-byte value:

| Mode           | Value |
|:===============|:======|
| modeOPRF       | 0x00  |
| modeVOPRF      | 0x01  |
| modePOPRF      | 0x02  |

Additionally, each protocol variant is instantiated with a ciphersuite,
or suite. Each ciphersuite is identified with a two-byte value, referred
to as `suiteID`; see {{ciphersuites}} for the registry of initial values.

The mode and ciphersuite ID values are combined to create a "context string"
used throughout the protocol with the following function:

~~~
def CreateContextString(mode, suiteID):
  return "VOPRF08-" || I2OSP(mode, 1) || I2OSP(suiteID, 2)
~~~

[[RFC editor: please change "VOPRF08" to "RFCXXXX", where XXXX is the final number, here and elsewhere before publication.]]

## Key Generation and Context Setup {#offline}

In the offline setup phase, both the client and server create a context used
for executing the online phase of the protocol after agreeing on a mode and
ciphersuite value suiteID. The server key pair (`skS`, `pkS`) is generated
using the following function, which accepts a randomly generated seed of length
`Ns` and optional public info string:

~~~
Input:

  opaque seed[Ns]
  PublicInput info

Output:

  Scalar skS
  Element pkS

Errors: DeriveKeyPairError

def DeriveKeyPair(seed, info):
  contextString = CreateContextString(mode, suiteID)
  deriveInput = seed || I2OSP(len(info), 2) || info
  counter = 0
  skS = 0
  while skS == 0:
    if counter > 255:
      raise DeriveKeyPairError
    skS = GG.HashToScalar(deriveInput || I2OSP(counter, 1),
                          DST = "DeriveKeyPair" || contextString)
    counter = counter + 1
  pkS = ScalarBaseMult(skS)
  return skS, pkS
~~~

The OPRF variant server and client contexts are created as follows:

~~~
def SetupOPRFServer(suiteID, skS):
  contextString = CreateContextString(modeOPRF, suiteID)
  return OPRFServerContext(contextString, skS)

def SetupOPRFClient(suiteID):
  contextString = CreateContextString(modeOPRF, suiteID)
  return OPRFClientContext(contextString)
~~~

The VOPRF variant server and client contexts are created as follows:

~~~
def SetupVOPRFServer(suiteID, skS, pkS):
  contextString = CreateContextString(modeVOPRF, suiteID)
  return VOPRFServerContext(contextString, skS)

def SetupVOPRFClient(suiteID, pkS):
  contextString = CreateContextString(modeVOPRF, suiteID)
  return VOPRFClientContext(contextString, pkS)
~~~

The POPRF variant server and client contexts are created as follows:

~~~
def SetupPOPRFServer(suiteID, skS, pkS):
  contextString = CreateContextString(modePOPRF, suiteID)
  return POPRFServerContext(contextString, skS)

def SetupPOPRFClient(suiteID, pkS):
  contextString = CreateContextString(modePOPRF, suiteID)
  return POPRFClientContext(contextString, pkS)
~~~

## Online Protocol {#online}

In the online phase, the client and server engage in a two message protocol
to compute the protocol output. This section describes the protocol details
for each protocol variant. Throughout each description the following implicit
parameters are assumed to exist:

- GG, a prime-order group implementing the API described in {{pog}}.
- contextString, a domain separation tag constructed during context setup as created in {{offline}}.
- skS and pkS, the private and public keys configured for client and server in {{offline}}.

Applications serialize protocol messages between client and server for transmission.
Specifically, values of type Element are serialized to SerializedElement values,
and values of type Proof are serialized as the concatenation of two SerializedScalar
values. Deserializing these values can fail, in which case the application MUST abort
the protocol with a `DeserializeError` failure.

Applications MUST check that input Element values received over the wire are not
the group identity element. This check is handled when deserializing Element values
using DeserializeElement; see {{input-validation}} for more information on input
validation.

### OPRF Protocol {#oprf}

The OPRF protocol begins with the client blinding its input, as described
by the `Blind` function below.

~~~
Input:

  PrivateInput input

Output:

  Scalar blind
  Element blindedElement

def Blind(input):
  blind = GG.RandomScalar()
  P = GG.HashToGroup(input)
  blindedElement = blind * P

  return blind, blindedElement
~~~

Clients store `blind` locally, and send `blindedElement` to the server for evaluation.
Upon receipt, servers process `blindedElement` using the `Evaluate` function described
below.

~~~
Finalize

Input:

  Element blindedElement

Output:

  Element evaluatedElement

def Evaluate(blindedElement):
  evaluatedElement = skS * blindedElement
  return evaluatedElement
~~~

Servers send the output `evaluatedElement` to clients for processing.
Recall that servers may batch multiple client inputs to `Evaluate`.

Upon receipt of `evaluatedElement`, clients process it to complete the
OPRF evaluation with the `Finalize` function described below.

~~~
Input:

  PrivateInput input
  Scalar blind
  Element evaluatedElement

Output:

  opaque output[Nh]

def Finalize(input, blind, evaluatedElement):
  N = blind^(-1) * evaluatedElement
  unblindedElement = GG.SerializeElement(N)

  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(unblindedElement), 2) || unblindedElement ||
              "Finalize"
  return Hash(hashInput)
~~~

### VOPRF Protocol {#voprf}

The VOPRF protocol begins with the client blinding its input, using the same
`Blind` function as in {{oprf}}. Clients store the output `blind` locally
and send `blindedElement` to the server for evaluation. Upon receipt,
servers process `blindedElement` to compute an evaluated element and DLEQ
proof using the following `Evaluate` function.

~~~
Input:

  Element blindedElement

Output:

  Element evaluatedElement
  Proof proof

def Evaluate(blindedElement):
  evaluatedElement = skS * blindedElement
  proof = GenerateProof(skS, G, pkS, blindedElement, evaluatedElement)
  return evaluatedElement, proof
~~~

The server sends both `evaluatedElement` and `proof` back to the client.
Upon receipt, the client processes both values to complete the VOPRF computation
using the `Finalize` function below.

~~~
Input:

  PrivateInput input
  Scalar blind
  Element evaluatedElement
  Element blindedElement
  Proof proof

Output:

  opaque output[Nh]

Errors: VerifyError

def Finalize(input, blind, evaluatedElement, blindedElement, proof):
  if VerifyProof(G, pkS, blindedElement, evaluatedElement, proof) == false:
    raise VerifyError

  N = blind^(-1) * evaluatedElement
  unblindedElement = GG.SerializeElement(N)

  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(unblindedElement), 2) || unblindedElement ||
              "Finalize"
  return Hash(hashInput)
~~~

### POPRF Protocol {#poprf}

The POPRF protocol begins with the client blinding its input, using the same
`Blind` function as in {{oprf}}. Clients store the output `blind` locally
and send `blindedElement` to the server for evaluation. Upon receipt, servers
process `blindedElement` to compute an evaluated element and DLEQ proof using
the following `Evaluate` function.

~~~
Finalize

Input:

  Element blindedElement
  PublicInput info

Output:

  Element evaluatedElement
  Proof proof

Errors: InverseError

def Evaluate(blindedElement, info):
  context = "Info" || I2OSP(len(info), 2) || info
  m = GG.HashToScalar(context)
  t = skS + m
  if t == 0:
    raise InverseError

  evaluatedElement = t^(-1) * blindedElement

  U = ScalarBaseMult(t)
  proof = GenerateProof(t, G, U, evaluatedElement, blindedElement)

  return evaluatedElement, proof
~~~

The server sends both `evaluatedElement` and `proof` back to the client.
Upon receipt, the client processes both values to complete the VOPRF computation
using the `Finalize` function below.

~~~
Input:

  PrivateInput input
  Scalar blind
  Element evaluatedElement
  Element blindedElement
  Proof proof
  PublicInput info

Output:

  opaque output[Nh]

Errors: InverseError

def Finalize(input, blind, evaluatedElement, blindedElement, proof, info):
  context = "Info" || I2OSP(len(info), 2) || info
  m = GG.HashToScalar(context)
  T = ScalarBaseMult(m)
  U = T + pkS
  if VerifyProof(G, U, evaluatedElement, blindedElement, proof) == false:
    raise VerifyError

  N = blind^(-1) * evaluatedElement
  unblindedElement = GG.SerializeElement(N)

  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(info), 2) || info ||
              I2OSP(len(unblindedElement), 2) || unblindedElement ||
              "Finalize"
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

This section describes considerations for applications, including external interface
recommendations, explicit error treatment, and public input representation for the
POPRF protocol variant.

## External Interface Recommendations

The protocol functions in {{online}} are specified in terms of prime-order group
Elements and Scalars. However, applications can treat these as internal functions,
and instead expose interfaces that operate in terms of wire format messages.

## Error Considerations

Some OPRF variants specified in this document have fallible operations. For example, `Finalize`
and `Evaluate` can fail if any element received from the peer fails deserialization.
The explicit errors generated throughout this specification, along with the
conditions that lead to each error, are as follows:

- `VerifyError`: Verifiable OPRF proof verification failed; {{voprf}} and {{poprf}}.
- `DeserializeError`: Group element or scalar deserialization failure; {{pog}} and {{online}}.
- `InverseError`: A scalar is zero and has no inverse; {{pog}} and {{online}}.

The errors in this document are meant as a guide to implementors. They are not
an exhaustive list of all the errors an implementation might emit. For example,
implementations might run out of memory and return a corresponding error.

## POPRF Public Input

Functionally, the VOPRF and POPRF variants differ in that the POPRF variant
admits public input, whereas the VOPRF variant does not. Public input allows
clients and servers to cryptographically bind additional data to the POPRF output.
A POPRF with fixed public input is functionally equivalent to a VOPRF. However, there
are differences in the underlying security assumptions made about each variant;
see {{cryptanalysis}} for more details.

This public input is known to both parties at the start of the protocol. It is RECOMMENDED
that this public input be constructed with some type of higher-level domain separation
to avoid cross protocol attacks or related issues. For example, protocols using
this construction might ensure that the public input uses a unique, prefix-free encoding.
See {{I-D.irtf-cfrg-hash-to-curve, Section 10.4}} for further discussion on
constructing domain separation values.

Implementations may choose to not let applications control `info` in cases where
this value is fixed or otherwise not useful to the application. In this case,
the resulting protocol is functionally equivalent to an OPRF without public
input. See {{equiv-2hashdh}} for discussion about repurposing existing non-verifiable
OPRF implementations, i.e., those without the `info` parameter, using the construction
in this specification.

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

Additionally, for the VOPRF and POPRF protocol variants, there is an additional
security property:

- Verifiable: The client must only complete execution of the protocol if
  it can successfully assert that the POPRF output it computes is
  correct. This is taken with respect to the POPRF key held by the
  server.

Any VOPRF or POPRF that satisfies the 'verifiable' security property is known
as 'verifiable'. In practice, the notion of verifiability requires that
the server commits to the key before the actual protocol execution takes
place. Then the client verifies that the server has used the key in the
protocol using this commitment. In the following, we may also refer to this
commitment as a public key.

## Cryptographic Security {#cryptanalysis}

Below, we discuss the cryptographic security of each protocol variant
from {{protocol}}, relative to the necessary cryptographic assumptions
that need to be made.

### OPRF and VOPRF Assumptions

The OPRF and VOPRF protocol variants in this document are based on {{JKK14}}.
In fact, the VOPRF construction is identical to the {{JKK14}} construction, except
that this document supports batching so that multiple evaluations can happen
at once whilst only constructing one proof object. This is enabled using
an established batching technique.

Consequently, the cryptographic security of the OPRF and VOPRF variants is based on
the assumption that the One-More Gap DH is computationally difficult to solve.

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

The original paper {{JKK14}} gives a security proof that the 2HashDH-NIZK
construction satisfies the security guarantees of a VOPRF protocol {{properties}}
under the OMDH assumption in the universal composability (UC) security model.

#### Q-Strong-DH Oracle {#qsdh}

A side-effect of the OPRF and VOPRF protocols is that it allows instantiation of
a oracle for constructing Q-strong-DH (Q-sDH) samples. The Q-Strong-DH
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
log\_2(Q)/2 bits. Note that the attacks only work in situations where Q
divides p-1 or p+1, where p is the order of the prime-order group used
to instantiate the OPRF.

As an example, suppose that a group instantiation is used that provides
128 bits of security against discrete log cryptanalysis. Then an
adversary with access to a Q-sDH oracle and makes Q=2^20 queries can
reduce the security of the instantiation by log\_2(2^20)/2 = 10 bits.
Launching this attack would require 2^(p/2-log\_2(Q)/2) bits of memory.

Notice that it is easy to instantiate a Q-sDH oracle using the OPRF
functionality that we provide. A client can just submit sequential
queries of the form (G, k * G, (k^2)G, ..., (k^(Q-1))G), where each
query is the output of the previous interaction. This means that any
client that submits Q queries to the OPRF can use the aforementioned
attacks to reduce the security of the group instantiation by
(log\_2(Q)/2) bits.

Recall that from a malicious client's perspective, the adversary wins if
they can distinguish the OPRF interaction from a protocol that computes
the ideal functionality provided by the PRF.

### POPRF Assumptions

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

#### Static q-DL Assumption

As with the OPRF and VOPRF variants, a side-effect of the POPRF design is
that it allows instantiation of an oracle for retrieving "strong-DH"
evaluations, in which an adversary can query a group element
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

### 2HashDH OPRF Equivalence {#equiv-2hashdh}

The non-verifiable 3HashSDHI POPRF construction in this specification is equivalent
to the non-verifiable 2HashDH OPRF from {{JKK14}} when the input `info` is fixed.
In particular, the 3HashSDHI POPRF computes the following given private key `k`,
private input `x`, and public input `t`, where H1, H2, and H3 are GG.HashToGroup,
GG.HashToScalar, and Hash, respectively:

~~~
H3(x, H1(x)^(1 / (k + H2(t))))
~~~

Similarly, the 2HashDH OPRF computes the following given private key `k'` and
private input `x`:

~~~
H3(x, H1(x)^k')
~~~

Given a fixed public input `t`, one can transform a 3HashSDHI private key `k`
into an equivalent 2HashDH private key `k'` as follows:

~~~
k' = 1 / (k + H2(t))
~~~

This transformation is undefined for values of `k` and `t` such that
`k + H2(t) = 0`. Because only a single choice of `k` leads to this
undefined case, the distribution of `k'` defined via this transformation
is statistically close to the distribution of a randomly sampled `k'`
as output from `GG.GenerateKeyPair`.

Note that one can also transform any non-zero 2HashDH private key `k'` into
an equivalent 3HashSDHI private key `k` as follows:

~~~
k = (1 - (k' * H2(t))) / k'
~~~

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

This section includes test vectors for the protocol variants specified
in this document. For each ciphersuite specified in {{ciphersuites}},
there is a set of test vectors for the protocol when run the OPRF,
VOPRF, and POPRF modes. Each test vector lists the batch size for
the evaluation. Each test vector value is encoded as a hexadecimal
byte string. The label for each test vector value is described below.

- "Input": The private client input, an opaque byte string.
- "Info": The public info, an opaque byte string. Only present for POPRF vectors.
- "Blind": The blind value output by `Blind()`, a serialized `Scalar`
  of `Ns` bytes long.
- "BlindedElement": The blinded value output by `Blind()`, a serialized
  `Element` of `Ne` bytes long.
- "EvaluatedElement": The evaluated element output by `Evaluate()`,
  a serialized `Element` of `Ne` bytes long.
- "Proof": The serialized `Proof` output from `GenerateProof()` (only
  listed for verifiable mode test vectors), composed of two serialized
  `Scalar` values each of `Ns` bytes long. Only present for VOPRF and POPRF vectors.
- "ProofRandomScalar": The random scalar `r` computed in `GenerateProof()`
  (only listed for verifiable mode test vectors), a serialized `Scalar` of
  `Ns` bytes long. Only present for VOPRF and POPRF vectors.
- "Output": The OPRF output, a byte string of length `Nh` bytes.

Test vectors with batch size B > 1 have inputs separated by a comma
",". Applicable test vectors will have B different values for the
"Input", "Blind", "BlindedElement", "EvaluationElement", and
"Output" fields.

The server key material, `pkSm` and `skSm`, are listed under the mode for
each ciphersuite. Both `pkSm` and `skSm` are the serialized values of
`pkS` and `skS`, respectively, as used in the protocol. Each key pair
is derived from a seed `Seed` and info string `KeyInfo`, which are
listed as well, using the `DeriveKeyPair` function from {{offline}}.

## OPRF(ristretto255, SHA-512)

### OPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 441783d4ca98aea280fd7e11b00360798b1e46fcff376ac65bfd1aa653d98
50c
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf
8e03
BlindedElement = 744441a5d3ee12571a84d34812443eba2b6521a47265ad655f0
1e759b3dd7d35
EvaluationElement = ae6c06f834726d64a59504ecd7a89c5e6e7f491efd788826
947f29e97a206719
Output = 3d69a60299d078b851e6d1fbfb88c894ab52679e29c0ec3f2762be260a8
5c780dd7bc53c6ab028f608ddf9ffb8bb87dc07aac82e3ec6a2af204ac397da3ebbb
5
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037
e50b
BlindedElement = f4eeea4e1bcb2ec818ee2d5c1fcec56c24064a9ff4bea5b3dd6
877800fc28e4d
EvaluationElement = 4cd3fb07278079d52fa9d58fa6bd9200ec10af0b6fe5d69e
50f798aaad679661
Output = 19d361b4b1aedb1b074d7204af15dfc07357ced4ea3496ea95cf8eab5af
81b1f7c63f442fcdc6c68c8e0c9b13e8102ae62c9976aedc5c5e46c4068d096c5dd7
2
~~~

### VOPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = a92262cee280c3c4c0d4574ea5a55f569da769cbcebef4e1e5b950d44e5db
e05
pkSm = acedcbd16fe82145d7e43461dd4d7d2be71bc0afbe1a07210e494cb8c2dfd
018
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e326
3503
BlindedElement = 56c6926e940df23d5dfe6a48949c5a9e5b503df3bff36454ba4
821afa1528718
EvaluationElement = 3c6861027d4f82ea81e0f2379782a3c7249c635127376791
45b3035a1e61241c
Proof = 2cf535c4fe8d02e82adc02227e639dbefcc818848696023d0bcc3069e719
430faf14e71d90588b75aef04a0f657bdf5ddb32ccbcc0d884290b34410b37405807
ProofRandomScalar = 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9d
bcec831b8c681a09
Output = 670b3a4d70d57bcf2f2a673441fc2d8febecb9686f46200d9bf9d22fe39
944c3c1fb11d7ef28eb170caec89837d5f0dc8ea520d8ca5fdf63ff11982a6f05a3e
2
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd4171
ea02
BlindedElement = 5cd133d03df2e1ff919ed85501319c2039853dd7dc59da73605
fd5791b835d23
EvaluationElement = bc92b1ffdf4ac12dbe462a5458ebd6881d47e87f3f3bc718
a090a45258adc64e
Proof = eb1954f8e4dcc4d92137aa966165b5b5d09e7c2c7123b4aece64f36477bf
7b07c85f67f97f696fdf4b235d28ab49e2d8b38dc8e519b0bc9c7ab3894a01a29607
ProofRandomScalar = 74ae06fd50d5f26c2519bd7b184f45dd3ef2cb50197d42df
9d013f7d6c312a0b
Output = 011db44783fd67eacca4eae8cadb57c5f8b03e37f04a6e02b4f6e84e7da
bd019636a10d207f9bcbb983282c6abce7c3ecffc258b44d75a4400feadace0f2552
c
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 80513e77795feeec6d2c450589b0e1b178febd5c193a9fcba0d27f0a06e0
d50f,533c2e6d91c934f919ac218973be55ba0d7b234160a0d4cf3bddafbda99e2e0
c
BlindedElement = 1c7ee9c1b4145dabeba9ad159531432a20718cb44a86f79dc73
f6f8671c9bf5e,7c1ef37881602cb6d3cf995e6ee310ed51e39b80ce0a825a316bc6
21d0580a14
EvaluationElement = 8ce9594ac32b83eaaca100d1c3e8a9c78c637b1b90cf691e
e9a0ee7e3fe2773a,ee79cfd63e53179e862191b8b1d39d2b51c9223595a31eaa763
f4e0485ae1837
Proof = 445631f458980856ef46bc97cd039e10991332a570424ba206a578c56cf4
690d81ac6d83650c5e541015e45f6f34bc01cbfed6c7fd8cce08e476f7d44d12d905
ProofRandomScalar = 3af5aec325791592eee4a8860522f8444c8e71ac33af5186
a9706137886dce08
Output = 670b3a4d70d57bcf2f2a673441fc2d8febecb9686f46200d9bf9d22fe39
944c3c1fb11d7ef28eb170caec89837d5f0dc8ea520d8ca5fdf63ff11982a6f05a3e
2,011db44783fd67eacca4eae8cadb57c5f8b03e37f04a6e02b4f6e84e7dabd01963
6a10d207f9bcbb983282c6abce7c3ecffc258b44d75a4400feadace0f2552c
~~~

### POPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = fb981fd5c4841802579343e171171751eb52fb76fc6ea38780d29a04f982e
a08
pkSm = 64a7a885d0a93e8ce5991f0d9a73675fbbe2d8d1f92451f797d322282ebaa
a02
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 7e5bcbf82a46109ee0d24e9bcab41fc830a6ce8b82fc1e9213a043b743b9
5800
BlindedElement = a045ba27352937407c6c3f09ae1ad7b8ccd4ee120df5e92dcd2
2014756e17806
EvaluationElement = 46d2dfb6131c06a43fad966d821b80bed9bd985f7a1f58c2
2406444569acd145
Proof = 673f0f4bd71a78e9e7f0c7b8229afccdfdc750800d23f8902a32fa4710c7
64027fddc46b32f3c843993618d6613fc0553d687d82b43955a5e0da0eba8002b60d
ProofRandomScalar = 080d0a4d352de92672ab709b1ae1888cb48dfabc2d6ca5b9
14b335512fe70508
Output = e19256be6da2776df64c5cd77091f7818191d493070d2bed6fb76a5534a
283eb9c923f5010ffbb23b312df96583e139881b871b0345e1191afe656b949a9f58
0
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = de2e98f422bf7b99be19f7da7cac62f1599d35a225ec6340149a0aaff310
2003
BlindedElement = aad45f3d7d66884129d3048614dcd3e35bb0fbac66f073b916b
8ab66c7252249
EvaluationElement = ee51983f99ba21ae3bc684d4c79d3a9a4f5650f9ef0be0da
c3f0748a38e4b43b
Proof = 4169b6cedfe0cecaee4265f76a9980eb464cbb82ce05f9ef98ee0194dd20
2005a67afe842a3149ebfc6310e5ecdda04b567b4728df0d1cab732a3602de95c600
ProofRandomScalar = c4d002aa4cfcf281657cf36fe562bc60d9133e0e72a74432
f685b2b6a4b42a0c
Output = dfa24b4518300b95692b7bce531fc3f12ea770b93f511181ce1917ec921
93fe7d780c0d08c91e2a66412f06bf07ee5168f38e5f53034ae9ed8d94de9b30dc6c
3
~~~

## OPRF(decaf448, SHAKE-256)

### OPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
KeyInfo = 74657374206b6579
skSm = 35847d22e42237db5c6f91409a589e9499452ea3555bd1654ea4a3ae571a8
130eca151ed991ae3adbb123cd79c0d83b7d854423ba149a826
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = d3a425c41eac0e313a47e99d05df72c6e1d58e654a5ee9354b115060bca8
7db7d73e00cbb8559f84cb7a221b235b0950a0ab553f40bcc304
BlindedElement = ae09cc0ef98064e4d0b3a295026d62ce80b4be8e44aae716fe3
5c1536fecd0aff874fe7553bbd3c609558a8c5474a8762ebf8056839dcc0f
EvaluationElement = 5a6e77c9a5bcab0f3b39e3c947f75966e6582b8127c9c2ad
74994b7932787f34eb08fb536599ff0f3bebefc9de7bd4e23f0bc18934d03655
Output = 8ddb739bbbd1a2b3ec5d08f0118939821ed9021f221ea717e070be5b540
73a2e7702638c0c60896aa3549c56f5c8b8c4165689e3410fb4b3007ff8ec05174ff
f
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 87abe954011b7da62bb6599418ef90b5d4ea98cca1bcd65fa514f1894bcf
6a1c7cef33909b794fe6e69a642b20f4c9118febffaf9a5acc11
BlindedElement = 863a8628a9837efbc0d1caeb69fd5b31c6fd3359d8e74fc07c3
911dbaa6103dfb7b7b6c0b86f50db7b151fc61d1079c271abd402a2932d20
EvaluationElement = 2865f05ecafaefefa1589f0436c8aca9287d6884c60c5217
3a1727745a4f917c5959d34700a1f7e6178d0804b5d43800419ddff86bcad9c2
Output = 19779e932b51e22294a6def08091b36b56bdf05b69765f1b6a089de28b9
eb53dd419f5c119888fd536ba771f951df4adb056613b86622a2604625923574e7a1
2
~~~

### VOPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
KeyInfo = 74657374206b6579
skSm = ab46beee40f423cb5265f7d04ce0ecb1bb5f30639792a5cc1ae8d860d69de
411504ae89566aba36c5cc6bde543e7d95777a301b3fb4d3825
pkSm = ac9efbf6c07845041e335d42698d1d1c5634a4d0f019bd58021a5d0573c41
742530b9d2294c183be38e81a4d2f7234dea7f27f202caf9d2a
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 20e7794aa77ced123f07e56cc27de60b0ab106c0e1aac79e92dd2d051e90
efe4e2e093bc1e82b80e8cce6afa798ac214abffabac4a096005
BlindedElement = 5cc67ce84bd60ef4760cbd864aefd7d30767a7d6ba6c7af63bc
11347ccab9b59f9bf09cb76e627f061f46501a1f05a8d7cf11a24dc0d9c1b
EvaluationElement = 7853b5f52655574ce2747681d9a51b1e76f3005d26bcb945
4497993d95350792b9e71bc10b80f917a7d7f1ce8a64b9892159a52ae08a64c6
Proof = a11645866c5ce4c037c74ddec6ef7c3b182b3466496aedca6a77b1c3eb98
3cdac6bdad15b9f0b227a16c3a3d67284470a6bff94b14ee0c362b7fe2fabd030f1f
9f121309331e6c26981303109756334ab2d381f4d359fb7bd27807fd40982f80bf0c
6e73f6a45a31c171e55a26e38d04
ProofRandomScalar = da3e9faf0f2009d16c797646097d761e2b84e0df5d76ece5
658b3aab5207735beb86c5379228da260159dc24f7c5c2483a81aff8f6ff991b
Output = 44681eff0ceee52226b59da3ca75763f4aea949e04c4e9a4f6594847ea5
a7809be7873cd39bce9477f7a7b5d8b4951ce7b880a430f37dda756b9be525a3d1c5
e
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = befcb571168f337dd52851d4bc07947c858dc735e9e22aaf0576f161ab55
5182908dbd7947b1c988956fa73b17b373b72fd4e3c08992892a
BlindedElement = 8cbf06254ec3393734d50a9cbf7b6b27bc18706a49f4c559ee7
aa4642b1295d5de7e9f1150d51611660344d8a194c584fbbc1e1908428a72
EvaluationElement = cae3d1979df3d044e0e7292f6275001e5abc2faa5bb978d5
e74c48f5e3177d738bc98014f3025cbda4d6ecfd9c438742ee920f1df7932fce
Proof = 5163e30eb1ae78c62019f8800751822d1af45e259fc093912984d07eb325
eba09c7465dbc69f95eb581fdccd9964f3932e3f531db62aca0c309890debaf576b7
0d1f266c6432b53ae6099c75d51f36aed0ebf96e101f39b9134a256b5cff438a2bd5
270eb26da0c65d130e6e24cb1208
ProofRandomScalar = 4dab20fd864de6ceab345e8d755997956ddd1f267a2d8617
5aeae5e1168932285a6f602b4b20a570a697452b3ddbb7d0e29363ad3a6fed19
Output = 874040eb6a6da67891c7d84e9667e8b6bd705e6b4cdab9df172cbf50270
d45acdd7b12b7c7daf53c58cf132d2205be9792354d004b902b044056cc7581bc89f
5
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 01229ee057507c3e53534ad9db9f6df6ce515d1b8017923b65cada199e93
6a623c8eb3bd08e9b3f6584a85e4ff26e9f869d30b6c1f5bf11b,da4e3069d3ed33e
f13a08c384d74f6dcaed32bb9448c02865efb17a32b82c7f06a9586c63b775932689
cb8215043bf2952776afbc6d9ab26
BlindedElement = 90bc0fdfeeeb43811c39afe42a4e97448e5e8494c2bf9522154
10d4147667f9bdc7c9e7db02a94a844ada03f834660e83ff4e052e23d0b7d,e633bf
3e0df4150bb0feaa524ab008f26b65006e9d04b299949dd44ea814c9d4b837473e3a
dff919202645557118463b0ca5798b1a12f3e0
EvaluationElement = 808bf9cce6de67d93f89d9ae28351b29227936796d6cfb9e
64380e7341868160042d086b9a137940be6599b842a22f40b126df3c645a8662,e60
76c036d0f60b972f0b03a245f2a7043129a2e92874905290126f1523454cc29517ab
85892798b2a1a3dc1a02d83c547c7845df800efcb
Proof = 9ca049a4c1222aca0e53aa03d22ec53711c053285ddfb128060143e03c2d
b7325af8abc8c34f85d4820b3d96cf0fec74b38840ccfe1b58038e8db0b0292a2670
1465a57629461920db1c0e32c92e5027333bdfa9d1eef10978f0bb32dd574e3025d8
97539bad83a77e4f09bbe0940d22
ProofRandomScalar = 4e278b9fbe31963bbdda1edc786e5fd0033feac1992c53a6
07d516a46251614940e76a2763b80683e5b789398710bdbc774d9221f74c7102
Output = 44681eff0ceee52226b59da3ca75763f4aea949e04c4e9a4f6594847ea5
a7809be7873cd39bce9477f7a7b5d8b4951ce7b880a430f37dda756b9be525a3d1c5
e,874040eb6a6da67891c7d84e9667e8b6bd705e6b4cdab9df172cbf50270d45acdd
7b12b7c7daf53c58cf132d2205be9792354d004b902b044056cc7581bc89f5
~~~

### POPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
KeyInfo = 74657374206b6579
skSm = aad6576c08b24a3e0ef3119b74f1f52d267fb10dea6cb4188515d9592f520
e3362a438462355e4e1f4bb209a60bcf21aa84a4f9ce9aade3c
pkSm = 88559f466b7681c92cb82f66b55ab9949f9f3f6c874658bb13a56d4f51797
83a7dc7c345cbbeec7efee27e1884a30dec8eb69d0efee6dea7
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = c3b11cb03005ced988ae863bc6f3e8b59bbd1354548220e81cd0ffb6f9e4
ec2173870ae684f86b1c06e41ecdb9ef83429e58098b238c292d
BlindedElement = ce23c7d365058dc76f97adf83eb0c7baa4f27aea3ba1b015d0d
a3043afab3d84694f1d0f5dbb77cfb96873aade920218f5ec80e481584747
EvaluationElement = 3e29ec3132fd3dfc1c9b80f9a09905fe021d9ed863bcc908
99085b9c1bc921c28852ba1a5df525c2e73c9a13021b749d7fc9d91d13606dfe
Proof = c1bca24e6b55ac65625a1dde2b487a2daa8de9c5d05f4b76a2d43d38a0a7
6365cf2727cc5b43985831ec00d25f16f7e2f34fe5d293ba800e305ec0ed0173a1d2
cd0deb987a8124858bf74ad20840a386e546ffa2b5c811a6e73af21a0d12c859629c
f117576ba5409b02a0804c61a10f
ProofRandomScalar = 9e414ad5e6073d177a1f0b697d9efa2b60c984df38632f10
96f2bf292478118d78e9edabbe9ad22900ad84b1a2cdcb869c70c832589a471a
Output = 45cf96137417e556d3fe134d09a7e9d4f2a50bea341d15af45c2465efc2
1b37d03f405ee079170cffa37e4b1bc1678462e6d3452124d8cac35b5c159e09dd0f
6
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 87c1563075086f0749e88205237f77416210747f2369383efbec7bf6c78a
77d5062b938e91fbc6ce569a4461a97bda32d0af163d4307bb22
BlindedElement = 14e74297bbe248bb6a56e72310c55cc3de98622adc7aede7fa9
89163456486e06909f990d046120571f7e787c5cd177480b769f51d240618
EvaluationElement = aa45614199f7497e474db453a8ad66bdb7211ed03a4459db
2d4f56be5b289f4b81365f71ae63308ecad15b65b54b3c083d82a47708512675
Proof = 24d2185c04455d63a299700a5b68c67f73d8078c1bf1250278dd06839e84
c65c55c7a9dc53aaa3620f9381d728210be00daa259ea4567e0e877b4f1435e1cd18
933a371a2ceb0836a3c8b6449d831150c7775ae2f16984362e7da2bc3c54b14d9917
c7e0c34878deefff9458a4ff2d18
ProofRandomScalar = 68481b589434b3b5b6c131de9e080e58e63ca9ce7d0c1bf8
1599e1a6292f2574e3a23e21d5bf79ecc75a16f7a77618bb9a9224c39cf90a18
Output = 3d010b50f9ac87338e537fff646a986dff3dcd09ac40d5ee33488db0515
46ad8866be51b462cae03d9a3d53737eaa14c1bd87edd0398dbba36880df1ea86c9f
5
~~~

## OPRF(P-256, SHA-256)

### OPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 8a11d20c241137a8db01b37b06ba030cad9a9b736dfa5bfce31fed1a73f3a
070
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 41fabd4722d92472d858051ce9ad1a533176a862c697b2c392aff2aeb77e
b20d
BlindedElement = 0214499fd6847222cfb6cb68db02121851b9ed884737541fddf
655798a2b22c9a2
EvaluationElement = 03713a81b65a93a7dad796898fafc589f19b0756338185bb
48da820f7896694c80
Output = a4c75555297f4882a74ac3077f09cc23f7123910b21199714505dd9dcb7
b9f77
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 7b7f977a1fb71593281099ef2625644aee0b6c5f5e6e01a2b052b3bd4caf
539b
BlindedElement = 034c9497343f27a300bde18834dd02dc656af533111811a565c
ba0ff554d384dd0
EvaluationElement = 02b8560add0d1bc85f82a4c620abd8b6f9919cfd06111ab4
ec635fa15b6b838f84
Output = 4ab18257b0bb6b79518ec4f144b6b4936252bbc7ab8710f707128594d3a
61ff2
~~~

### VOPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 85129a83886a1e20196c263ecb83720d1ae417471516bd9e28d71ef2c34ba
f76
pkSm = 02794f9e628a2de1797f0f216c064d3117a6dc6ab5f8efee677b83a07a558
d2dc0
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 2c2059c25684e6ccea420f8d0c793f9f51171628f1d28bb7402ca4aea646
5e27
BlindedElement = 035f218c9109e2f9fda41525d02bf0637b76e821a11155b8cef
51c2f4143261124
EvaluationElement = 03f96c083a043bc01705022a8b0c55350b320e7d0abe8440
63e6c6ed1ea5126402
Proof = 33de7c711850cf2b8734fd73130369d8dc613ee01ba59160276270cf616d
ff4b038ad005defa83f31275eceddef82e2a49b91fc93b9957bea5b2ff75913655ef
ProofRandomScalar = 1b538ff23749be19e92df82df1acd3f606cc9faa9dc7ab25
1997738a3a232f36
Output = 6a988e786a0564143d17a156c0cf97c8ccdd3dfb4f6af5774c780c11af7
fa8c1
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 8b45f65717a40c38f671d326e196e8a21bf6cfd40327a95f1ccfc82a9f83
a75e
BlindedElement = 03552596458a0cd6656909d2b475306e1bc8a08363984d6bda1
546784501b5b068
EvaluationElement = 036e4463add6634ef13ee1c935bf9c0d05b3e1c0601c03e5
c02385963175e388ea
Proof = ee3391d71b13be0ca0c4e5c098c46ac672f80fb486729d2162fda8779636
a805b969e145732eca75bc7112b3f0e9bdea718e914d5d06ac010b85510028e40bdf
ProofRandomScalar = 3d35895f4cff282d86b2358d89a82ee6523eff8db014d9b8
b53ad7b0e149b094
Output = 8b5ce3289e53b8df93aa8f684ce136ea10a10a091f76933b337d21ccd00
347d0
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 83705fcc9a39607288b935b0797ac6b3c4b2e848823ac9ae16b3a3b5816b
e035,644c8539857abe3a2022e9c9fd6a1695bbabe8add48bcd149ff3b840dc8a5d2
5
BlindedElement = 03cdccc126afb60535c4e75157cd8ec1431e169af693fdcff4d
5d77b64c5b586f7,0367169f69b1eff90261e7444049c6f2d08d6a218b21bbdbb7fc
8750a5a5ffd232
EvaluationElement = 0286bd74c7a0c8d71a0cbf87ec014789049e9770d2179cee
7f2649e06336244f8b,03881a221164f5497f88c15186fd1d28c8541a90210479624
bbf18c4c8ab7463eb
Proof = e84658eb2f2302205358f07e7ca0e39461af8bf4284df823e37982f506ca
e0334f117b6d88b4a4f3729017edcb9ce20ea1bab456c7443edc9c9b0dcd63eae8da
ProofRandomScalar = 316bc8567c89bd70267d35c8ddcb2be2cdc867089a2eb5cf
471b1e6eb4b043ba
Output = 6a988e786a0564143d17a156c0cf97c8ccdd3dfb4f6af5774c780c11af7
fa8c1,8b5ce3289e53b8df93aa8f684ce136ea10a10a091f76933b337d21ccd00347
d0
~~~

### POPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 363a20d5200b71ee7ebcdd33dca6348e55884b2f3a7c7ad86e6369de557cc
6ce
pkSm = 02b5b2def73b7e195ee2eab4a9795b422101c13898b74a0a5d560ec6b07dc
2af92
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 0470f06169bee12cf47965b72a59946ca387966f5d8331eab82117c88bbd
91b9
BlindedElement = 02a9e77b7aa32172fd173e59a8a8a9c1e3c4f4b5528bc0592dc
21ab64772a3320d
EvaluationElement = 039154e62d801c03d386ab18e8233bf21555a5c429b8e6e8
ec2c5baf23ae8e4731
Proof = 69fb9d3b2a370a54a991cf5529cc06a0d0b3beca5253e49795268f5a37b2
32e6da1385779d340878c15a12f776b50b55d4c5015ed9f9ac61f5520a562161da57
ProofRandomScalar = 466f3c0a05741260040bc9f302a4fea13f1d8f2f6b92a02a
32d5eb06f81de797
Output = 11db73465013382ffbca778b84e7869413b4a8f009efaf0de2363c93e13
bcc8f
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 15c1b9ee1e66339439e3925cf8ce21ce8659f22523b6ce778bbd8f8b541b
e4be
BlindedElement = 02f6e5ffbaf4b8d98cd9b8a6a5243a3cd509afcf537712f21c6
28aa10ef52c4fb0
EvaluationElement = 031e7ee22b136336473476004b8dc1d5e455cc23c23f2e1e
41d3659a1fda6a1996
Proof = 47f688b27e47147e977f8ee93fa8a85cc326d174cd8781bf17941f3d031c
4b2d6f086dc6fe1ee658a461acaa42c3dc73e46406c2ce69347b32df8097cfdc9f6e
ProofRandomScalar = a1545e9aafbba6a90dc0d4094ba4283237211e139f306fc9
04c2d4fe4cc69c0b
Output = 964c2b3148f41e79c0d313d3b3bf6bbd25f8fc501ebb2c9dd5c22c73626
27a84
~~~

## OPRF(P-384, SHA-384)

### OPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
KeyInfo = 74657374206b6579
skSm = 778c06faef667408ad8f9b2ff96b38c33496f828a84b9fdd342225544020c
1c4f41493211478a8a0459f0bc8c4524949
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 4dd65065273c5bd886c7f87ff8c5f39f90320718eff747e2482562df55c9
9bf9591cb0eab2a72d044c05ca2cc2ef9b61
BlindedElement = 02c4eb0f78b26dd471bfa6d8babb0936425667ee6bee5515513
25431a564b7a5bfdef110317b6b21453955c63681bb2a11
EvaluationElement = 02469dab274fb4442c2244bf409f67420a7ba13b6def1b62
eb35607b33e13554630de4b29322a3de3b9631fca2a1bc2ac7
Output = 830e6139dae0fbe6419c2b110ed0e455440637fcb235fa06a9fe99e06dc
987e60377c2a3d33784cc1752ddfb5f3618ba
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 55f951785ae22374dfc19eb96faba6382ec845097904db87240b9dd47b1e
487ec625f11a7ba2cc3de74c5078a81806f8
BlindedElement = 0334bfc4cf126b2caad4964447039346a3f2170608f6aff312e
deed6d186d6cd16e80a381cd3575b9561ae68c228fee4b8
EvaluationElement = 0219848938061b5bd448422c3019867757bce91ea207fe74
f981fbb9762e2d76b1d758e0cd435d0da7152ed3721cb1ec54
Output = 2da941c96540044448386e1ec3933be32372cefa5423ab599f0dddec0d3
e7f4103eb13ed542e6297d08510774e94b5ae
~~~

### VOPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
KeyInfo = 74657374206b6579
skSm = 5cc01a4e52967d51840497044d9c760ccd5cc27c6ee9d572b19ea101abc80
a8e33ec4768902485c4f1ca61354efd1894
pkSm = 0247d0c6c682c060b9d2baec22d13d8399efd34828180805cf4b26508b1cd
a321acf8ea85bdbb3ff33117b59183de84e16
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 84580de0f95f8e06aa6f6663d48b1a4b998a539380ed73cafefa2709f67b
d38be70f0ffdc309b401029d3c6016057a8f
BlindedElement = 0394e2556115a7e830f55d56d141ccf3d85ae18169d8ee80c28
978ae1abc49fb4bf28e82f68413359312d38d2cedc55bf7
EvaluationElement = 033b97c9e7f2f069b5cae91c7bc606e80c99d512fb19e3e2
0556e76459575d12a6c941c73b651e1b208ca7448b74537dc9
Proof = 7d3e17d3995c851deb27df95f2dc5757048bb6a6ee4b677d4f7d6a3b2ce4
b94406121c9a0d2054e97efaee816437c5df05b8fcbff8870ea78b03411528524c25
b3c2dd1d70e525131361f46699a8826485e603e56256cb751c67899dadcffcc7
ProofRandomScalar = e17e559ca3ccd1944f9a70536c175f11a827452672b60d4e
9f89eba281046e2839dd2c7a98309b06dfe89ac0cdd6b747
Output = a0cb8ed13d1c57281eb3207a28dee37f2ac1388f7892203a544b7c3f381
a5f99eeb1b4d9c1eb3e0cd4512dfa8f942028
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 7759061965a423d9d3d6e1e1006dc8984ad28a4c93ecfc36fc2171046b3c
4284855cfa2434ed98db9e68a597db2c1473
BlindedElement = 022a802b27e6f6468b5f8ff12a9e10e971b55f5f80c2967cebe
6cf3a22c6c5350cc3b8a6fd7262d4f601946e18c827dae4
EvaluationElement = 02b8282fb5e29879639b3691daa44982b0604751abf8e41f
e327d581f205a2e42e99e4e30ccefb7aeffaf305eacab43858
Proof = 1cbab366ebd6caf02412cac0f5eb15c1a62b32986cdb9bd431a62c51671d
7aa9fba51394a7a9197aa872c43bbcc2379260394cdcfcfc026d9c49828d7e2f2fbf
9d21bc20ebc3ad86ed897f70d2b21c16574f6713bd6f01266a707b5401235608
ProofRandomScalar = f96713dfe16f40f2c662a56ed2db95e1e7bf2dea02bd1fa7
6e953a630772f68b53baade9962d164565d8c0e3a1ba1a34
Output = 4f4d96d9e4836930faf9bbf4794eb396cf389167158526e4bd9cbeedd5a
744f12372450b001ba9d68c492ef52af30c44
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 563b3420d7764097502850c445ccd86e2d20d7e4ec77617a423883574303
7876080d2e3e27bc3ce7b5fb6a1107ffedeb,4ecbc087302667fabefa647b1766acc
b7c82a46aa3fc6caecbb9e935f0bfb00ea27eb2359bb3b4ef3d5c65b55a1b8961
BlindedElement = 02fc9fc91ac7fee2f806445b45013a4a0464749d81750be4aea
300e4903d0e838e1c3c2e9182e8174b200df65392ddc47a,02ea354e2b7b46186577
390d16bb2af526e3b77340fb830f37356c4a0aa234400bc629ebcf030744e02ab611
4ca15b9150
EvaluationElement = 0215012f11792350a0d5fb9998d15efe423c09059676e294
2fecfdd13cc2b6d7590b9c93b5ab3d2dcab7649ba210c456f8,0326b65234dcb2e37
c4489cc67502ccfb8ac17d0cf68eb2e73edf8f72d30cc798ea88e0a05d8451264c64
54a80e3aabf13
Proof = c9caec24e1d0bc7b038dfb41016465c869cc115889c1f9e6f7631fe0695b
c3cee8187ad2275b615280499545c326d3c77e8eb9ecd8dc0f45793261db7af72ce1
512640ed156d429e66b8dc7e4c59e27db6b036ff714faa177a7a17c03f952c88
ProofRandomScalar = f77ff0b2ebcfe21e1a1ca4a84361e9f1b18e24c9a40ed5ee
c262bf51dc970d63acb5ab74318e54223c759e9747f59c0e
Output = a0cb8ed13d1c57281eb3207a28dee37f2ac1388f7892203a544b7c3f381
a5f99eeb1b4d9c1eb3e0cd4512dfa8f942028,4f4d96d9e4836930faf9bbf4794eb3
96cf389167158526e4bd9cbeedd5a744f12372450b001ba9d68c492ef52af30c44
~~~

### POPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
KeyInfo = 74657374206b6579
skSm = 2da600fa07df70d82081a073d5a60acaf6ebbc750dfa55d9fde6f5be38224
ce409cc489fec28358411b6cb688a20dc6d
pkSm = 031a1ffa698d45d4869227b49449b64a0b71345ecc62884c56df81f73679e
a94ece8fd85f353c01194d29dece331a01e5a
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = c405a354e666f086fa0ea4754fb56527be010296ea880e1c6a4dbbc9ede5
43a2ad0f83fd60fdacb59801a9d83b5d1c10
BlindedElement = 02fc60f6dbc6f262fc96f4b3cfd464f967eeb143f42630aeffd
8a89a51af29a4ee913899f1c43b8eada345126fa7291fbb
EvaluationElement = 03bcae42d341df5c5ac4da039ae732d5cd107f82896515f7
249c783a15cb2921b2c1ba1e9fdc3543b7a21554f78b6f5db3
Proof = 0d3e54064da48d9e2d7ea7bf10530afbd3af505dc6ddb9613aecc9ea5650
6b4867657daa8b5b341c379b291c287c3082cf2c5bbeac1848ae6cac88a09f71978f
edb316805a9f37321b27f4dbcca16d6e06dff8ca81b881d759a59f9a8c369b62
ProofRandomScalar = 5cf7fa02f3ad744eb5baf418275e45ab31ade30669dbae98
fb0879524fb9234e93a8bd048ad9f44b428026396a810329
Output = 980ca28743e91db9e47eb0bbd0d97653be3eafa418e22a74443fcb0d0ab
1324639d253e8e47bf763080d8c888beefaa3
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = fd762bff10c1b9bd5d37afc6f3644f8545b9a09a6d7a3073b3c9b3d78588
213957ea3a5dfd0f1fe3cda63dff3137c95a
BlindedElement = 025fe88056c51a118883f57fc066ebfd34d1c430b6ae63e807c
002a97137576077456d001cbdc1bae9ba913cd07704635e
EvaluationElement = 03bfbf00976f19a850d2396417e04aa46a26e1c73dfc2ad1
f68e00e7b950a4d9d527bb490e18fbcd060113b027a37cef58
Proof = 0237849b941f1ceee136e82811afd1d3106336ff2e3917afd3eac222d9aa
c24373fc3ffd93c12c2b03de52ac10ca7db59fb9ab1d7555fcc8ac382102aa63fcff
ea84faa4b1bde8e67d5ec0a33da093f0c78950505fe2a43e597821c95e26fc70
ProofRandomScalar = ddff1365bb9b82b279e775b7220c673c782e351691bea820
6a6b6856c044df390ab5683964fc7aabf9e066cf04a050c5
Output = eaa3b760a8bc96985f122755cccb679ed403e736d78202795702b5f2ff3
f95e83f12e381183182390ceaa1a9db99b9eb
~~~

## OPRF(P-521, SHA-512)

### OPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 00d1a63030c21e61132dd7a262eb29cd1e829b9ac76ff23a46e7c26364283
d0a4aa4108e67579021fc38c68db559f92aa39981b1a509ccfc51f255f413355058c
526
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 01583649f3e9cdf20a7e882066be571714f5db073555bc1bfebe1d50a04f
d6656a439cf465109653bf8e484c01c5f8516f98f3159b3fed13a409f5685928c72d
9dac
BlindedElement = 0201e96bd2ad4e61e68a78f1ff93cc06c392b9d20ecbe5b3d54
7b27a1c2d59839ed4c1824f8a2e5d42b2c5c60ec13df725b6fc3a48ff95a226beb63
e369d3e64caef9d
EvaluationElement = 0201acc29c40527491aafd373692517f1225606aaee80839
fea30fb6d4485c1628d253b655f0a9eb69dcf3dbccee87ecee27fc99b89de62446ce
90919e71d4f0f14703
Output = d7d11aa9714247ceacf49df4d2a04fa94220d5194cf010f2a2a02ecb50b
d060544daf5cf12594864180bdf2384ff2e6d3abfc3c282e92135da48754a3e7abd1
0
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0017a273530dc66aa53bb9adb4f0ed499871eb81ae8c1af769a56d4fc42a
ef54a703503046d8272eaea47cfa963b696f07af04cbc6545ca16de56540574e2bc9
2535
BlindedElement = 0201d0be20c38601fad866c78c2caf7fbf2a1cb22a8cc5169a1
a989b8f058cc55d7435242aaf1dd373dfe232ae7327cf1f3d357fd367adbc4a2ee95
99af9d85b02afc8
EvaluationElement = 02012025803623810dafcb1fdc2afa164ca3be2820cfadb2
b0f560f396d8c8517aed3531c5d4296cb7a26adf6e7c6c7e30cda744bad6b479587c
4531d5e774cb749a10
Output = 73b823024bd35b189680dffa775d21e1c7bc8781064a083994caa821dae
7a5d33089b9fa059d5cae5b6435bd2790da3c84dfd069b6c3d0e0c5f63040b1b293e
d
~~~

### VOPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 007cc1dbc0a41dac889b3e7d1ffd2a6d30cb52cfb5818a3bba3971f5e698d
e287dd75c2b84abf675d8663124f1be9b58dfda3232dc660ebbdef28939862cf868f
62a
pkSm = 030167f18dbc82691eaf299fbf896f5f9940d9e15a99696f7ad456393ef8f
6611397ae8b59f96f1b964d34e0c632f704f345743617447c7ccbebe171322408839
1b88f
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 013a196708f773cf65852bda777210337d8b3b88754b881aa5fd937ec793
2e725ac43a07cb3ea0e90b40e0501e6bdc3c97510cdd9475ad6d9e630235ff21b634
bc66
BlindedElement = 0201cb841061f512b32bc297075fb06f149dad897ad465e6ba0
3ecdadd24966922a8f67d18df8cb62189c59973fe772debc0675408a7f678b14d090
ced5a61198ee5e0
EvaluationElement = 0300f875ff9725e1f01d7b033b7f5db6270e7ed0ca4335c4
2480095d8be79b537216fb5dcbcf8c184eb19d224b737c1c4738b69d7ddaca417713
1115a29b7f0d213e43
Proof = 00bcab8db0a1dad1aac087b973650db0fc56e3c47c3e2ba7509894666df4
52a603b64d80c6e07ef30e7926871f9879518087dbf8f7c1807ba9a1313117abdda2
4cb4017c2f88ed99ba46807165ce44c23a8010cbdaa7a0ebad771e6cde2775f333f9
7fd82350ba50eb516e7804860321bc03b0a29a828aea2535e7b67d7f047e6ce8399b
ProofRandomScalar = 00eba4687426b0b4f35c14eb2477c52e1ffe177f193a485c
ccf5018abbf875b8e81c5ade0def4fe6fa8dfc15388367a60f23616cd1468dae6018
75f7dd570624d0af
Output = 14e5fd2db0a9f6f8de87b32c7a3e0ebaaa6f88864cbdee830663b42bdfd
c7394d535b6c11c5f475efe17d81c0feec2a06b86ae71aba9139160152c8d7a38f5f
c
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0085f76f3320fdd24777894218769fc1965033654f34b06b578fe36ef23a
5b9872ade82b9261cc447670debcf78318add682f6055089b0a2484abc37f110b36f
4c2b
BlindedElement = 0301baa873c7209654d581f46fa3f2f4bdc4f423050e7c9a779
f4ccff0812c5acabc2fe940f39d280fa9a07316acfbfaeeabcdc520cd5e75cccedb1
adcd5078f9236a4
EvaluationElement = 02010d2cf68d4487a5bec660ec3f73643bcc943eabb87a2d
247221744ab4d04acb1b9a86473634545a0f25f4ce8f749e3c801563922f676930ba
b02713aa58ed8da5f4
Proof = 00dc5e22af46281b266ff0db223f4467139e101e7e0edd2d166698547ef2
6512ea3e75efbd38d1ef0ae0aa34fc595d1f7ec6476dfe458b1513add106c2161bbe
ae1901a0273488c5849ebe72409bbb004b9fb907dbf2ae243024f11cf03898448f37
4917e467c15501f8994573d8f90cd331ad57321318ba1560c6a7f6e45350d258d67c
ProofRandomScalar = 0165aa02c8e46a9e48f3e2ee00241f9a75f3f7493200a8a6
05644334de4987fb60d9aaec15b54fc65ef1e10520556b43938fbf81d4fbc8c36d78
7161fa4f1e6cf4f9
Output = 0360a959a6b39a605df1eb3a82a1a81fe556bced35641e76282cc6da1cb
b9b1cc59a4c4ea8ee6d7a1c6ce9dc6b5afddf50fabf785119c34426b9a868de1a1ff
8
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 006915357a04fab501c0f6764e854701129e38071b008286c5fb629de5cf
ea56c0532dd8254a5a6e7fcc9e51e20a1cf4f254335ca57ce603ae7cf03fc00b7a2d
4953,00d60ce57aa6729d935ef02e2dd607cb7efcf4ae3bbac5ec43774e65a9980f6
48a5af772f5e7337fbeefbee276c901e6e57b7ec6752a45c74f3ed36a3eb8ad0dafb
7
BlindedElement = 0200112309d14634e5f0d453d1289f789d7014a90b021469e68
2026f411af0549ca3d46b22c46dc4c05ac9c3cac9755f394f3ee4374925d1f0395cf
b5611ffd7988b9a,02000f240c39d3ef3b03a08efa617eafd9605fdf40f483a9e8b5
f3ff31e9affe14812e4afa16939069070dc4467481f4557c6bf21f1da1fa706b5ed6
a9895093abcc5c
EvaluationElement = 0301170379a824cb1fda73cd468434928d130e7ed2278250
e65acdaa3d83501d4035c38e095f409456dced6897f6ef92d1af6f8c7d83cf895a47
5fbd3b128ff87cef40,0200a4e6f8809015a2013b7bd179bc8779bc9e48a97bc2e03
75cab55bace4d4b37f9eb49c30d5c8444ffd5b3c55ab423634186d0c612120b18abe
a7977f2e78f1b7108
Proof = 00ed723125343b1b28ac5be37d0a8450c51719b67991a49bc293dd635561
a8b8baec98d3d44ae4a6b11c70fca0b70baf20aad7b957069f694bef2c3f9e3b7c0e
6249009da81daec8c7edac11437e361edfa82428bcd13b64fbe092fbb5bb9575472d
608bb025781ee97d64355e7d4b2b15d0312a28abe169c45e0084ed97102c0b951d27
ProofRandomScalar = 00ac8346e02cbdf55c95ef9b1aadda5ef280cfa46891dfa6
64a785675b2c95bbc2412ceae9d69a186038345f8ff704bc925f6818500615a825a9
a6b5646a4e4f11b2
Output = 14e5fd2db0a9f6f8de87b32c7a3e0ebaaa6f88864cbdee830663b42bdfd
c7394d535b6c11c5f475efe17d81c0feec2a06b86ae71aba9139160152c8d7a38f5f
c,0360a959a6b39a605df1eb3a82a1a81fe556bced35641e76282cc6da1cbb9b1cc5
9a4c4ea8ee6d7a1c6ce9dc6b5afddf50fabf785119c34426b9a868de1a1ff8
~~~

### POPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 0054f0bdeb1cd3f6f40fc22d946fb601d0952346962789123bb0d8a8d5b7f
323e1d4221d17c29ef172fd8d3f72a8c0513191e4d61463d300102d3ac80e0823501
22c
pkSm = 0300153a24651db423fc97855da300e800b3a8283d5c0a449e0a287379f6c
fb8c3f2fe3d76910c33ba15f8ff326781e66d0dccad9b5738110e614dc15fe019f2e
aa7a8
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 010204f2476ad5274e2f9d258659e80b0fbd20e4761b22298eba98ae9dc4
fcbc7ad42f5459d29f5c3b170f51d08e65679d984c1e852b2344bbebcb92747c83cd
6b89
BlindedElement = 0301fbaa2acd4b3c118aecd4001d521331b1d98cd45876c8c28
b37f6e38931abf8f6d7ef221ffaa89430817c0f51af0a3c82a5ae01e5afb76e912b7
13f095dd2ca2152
EvaluationElement = 02011c890911f37cbe4ea6661fc75fe48906b1e5b23ba6d6
572bb4d19962764f3035998c20d83a24542a17bee14e6a42c40d93d187d0ca19d88b
d1af204e69d4784ce7
Proof = 00d1c1971521dabae232b4d8a39452e6e24c02275dfabc3ac9a73f393c6e
98cf48c6cad2debd7dce9c77afaa1bd1db7fc36f7a0800e967a8ee5eaab246f4a8ee
3aa6013ff6d10facc5dbb9d9663a6e35eae7af9fbfc3734f7110a54f60daeeeeaf61
adc56d8756b4d7a2ea4ac796576309b197719c1f824cac0980c496db8bff29a30f51
ProofRandomScalar = 008492e4dc9cd7f7aebfb1d3d2b8c7fa7904503aef20c694
a01d3e1154fe98e7232be9eaec5789a012a559367b1f99654ddef5acc7b0dbee75bc
d8bb50363ec64004
Output = 784ffc4bf976fb038bbec35daf7224538ad9a466db2ed46c45adc12c6b9
d3f5c288ed3eab6eab2b80827f39adc462dea08f6b8bca915254c07ae8e07c422c17
8
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 01ab3a90cc9da17604b2e59a93759eb0985d2259c20e3783be009527adf4
7f8fb5b1437cba7731c34ac70bc6ab1b8c14ff4110afc54c9598d5f1544830f9d667
b684
BlindedElement = 03005afd7be45866679f4d6407ffbae16df62ca61437487ef41
97963d0700ab9dde69bd326931261d533e16755b528b5ac7d6916bd37c49e76a3147
a3d91d3a9655d70
EvaluationElement = 0200052e9d41ff00effd5271902cdc24c8da90cc0580eda8
64e39e6b37ccf683773b0954536d75dbcad9e58529ca62c168d465f0a0c769ef1801
676175b32f96c8018d
Proof = 002138268534e0e2c0e930b2bc56aa77336ca32ab1f071366c0ddd27a303
4466cc37e141d623fc3116eb2b0548171bd71cca4a60bfb8b08326e023cf370ae3dc
6e2300bc1780c8e8abd14e9668528a1e3cac326d1d23feaf8c0db09d17e4b39e340a
08d15cab3d16299fff888683a5c16cc75977ef53dd517cec9081cda26ba0d0822bf9
ProofRandomScalar = 008c15ac9ea0f8380dcce04b4c70b85f82bd8d1806c3f85d
aa0e690689a7ed6faa65712283a076c4eaee988dcf39d6775f3feee6a4376b45efbc
57c5f087181c9f04
Output = ea16d3f0686fbde89d127402676961bf0f6f06a9e573eb643d4e77259ea
e4b74ce57dc50a6a2a04f511f9d2d32f0ccc97527a3722254f12d9a9b6cf23f3b5e1
8
~~~

