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

Base mode and verifiable mode uses multiplicative blinding.

The server key material, `pkSm` and `skSm`, are listed under the mode for
each ciphersuite. Both `pkSm` and `skSm` are the serialized values of
`pkS` and `skS`, respectively, as used in the protocol. Each key pair
is derived from a `seed`, which is listed as well, using the `DeriveKeyPair`
function from {{offline}}.

## OPRF(ristretto255, SHA-512)

### OPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 4c7fc71da2894e99df0cd5bc4ebdf3af8762b9f92accb142af1894fe87bc3
805
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf
8e03
BlindedElement = 744441a5d3ee12571a84d34812443eba2b6521a47265ad655f0
1e759b3dd7d35
EvaluationElement = d028a654086f9e469ef8a98fdbead48166ce3a61a76b6869
15f2762f7941a36f
Output = adc35bbea9f0a8c866e08acdccbb8c0a3d1622b057f62ec3df359179a05
c4a2b02ec2dbb060257286f64e593c9a5c9dfda36f4bed110a32fce2b6197a42509f
3
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037
e50b
BlindedElement = f4eeea4e1bcb2ec818ee2d5c1fcec56c24064a9ff4bea5b3dd6
877800fc28e4d
EvaluationElement = 4e8704e7f9dfb4f120ec7c9c13444f526713f0518338e14a
437672a16be2cb22
Output = 0bfe47ed643d6ef9a775a68a8161f6c52d5500393bfa7977a3da9298f47
622250d0ecd5731e0bfa42b265c2539766e1ca71cf0fdfebac5fcd06d1814225d0b9
7
~~~

### VOPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 78a9e0462f4b74f8f645f270a019f75df3c7da3c55b006a96eb4434be805c
200
pkSm = 2840e6410a3e9af6cbcc53f518f3cbe7906b8a60b701c98ce387277c461d0
a78
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e326
3503
BlindedElement = 56c6926e940df23d5dfe6a48949c5a9e5b503df3bff36454ba4
821afa1528718
EvaluationElement = 5aef15517ae1a5caffdfad7fd7f6749d60f69d23176b99e3
78c24f0d92d03657
Proof = 0bbc3b268c6b910d4d77a9abffab9de6598b0688a31b83ca5dfdb8c88e20
3b0baf9cec4b25a3a04840d2909e88124c44bd5fefbfba9bca7ad93c650476b59c0b
ProofRandomScalar = 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9d
bcec831b8c681a09
Output = 65c58ad1d6f8642d280f27604eb0eee50d84098e4bdfa5a232d280be244
0cd7a5fc0cb15e9027da8fc42cd731a97fe14db373deeb02a31d896d80a37a9ce4a6
5
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd4171
ea02
BlindedElement = 5cd133d03df2e1ff919ed85501319c2039853dd7dc59da73605
fd5791b835d23
EvaluationElement = dea3a15dd1f22784999454c0a583d73e220b57c9917c6919
6d479cb4f2081d4a
Proof = 28aec272e3b845d552dd61685c75e5b5b6ec36893e84d5736dfcdd065fcc
380a0ec31bf061132c793ce0119e2ca70684e3cc5c84180189b69c8877b81f9a5601
ProofRandomScalar = 74ae06fd50d5f26c2519bd7b184f45dd3ef2cb50197d42df
9d013f7d6c312a0b
Output = 4e092a6fa61b18eb445ade7317a2083de5c4bca8508911062ae36b57d85
9a56c7458643fc5d02a8a0df1908fd738f92a964f6313162e69d311d41a55fc10f4c
6
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
EvaluationElement = 1ad9916dd8df4ea504dcdb612227cce43f00e7cd43a32780
feda5840a56c1804,a89cce726824b6f05db2ace2e5d4879d44a54ee8f99f52df37c
5cc779ff16520
Proof = 57a76015b268d55f5f7de93053dc4facb189664eb1c0b6bd1892d81e429a
b8012ae6ef1b1298880d68daaca3c4fe90e59842f32c588a1e1f1d1b6f943856540a
ProofRandomScalar = 3af5aec325791592eee4a8860522f8444c8e71ac33af5186
a9706137886dce08
Output = 65c58ad1d6f8642d280f27604eb0eee50d84098e4bdfa5a232d280be244
0cd7a5fc0cb15e9027da8fc42cd731a97fe14db373deeb02a31d896d80a37a9ce4a6
5,4e092a6fa61b18eb445ade7317a2083de5c4bca8508911062ae36b57d859a56c74
58643fc5d02a8a0df1908fd738f92a964f6313162e69d311d41a55fc10f4c6
~~~

### POPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = d42f97caeed7ccc7e8b545af9dc13b52b03910e52c1943975bfc4ad582e98
800
pkSm = e65ba5670b3135afe3f50bd67157eb61f4176c9a936198a6cfdbb9649e050
f53
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 7e5bcbf82a46109ee0d24e9bcab41fc830a6ce8b82fc1e9213a043b743b9
5800
BlindedElement = a045ba27352937407c6c3f09ae1ad7b8ccd4ee120df5e92dcd2
2014756e17806
EvaluationElement = 8c7e204ba4669a956fd4b105b2a37f5f4ad5a354d24aac21
6ee960206fc2480d
Proof = aa418f22626da212f2cbb8d32177ba22c30ffd5ae34ffd5e58807791ab36
30093e02ee752afa2ab2cad747df8a172c3f010ee61c2150f40a7a0a2a046175c707
ProofRandomScalar = 080d0a4d352de92672ab709b1ae1888cb48dfabc2d6ca5b9
14b335512fe70508
Output = 55736cf6ac56ff90a9023496a7cb7fc6cfdd0b2ca5e5f3d226cd6adc69b
ba83751d9c0da2e88be9419f541ccf5ee6bfb2c68a9448a95c8968a85df721247498
5
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = de2e98f422bf7b99be19f7da7cac62f1599d35a225ec6340149a0aaff310
2003
BlindedElement = aad45f3d7d66884129d3048614dcd3e35bb0fbac66f073b916b
8ab66c7252249
EvaluationElement = 8e5d0309251e753f4f73a6792dbfb6734bfd8f00b2bef1bb
f22f1b675aafb01c
Proof = 4761f424b72ba05ae2157358c67d7779ef9842d3bcdf59d976ca906e642f
34067df26d1c4d31200bd129f5359066c301c0fcece6b175c59ff4e6cf70ec704508
ProofRandomScalar = c4d002aa4cfcf281657cf36fe562bc60d9133e0e72a74432
f685b2b6a4b42a0c
Output = 97f2252268ec5e3d0283f18fdd2286d6ffd478f9a61dfb023dcfe41a84b
289e798be60c49396f80464cfd5cd55d8ce792fbb469b15a96471e5fc6a0033f8567
c
~~~

## OPRF(decaf448, SHAKE-256)

### OPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = ebe387580d5030a2242b84eff659b5dac5517e29f66bda6516ee6d1fdccfc
e42f44c293f4242ac0ea4effca0f602f26bd3eaaa7b87547528
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = d3a425c41eac0e313a47e99d05df72c6e1d58e654a5ee9354b115060bca8
7db7d73e00cbb8559f84cb7a221b235b0950a0ab553f40bcc304
BlindedElement = ae09cc0ef98064e4d0b3a295026d62ce80b4be8e44aae716fe3
5c1536fecd0aff874fe7553bbd3c609558a8c5474a8762ebf8056839dcc0f
EvaluationElement = a8578389ab28bca82f4e4650daa3d3cd22cb4a9c31c75da7
a248e57dc3c2ea8a72b552df98c61abebdcf1e52bb748bdc0c8f26852e8762a8
Output = 318b62a1a3fdd7993b9efe6d1c20297ddc2d3ee930b9ac5aa31f3623fb4
bfa8047f1242785f658a5d9c2e4ddfc5780ceeeaa08c224396f52c68290fbfbd3b56
9
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 87abe954011b7da62bb6599418ef90b5d4ea98cca1bcd65fa514f1894bcf
6a1c7cef33909b794fe6e69a642b20f4c9118febffaf9a5acc11
BlindedElement = 863a8628a9837efbc0d1caeb69fd5b31c6fd3359d8e74fc07c3
911dbaa6103dfb7b7b6c0b86f50db7b151fc61d1079c271abd402a2932d20
EvaluationElement = be0bd51445ff663f72f0193c53d6cb570109511383af6a0e
2f7cf96d0e9891cb801f17146186522aa8c58db61c5965dfa88d7a805d1cdb9b
Output = 778d09c174dba9f6da72a77016b370f540aa600e7f826cd12e5dc106320
4df92d954fd3de790f8786916163396e20ceb34ae6e5c5476dee386dc62e405998d2
f
~~~

### VOPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 2402105dc23bc3f34b02cb2327517639d128ced6db5c73c4c253caba0909d
88d56107f8eb86768e4466202ecce4a233bf5fb0cb914354c10
pkSm = b2e4f4f153b36566a01b7e30df4e9ec84b8b61933fc00b51bb4aa2af6e80e
faadb43d5d655d7be0289621ee58de7cc2379a9e1129b7faff4
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 20e7794aa77ced123f07e56cc27de60b0ab106c0e1aac79e92dd2d051e90
efe4e2e093bc1e82b80e8cce6afa798ac214abffabac4a096005
BlindedElement = 5cc67ce84bd60ef4760cbd864aefd7d30767a7d6ba6c7af63bc
11347ccab9b59f9bf09cb76e627f061f46501a1f05a8d7cf11a24dc0d9c1b
EvaluationElement = 28cdb10f86342a8808dde4cdf87e88b0d1933c80eca1e019
49d771d100b7fde1f7bb655522608eb53bbe865dae066b4f68b5c8898903b350
Proof = b38c9ced8c19c21d117ab3ff74a260465c41d6bd4f1d13591fca6064b3f1
25adb1f00107dee966e40b6ac3fd2f9af6bf37db2c65b64e5430c0a85271ecb43346
58197ed7fd6db3344e9954542b35931a6cc050219df540e32e183a85107d880b1b78
9574aca698cb1a42dcb212c5f705
ProofRandomScalar = da3e9faf0f2009d16c797646097d761e2b84e0df5d76ece5
658b3aab5207735beb86c5379228da260159dc24f7c5c2483a81aff8f6ff991b
Output = 343c4f56ba8a91b536fec3f46ee4d2bded75e01017beef067ccba93f297
b338b5460280042a4e5bb960baeed5730fde8e2d647b1649ade87665396c995f3c85
f
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = befcb571168f337dd52851d4bc07947c858dc735e9e22aaf0576f161ab55
5182908dbd7947b1c988956fa73b17b373b72fd4e3c08992892a
BlindedElement = 8cbf06254ec3393734d50a9cbf7b6b27bc18706a49f4c559ee7
aa4642b1295d5de7e9f1150d51611660344d8a194c584fbbc1e1908428a72
EvaluationElement = 1e758ae94e868b6c302362370916fe32c0e310df5239f83c
1903aa4086090228c76ddea1724e476afcf04ae7ea289ca30d7ea4b822b0499d
Proof = 05a7ddb6f2ff77babb4616e30622d0daca3e0c6cc8e75e981f166726c984
c8abc1c75e049ab66094c92989ef46152d464075512bd6b1131c399c78e751b6ce2e
110c50d4f9600a2762a1acf508fbde14154d5e0f7524ad8a76af435e3eedb93035fa
174ed3a60c29aeb7ce1e48aaa712
ProofRandomScalar = 4dab20fd864de6ceab345e8d755997956ddd1f267a2d8617
5aeae5e1168932285a6f602b4b20a570a697452b3ddbb7d0e29363ad3a6fed19
Output = d71928d17aca3f582f7f1b6af7aa8d9b67400f5fb00691d0f3651485afe
831bc23e6c8c989597f54d9905de2c4d2f9eb0d0999cc50d16b3272d7a60eb16f0ed
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
EvaluationElement = d8d4acf41f8183a200c849d8d99ce29a89626b573d5c0eb5
e6fca01c30212f17dfaa7436859cca3d32a15cebbd548c0648a0ae1abb57272f,58f
b207a2f35d576ca047baf3381400e737f36ded618d84c05d4d78cfe0039ad9dcc808
88801e4bf921122e0404bd9306908ecfac99b3e53
Proof = 2d81da6539b3b2624e538a98ed729b1c9a54b7ab4837118afb327d843416
976423bbf19dde84553dcf9419de4c10d6f8380f17b8f0c46124ff45837245d3d8f6
2fa64bb4dc3d690ce02e6c7706ff12bb5cc15a784634a934f90b0fefae12d4085324
ba45c504e5e412f49ca8e1e24c09
ProofRandomScalar = 4e278b9fbe31963bbdda1edc786e5fd0033feac1992c53a6
07d516a46251614940e76a2763b80683e5b789398710bdbc774d9221f74c7102
Output = 343c4f56ba8a91b536fec3f46ee4d2bded75e01017beef067ccba93f297
b338b5460280042a4e5bb960baeed5730fde8e2d647b1649ade87665396c995f3c85
f,d71928d17aca3f582f7f1b6af7aa8d9b67400f5fb00691d0f3651485afe831bc23
e6c8c989597f54d9905de2c4d2f9eb0d0999cc50d16b3272d7a60eb16f0ed5
~~~

### POPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 65dd6345bfc5c706fb83953c4da666e8cac69f5d6b76d14fa9ee4eda12946
46b981c92cf836c8e6a1ed9591f0081cfd29cddea94ffea0135
pkSm = 6e229312ee156b0cc42207835a6166ef07a27a21277f6a679a3e34000b5d8
9ddb68aeaada39b011d79ce00715578ec25cc1d0225fef659a6
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = c3b11cb03005ced988ae863bc6f3e8b59bbd1354548220e81cd0ffb6f9e4
ec2173870ae684f86b1c06e41ecdb9ef83429e58098b238c292d
BlindedElement = ce23c7d365058dc76f97adf83eb0c7baa4f27aea3ba1b015d0d
a3043afab3d84694f1d0f5dbb77cfb96873aade920218f5ec80e481584747
EvaluationElement = f2475b26585ba90dd554e846697b3028ceae370fc263dc59
3d144049d93e07ea1b4656dcca116623d7b161b54cc7fe2b96927fe61543729b
Proof = ab3a046662927c1410fd94a2df0d525668c912eab173f7f584b3303b1b2b
2a32b332c7a696aad02e74a1dfe32b59c1875f379dba2253d31be881db3f47769136
fb19332718752aa540e1131ad87450b1c5fb6b807f4a03545cab3f07bdc2ac6c7d20
f35cd3bf0301beb50a04d2e46104
ProofRandomScalar = 9e414ad5e6073d177a1f0b697d9efa2b60c984df38632f10
96f2bf292478118d78e9edabbe9ad22900ad84b1a2cdcb869c70c832589a471a
Output = 88f4d7a08e3f19109735fe21dc82ab9255d67d796eb5fd7502bd017b403
e45f03ea973e949442c0946d18e7440f82b7d7d29c4e2dc5f5b9502a8bd135a5cc64
4
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 87c1563075086f0749e88205237f77416210747f2369383efbec7bf6c78a
77d5062b938e91fbc6ce569a4461a97bda32d0af163d4307bb22
BlindedElement = 14e74297bbe248bb6a56e72310c55cc3de98622adc7aede7fa9
89163456486e06909f990d046120571f7e787c5cd177480b769f51d240618
EvaluationElement = 4e96932e79378a80dd689d626b5caf1f75ef971d9700b009
7f29cbdda6ff4fb2bcbc79463aa9765b63f94d7034e5b87b075c2447fa3ddb4a
Proof = 759cdfd0120de1c1cdf52c67f3762999d1fe970843b9b67fec37e2ecfb16
b3a80c973f90139e14c3d1c33fb5e81742b3c559b93413a26c37b642ce726a1917e8
b37648984befb2a8c1786d46f1b3d9e729f9bbde585e0718182841ccefd8f1b9de5c
6d5bd3fc3d8b478b88a479146f34
ProofRandomScalar = 68481b589434b3b5b6c131de9e080e58e63ca9ce7d0c1bf8
1599e1a6292f2574e3a23e21d5bf79ecc75a16f7a77618bb9a9224c39cf90a18
Output = 47c417085741e09883595fb04d3a79fe6b9ed1b2dc81278e13b5114e24e
e327ac96eed0e66cef98bbfde83c0541d959bd4c1f6b41c413ed25cbeaefd521ff8d
7
~~~

## OPRF(P-256, SHA-256)

### OPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 27036ed0b3b2f3004736b7b6d0d8c8cabb1e21d2d895d3f8de77e4aadda9a
3fc
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 41fabd4722d92472d858051ce9ad1a533176a862c697b2c392aff2aeb77e
b20d
BlindedElement = 0214499fd6847222cfb6cb68db02121851b9ed884737541fddf
655798a2b22c9a2
EvaluationElement = 02fbd25c24081b67493090a421989a8a2e49158e49f2ee3a
7fe7f27fa53f3ebb10
Output = 454fd1ad4a21113667529769a88fe7a2ad0603c4c8a083a99d8523fa9e6
d7368
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 7b7f977a1fb71593281099ef2625644aee0b6c5f5e6e01a2b052b3bd4caf
539b
BlindedElement = 034c9497343f27a300bde18834dd02dc656af533111811a565c
ba0ff554d384dd0
EvaluationElement = 03e2bc26ee4b00826601c6368c2134675ecc26deac58ad94
611cf03c09d0c92785
Output = 17155c3595a5e83cc95caa8fb6f3d9793a0c42c0a24eb8a76d399bac8d3
e57b3
~~~

### VOPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 6847d75f93e8e81f615cbaea3e78ba0460a24d14e4c6f0e6a85b677250a15
f4e
pkSm = 036524a7f7e081abc8843b66bb10c265150412b97c6e6c40015b07396411c
f25d1
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 2c2059c25684e6ccea420f8d0c793f9f51171628f1d28bb7402ca4aea646
5e27
BlindedElement = 035f218c9109e2f9fda41525d02bf0637b76e821a11155b8cef
51c2f4143261124
EvaluationElement = 0351db34399846a7550b53f3e4bf869040ee0c52065cdcb3
3f73250fea195d65f7
Proof = b75ebae0c84609ad0fbf5eb8ce97ae7316184d479217c94e28f57907f492
8fc0c3e6f875a2f9eeb1a4bedf97637e5f2833f8ada48316098d4d6d7ba858cb92e9
ProofRandomScalar = 1b538ff23749be19e92df82df1acd3f606cc9faa9dc7ab25
1997738a3a232f36
Output = d0565869d6c5a270981d5f7feb6b9dce2878272912cb0bec11d105731ed
84e2e
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 8b45f65717a40c38f671d326e196e8a21bf6cfd40327a95f1ccfc82a9f83
a75e
BlindedElement = 03552596458a0cd6656909d2b475306e1bc8a08363984d6bda1
546784501b5b068
EvaluationElement = 03270d4c0e917a44c2cab687b44c41aab67dfd4f4aaedaa9
bd6f38b82a1c16432a
Proof = 1c6f5d8a29b66343ed2939bb5956cef2a9e59ab3b82cdc4c99fc75c29239
0a95f0f6d368ef7cce36e894e44a6a8c6392866163b7d11289da9436c57cbdcef81f
ProofRandomScalar = 3d35895f4cff282d86b2358d89a82ee6523eff8db014d9b8
b53ad7b0e149b094
Output = 9d35d1f8a3f7daf8ddff02ca245929b4a5e6699b43b0b95b0162895e0b0
f675a
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
EvaluationElement = 0275d0f537d6038b2d75ce8cb083d024641ae8efaf1f7961
d26d9399c99acbaebe,023e38295350859fc05bf7a9a955aeee96b7085f15f641420
0b1b4dbdac479f25b
Proof = 9038d70ae28313177b5cb74661978c9933851116f08e5eb2a9ac901131ff
6678f8305d497f8277d35d5161afa91f29be4c1c422acb9660bebb5b707943a4029c
ProofRandomScalar = 316bc8567c89bd70267d35c8ddcb2be2cdc867089a2eb5cf
471b1e6eb4b043ba
Output = d0565869d6c5a270981d5f7feb6b9dce2878272912cb0bec11d105731ed
84e2e,9d35d1f8a3f7daf8ddff02ca245929b4a5e6699b43b0b95b0162895e0b0f67
5a
~~~

### POPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 86d7bd12b14d6cea0c974f4c8ec630aaa0ce4e3fc83e0c8f7767118a778f4
922
pkSm = 03ca3b8db80817b9b4a69bcd4eb759603f00e832c1e9ce262e515eb4e0166
c7d10
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 0470f06169bee12cf47965b72a59946ca387966f5d8331eab82117c88bbd
91b9
BlindedElement = 02a9e77b7aa32172fd173e59a8a8a9c1e3c4f4b5528bc0592dc
21ab64772a3320d
EvaluationElement = 039b74785598f3d52a31ac4508adc2596ba55605eddc82df
a1d2b8087edd0e1363
Proof = c91ebbe3034efe49a4cb1a69099d19c24a1d27ee643f590d7c53ba7ae000
bb605ef0fcce106ae053275b55e9ee6c70a88eaa65c2623d3da0ddb296b940547e90
ProofRandomScalar = 466f3c0a05741260040bc9f302a4fea13f1d8f2f6b92a02a
32d5eb06f81de797
Output = e67902ff37dbe765d5598734683e835b4c0b7a925ea6781732e2b2dab6d
3e1d8
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 15c1b9ee1e66339439e3925cf8ce21ce8659f22523b6ce778bbd8f8b541b
e4be
BlindedElement = 02f6e5ffbaf4b8d98cd9b8a6a5243a3cd509afcf537712f21c6
28aa10ef52c4fb0
EvaluationElement = 039ce11a11caa100f68f9bd21b40408ede31a823f49cfd01
0261e78de419138b8e
Proof = 85049e9d8bb84c3cf24546469809bc0dc344b0ace47ca6c97399b5484f10
469d7186693b495605f7bcc1e538cc117afffbe542d42422f1f0be56f284330d7eed
ProofRandomScalar = a1545e9aafbba6a90dc0d4094ba4283237211e139f306fc9
04c2d4fe4cc69c0b
Output = 333f322b5d5b8eee8135d5c62ecb4d11dcac46b177be37163933b3c338a
e4260
~~~

## OPRF(P-384, SHA-384)

### OPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 8a5b6078cf10527a7ea1cdba859f0cdf3630632da2767ca0abda4c80da1f3
5989e833d04d6100fd665d16a2fdc8c51df
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 4dd65065273c5bd886c7f87ff8c5f39f90320718eff747e2482562df55c9
9bf9591cb0eab2a72d044c05ca2cc2ef9b61
BlindedElement = 02c4eb0f78b26dd471bfa6d8babb0936425667ee6bee5515513
25431a564b7a5bfdef110317b6b21453955c63681bb2a11
EvaluationElement = 0290a2e04e422a40af79f1cfc3a5890df8b1bfa3584ce508
91356dd447088b303b171b5938527a24c2cfa7510b795611cf
Output = 15eb0853171822610664cc205bd7aedd08448bc0be7da43810b39f54a0f
aa91515bb8ba52c1c7ef0b191ba795561002e
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 55f951785ae22374dfc19eb96faba6382ec845097904db87240b9dd47b1e
487ec625f11a7ba2cc3de74c5078a81806f8
BlindedElement = 0334bfc4cf126b2caad4964447039346a3f2170608f6aff312e
deed6d186d6cd16e80a381cd3575b9561ae68c228fee4b8
EvaluationElement = 03341ade3279a078e7c9d77cc8a2b219529b58c464723eff
ae5958cbe457bf6941e01ebdb6813408d65480433be04ce2b2
Output = 390018cbc7652d672cfd3a24406640cf5f31c24df24269c39ee21a72e47
74ceaeb416d5caa681c1a5365d4e07313cb6d
~~~

### VOPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = f3de345ea565c0be9085a4351a533ffa45937c41539620354bcad1161d1ae
c8a940d1856691dae84b34443263210151d
pkSm = 0279310e8a83735e9a865cf74f4c9499c600d8dde733f9d67b7202cae8316
60ce1282c02ba76ff5816b5c051974ae4bd0d
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 84580de0f95f8e06aa6f6663d48b1a4b998a539380ed73cafefa2709f67b
d38be70f0ffdc309b401029d3c6016057a8f
BlindedElement = 0394e2556115a7e830f55d56d141ccf3d85ae18169d8ee80c28
978ae1abc49fb4bf28e82f68413359312d38d2cedc55bf7
EvaluationElement = 0219d1e9c4d8e4bb5d09a1efae0aa11c9bc6a146604e8784
fb7dc4a96556d27f4718b3b357caf42789dd62a2187f411f9d
Proof = 65403a204124678766690684c1793c823ea9b31b0aa566384b27d7d429e8
c05ee28801a4eac5bdc8a7f4348255ddbc965c6f103e952e3864e4948be2f28f2f44
9be1fcced439e4283a646d824de3b421fe869c013017bf550d35cc08a81ad28d
ProofRandomScalar = e17e559ca3ccd1944f9a70536c175f11a827452672b60d4e
9f89eba281046e2839dd2c7a98309b06dfe89ac0cdd6b747
Output = 8f6eec8556d0f4205f25d4389a177ddbcc09b44aec976533c5730e67fda
c05980ebdae562f080857519e965bc866aebf
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 7759061965a423d9d3d6e1e1006dc8984ad28a4c93ecfc36fc2171046b3c
4284855cfa2434ed98db9e68a597db2c1473
BlindedElement = 022a802b27e6f6468b5f8ff12a9e10e971b55f5f80c2967cebe
6cf3a22c6c5350cc3b8a6fd7262d4f601946e18c827dae4
EvaluationElement = 02d4b4a2b901b5f5bd9b51986a43e169ce5ce6b68314bfc8
2a0a397ab0e7754523a42f1aad10fa96d2baa578284ad7f730
Proof = 7920197b45a8f89e38f73c80531d7567db553702ef82d8b7b42cb50f478e
173399dfffc11f84fc9c2442d57055f529304de1468cfceca9a865309aed6f869420
4a1c32893f1d97fb9dc6d67835c1cca7413e9f9c0a95349d22e647196cf18bb9
ProofRandomScalar = f96713dfe16f40f2c662a56ed2db95e1e7bf2dea02bd1fa7
6e953a630772f68b53baade9962d164565d8c0e3a1ba1a34
Output = 9d47ac14c8a9acefb2367eba1a4601d73b21183e0acf72eae239b2fd6c7
07c5f81b330d2b74157fee6ae81ba4066cd14
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
EvaluationElement = 03aca8828681ee2e373eeec31725f720ab22911cec6e1ffd
bfb9b9810a7fa52fc835a19c2bec6672967e7cfb4939d0537b,0200cca5243bc29dd
d10db7069c1033e7b661f7ceebbb53a249bba706d8105d9efe3256e16665ee04145c
fd3c7a33521bd
Proof = 26c1028708c3e59ef5d8a397c8ce8cd527466e8d457e31ed2679507d2129
d80a0b2ce7b5c87d5ca2e18e24e77ee0f49b49968c678cb35a908f3c904d9940829d
c26028b90b893e7a878a941766574df4082b7d3f33f355d5f51630dea6202453
ProofRandomScalar = f77ff0b2ebcfe21e1a1ca4a84361e9f1b18e24c9a40ed5ee
c262bf51dc970d63acb5ab74318e54223c759e9747f59c0e
Output = 8f6eec8556d0f4205f25d4389a177ddbcc09b44aec976533c5730e67fda
c05980ebdae562f080857519e965bc866aebf,9d47ac14c8a9acefb2367eba1a4601
d73b21183e0acf72eae239b2fd6c707c5f81b330d2b74157fee6ae81ba4066cd14
~~~

### POPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 51ded4dc54dc6e5a16908ad6611d01444d97b62af69f07e01d57dedbd9dd1
40f30ca4d3f2173757ba6207846e543d4d3
pkSm = 035ce2b30f7d7065f25fbcfcebc03bbcd675e204207192d70a1b66a6e34e4
ce11bfab37f59357c9681b4bbfd307fc4e572
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = c405a354e666f086fa0ea4754fb56527be010296ea880e1c6a4dbbc9ede5
43a2ad0f83fd60fdacb59801a9d83b5d1c10
BlindedElement = 02fc60f6dbc6f262fc96f4b3cfd464f967eeb143f42630aeffd
8a89a51af29a4ee913899f1c43b8eada345126fa7291fbb
EvaluationElement = 036750d4d51b5db8bd3d36101144aa73c879b85563dd881e
cbf2f7a85b05bc6892f1d36880afd06ef617d3dbdb497c3bc2
Proof = 1dcd1ef4de8208b13769b1604ab1ee3606ef4489bf90c90f947445e14176
d70d6dd8da9818fb5fdf497fd6e79df61582d339a3bfd925ea0ae28b349dfa7b2424
bd6cf4653cb9fb4597cd7c93f790bc09f4d78690c71e9e4b9ab8b246f7b8a574
ProofRandomScalar = 5cf7fa02f3ad744eb5baf418275e45ab31ade30669dbae98
fb0879524fb9234e93a8bd048ad9f44b428026396a810329
Output = e6094a5251ef7495e4af0b16bba0637562f23a20a822d9bc944bd824cda
f6bec0e9e0edc60629bfe38935c152627bfcf
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = fd762bff10c1b9bd5d37afc6f3644f8545b9a09a6d7a3073b3c9b3d78588
213957ea3a5dfd0f1fe3cda63dff3137c95a
BlindedElement = 025fe88056c51a118883f57fc066ebfd34d1c430b6ae63e807c
002a97137576077456d001cbdc1bae9ba913cd07704635e
EvaluationElement = 02e5578a52ce2ae2402b52b4cdf1318c7966d50947b3cb84
0241c2feed67c72d18cf96a5db69478b3afa6d87d1efc13896
Proof = a9be545a8661e28a6032bc160176e7d202a516b37733294246a27d8e0513
9632ca2f4b138696aa46209b53a6c70b00568852dc20d43ab7042bf70080bf9280b3
3baeb82f907b72a493c3d2dc1b70a578f8e83c44073ed61618509706337fad10
ProofRandomScalar = ddff1365bb9b82b279e775b7220c673c782e351691bea820
6a6b6856c044df390ab5683964fc7aabf9e066cf04a050c5
Output = 2178cdb693cc4ccdffaa24ced6f139e4fc33ea2df2d8e139a6d50c31f94
13b5e0edf9c162e191cc9429edafad940102e
~~~

## OPRF(P-521, SHA-512)

### OPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 0097061ed5d9aef9e3ce979af799dfa7014fb55af6c09331179ef9b396197
c903e94547e81c58d7a73d82f7816d128ee0ca06d374e3a8f6ac6d26ba36c9f294a1
222
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
EvaluationElement = 03010283cbe505ee7bf7e7ae5471072f09274e71d0169d0d
1f468d8aef796c8def16e8d00fb04f17e19f7a7bef72a069f950659f2caaa480e732
534af9d510a5221748
Output = 5a5ed5c2be2a61e39f469434082a73fcf3923679b614245794fe79bdfbd
fb100cce4fb80b1d40d5506f742403917bd4314d9da6d42ee78ae20c0a8907a939bd
2
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
EvaluationElement = 02000ef9acd8cc4931f35691088db974f8401764ad7f26c6
7e7a31c2a5d1e6e6d2df49db9b036f4e3e98ab05e0ef3c5de3941722c2f0fe1ab798
ac30941ee81d026172
Output = 1420e3eae70caa328dad54098c86685fa8e538725447206bbc9b1b58034
45f852a60c8c25965b191a80cba80e43810bac1a47a79a57f29e9002989bf4bf485c
f
~~~

### VOPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 00bc68e70b02ec4df9f21f3d96e573b9108a6514ebfa73693e6512eb2ed54
58cfb2ac60061b845ec7e62d7860bdae2a7dfc00f8f3b17c447f80c080015890f0f8
6f9
pkSm = 030006d73227fd4ab3be05c0e1a2abe4f096c6e4b3ad9e0891d184e8ee5e5
ebcac3aea5d1b14cff3cde344f54d448e6afacf0fc9bdf8192f4d6773832000e6df3
fc527
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
EvaluationElement = 0201f29281468ddafbd483c11a1c362c8438da1eef031de3
f062aedffa59f4398f777d58334839fe49b5547d1ff40081ef4e70ac18cf6f8929ef
448d242206db317424
Proof = 00938eb0fbc789e2c77e9b204291aa776ccad8725db90025d19a7ccb74d7
d4701a64113e48ca1dfb7ae1f103640bf6474b852803224b84a590163af4078bdcfb
01ff007a30abdba075201d14ab3c9a2d8ff6cca5b90fdfee5c7ec75fbfef8e0b222c
fbb7173f44a7a414b99fc15b9b73ecc3f8bd16dc7ace76f92fb29e118f1363ea4b1f
ProofRandomScalar = 00eba4687426b0b4f35c14eb2477c52e1ffe177f193a485c
ccf5018abbf875b8e81c5ade0def4fe6fa8dfc15388367a60f23616cd1468dae6018
75f7dd570624d0af
Output = ce8b11de316008b15ad8f2295cb8a09f9b9b6264bba8437d720aab037ae
fd7417c765a7f8006961b2467af689ace7a07a61fd4bca0488b5989bbb463375e82f
1
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
EvaluationElement = 0300fb941d7bb2badc61a305923502081d41571d6e3b7853
944d01f5163e97edd3f487174a0f43c4802834a5b7c66ae4b8b2c06cd3c3c4bd77a9
0b32b7239f1e8a8398
Proof = 0152a006a087c67f1cadc1f64353d481eaaff46639ae41f492c62739cbf0
402d49dd49216eee71ee754f090f56c5916c6467ae53f398fef125167c348de23d34
1485004d307ae10cd780065f9feb1bc7863797853acba07ac1ca80d27843576d0601
93dc8f0acf4b1c10bc61d4c1f2db2ad18ea8051cf4f796c82e2221cf0b37d0606011
ProofRandomScalar = 0165aa02c8e46a9e48f3e2ee00241f9a75f3f7493200a8a6
05644334de4987fb60d9aaec15b54fc65ef1e10520556b43938fbf81d4fbc8c36d78
7161fa4f1e6cf4f9
Output = a97f09badaed99e75eff51a6b71756d53e3ace64dc70a0a38a4ac236068
7610b22f4aa0a329894fcfcd9e33d189674481b42c8301a31b2c581919f160df439c
f
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
EvaluationElement = 020084968738ad8157b1dfa93deb8824c63ad30eb4208429
19c0a24d047ef5e6e5d03e4f2beb703e5ad894b556224ae349548a00644bb68f045c
956f5d0bc5c3eca3ac,03011b50669cf6fc826f9c7e90dba3b6c4653cd2dbeae2f44
30cbae0685d846380889728fb3ea8d629b48b44e4f8cdfdd1dc6a765268456cadcf6
96ebeb80ccd76a7ad
Proof = 00b3eb3856e516103aa574b90f88badf22dbe70b554bef5fed5a1d90fe38
384f285ffa1f8152578088a165cc33e6eb289f597dd695a591264d0bd6f6aca315f3
7e3500cb2ddc1a2ec69e4359040ad9b16e6b19f3cb0f30fb56b3f812538faf668efc
6ae9732d478441a094d0a3c79218269cc93ef115430a7655a81b6bde70d8aeea0767
ProofRandomScalar = 00ac8346e02cbdf55c95ef9b1aadda5ef280cfa46891dfa6
64a785675b2c95bbc2412ceae9d69a186038345f8ff704bc925f6818500615a825a9
a6b5646a4e4f11b2
Output = ce8b11de316008b15ad8f2295cb8a09f9b9b6264bba8437d720aab037ae
fd7417c765a7f8006961b2467af689ace7a07a61fd4bca0488b5989bbb463375e82f
1,a97f09badaed99e75eff51a6b71756d53e3ace64dc70a0a38a4ac2360687610b22
f4aa0a329894fcfcd9e33d189674481b42c8301a31b2c581919f160df439cf
~~~

### POPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 01fe35aa65af93366c1db9a960570ff5993c70f156be6f4e557ae0904d845
34118c0af1bf59272f3abbd5ba8f59c6b9c32c23eb374c70022481e5ddfbdd51593e
9ef
pkSm = 0301b5ff57c0106d863442aef4007c4d2fce21d8a27115053a45ddf2e24fd
dbd31dbd4dc49110397c435a802f71c154c02f63a46ec7918d673ab7f790846d46f5
43da4
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
EvaluationElement = 03009dfaa6a53820a8a341ed3db8f78beea402cafc3f00a6
7ed1c641fd35e608fc85227155cdfb3ab8fd8fa58c993a26629f1593b451edf0547a
48bc9ee5da70e7cd5d
Proof = 011146c3dc5f34282f0c98318f74a1d0bc42bf1577c02eaeb6afd90be923
33569d786b8866befcc79bfd03a1f7c3a669d9729c733c7205399455e07430f52ee6
94740000495ed7e5c5d9a262faf6f060be04939259a1c08d73e7590d1a86dfb70b95
b85b1890f003eded7ba473f58088b65a6a202aa06b55ab8a8bacb1c8ec28c4bf19f5
ProofRandomScalar = 008492e4dc9cd7f7aebfb1d3d2b8c7fa7904503aef20c694
a01d3e1154fe98e7232be9eaec5789a012a559367b1f99654ddef5acc7b0dbee75bc
d8bb50363ec64004
Output = da3b4c7a4a2582e2f75e4e2dd3ee4fe9afd3c81995d3b12aa7f64b95d6c
e7fa20345f6bbec7df87966ad6474778b034f0bbbd2c9be5e710b4debb0ff9a9df3a
0
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
EvaluationElement = 0301da7d4f94bfa60caf9b02a7bad7b2e87f23d60c615b2e
74502a7815b4c4e365e2b941aa795de5201740dfb9298fa411b556c5a56a14c1cc2f
1cddaceb0b3c904b69
Proof = 00e680db433341669256873ea7b9bc0e590181d2479ff5ca149737ae8050
184de218529603e37ce625accd1ba49f83adccf2227dd31352e286a20eaae5619685
86f70138bc09ab9cd56292781ad1373b995c7c8107d9264d83d65923ca580e536c3e
b32c71631705b8d4c6d84bbe33f4af77ad9377a941ed4eda756ea06d75ba36dfd734
ProofRandomScalar = 008c15ac9ea0f8380dcce04b4c70b85f82bd8d1806c3f85d
aa0e690689a7ed6faa65712283a076c4eaee988dcf39d6775f3feee6a4376b45efbc
57c5f087181c9f04
Output = e60f8aa545f90988c9806f4c1d25a739b3c93138ee93c9760ba6870d8e6
141a5ea7150045eb039a4d88ee1905cdd80f3275347f6483d6d747742a068b58f8e8
3
~~~
