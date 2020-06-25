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
function with a private key k on input x. Roughly, F is pseudorandom if the
output y = F(k, x) is indistinguishable from uniformly sampling any
element in F's range for random choice of k. An oblivious PRF (OPRF) is
a two-party protocol between a Server and a Client, where Server holds a
PRF key k and Client holds some input x. The protocol allows both
parties to cooperate in computing F(k, x) with Server's secret key k and
Client's input x such that: Client learns F(k, x) without learning
anything about k; and P does not learn anything about x. A Verifiable
OPRF (VOPRF) is an OPRF wherein Client can prove to Server that F(k, x)
was computed using key k, which is bound to a trusted public key Y = k *
G, and G is the generator of a group. Informally, this is done by
presenting a non-interactive zero-knowledge (NIZK) proof of equality
between (G, Y) and (Z, M), where Z and M are group elements such that Z
= k * M.

OPRFs have been shown to be useful for constructing: password-protected
secret sharing schemes {{JKK14}}; privacy-preserving password stores
{{SJKS17}}; and password-authenticated key exchange or PAKE {{OPAQUE}}.
VOPRFs are useful for producing tokens that are verifiable by Client.
This may be needed, for example, if Client wants assurance that Server
did not use a unique key in its computation, i.e., if Client wants key
consistency from Server. This property is necessary in some
applications, e.g., the Privacy Pass protocol {{PrivacyPass}}, wherein
this VOPRF is used to generate one-time authentication tokens to bypass
CAPTCHA challenges. VOPRFs have also been used for password-protected
secret sharing schemes e.g. {{JKKX16}}.

This document introduces an OPRF protocol built in prime-order groups,
applying to finite fields of prime-order and also elliptic curve (EC)
groups. The protocol has the option of being extended to a VOPRF with
the addition of a NIZK proof for proving discrete log equality
relations. This proof demonstrates correctness of the computation using
a known public key that serves as a commitment to the server's secret
key. The document describes the protocol, its security properties, and
provides preliminary test vectors for experimentation. The rest of the
document is structured as follows:

- {{background}}: Describe background, related work, and use cases of
  OPRF/VOPRF protocols.
- {{preliminaries}}: Describe conventions and assumptions made relating
  to security of (V)OPRFs and prime-order group instantiations.
- {{protocol}}: Specify the protocol required to instantiate the (V)OPRF
  functionality via prime-order groups. Includes specification of the
  data structures and API that is used by the client and server.
- {{ciphersuites}}: Considers explicit instantiations of the protocol in
  the elliptic curve setting.
- {{sec}}: Discusses the security considerations for the OPRF and VOPRF
  protocol.
- {{apps}}: Discusses some existing applications of OPRF and VOPRF
  protocols.

## Change log

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
- Client: Protocol initiator, eventually learns pseudorandom function
  evaluation as the output of the protocol.
- Server: Computes the pseudorandom function over a secret key, learns
  nothing about the client's input.
- NIZK: Non-interactive zero knowledge.
- DLEQ: Discrete Logarithm Equality.

## Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}.

# Background {#background}

OPRFs are functionally related to blind signature schemes. In such a
scheme, a client can receive signatures on private data, under the
signing key of some server. The security properties of such a scheme
dictate that the client learns nothing about the signing key, and that
the server learns nothing about the data that is signed. One of the more
popular blind signature schemes is based on the RSA cryptosystem and is
known as Blind RSA {{ChaumBlindSignature}}.

OPRF protocols can thought of as symmetric alternatives to blind
signatures. Essentially the client learns y = PRF(k,x) for some input x
of their choice, from a server that holds k. Since the security of an
OPRF means that x is hidden in the interaction, then the client can
later reveal x to the server along with y.

The server can verify that y is computed correctly by recomputing the
PRF on x using k. In doing so, the client provides knowledge of a
'signature' y for their value x. The verification procedure is thus
symmetric as it requires knowledge of the key k. This is discussed more
in the following section.

# Preliminaries

## Prime-order group API {#pog}

In this document, we assume the construction of an additive, prime-order
group `GG` for performing all mathematical operations. Such groups are
uniquely determined by the choice of the prime `p` that defines the
order of the group. We use `GF(p)` to represent the finite field of
order `p`. For the purpose of understanding and implementing this
document, we take `GF(p)` to be equal to the set of integers defined by
`{0, 1, ..., p-1}`.

The fundamental group operation is addition `+` with identity element `I`.
For any elements `A` and `B` of the group `GG`, `A + B = B + A` is also a
member of `GG`. Also, for any `A` in `GG`, it exists an element `-A` such
that `A + (-A) = (-A) + A = I`. Scalar multiplication refers to the repeated
application of the group operation on an element A with itself `r-1` times,
this is denoted as `r*A = A + ... + A`. Any element `A` holds the equality
`p*A=I`. The set of scalars corresponds to `GF(p)`.

We now detail a number of member functions that can be invoked on a
prime-order group.

- Order(): Outputs the order of the group (i.e. `p`).
- Generator(): Outputs a fixed generator `G` for the group.
- Identity(): Outputs the identity element of the group (i.e. `I`).
- Serialize(A): A member function of `GG` that maps a group element `A`
  to a unique byte arrays `buf` that corresponds uniquely to the
  element `A`.
- Deserialize(buf): A member function of `GG` that maps an byte arrays
  `buf` to a group element `A`.
- HashToGroup(x): A member function of `GG` that deterministically maps
  an array of bytes `x` to an element of `GG`. The map must ensure that
  for any adversary receiving `R = HashToGroup(x)` be computationally
  difficult to reverse the mapping. Examples of hash to group functions
  satisfying this property are the ones described for prime-order
  (sub)groups of elliptic curves, see {{I-D.irtf-cfrg-hash-to-curve}}.
- HashToScalar(x): A member function of `GG` that deterministically maps
  an array of bytes `x` to a random element in GF(p).
- RandomScalar(): A member function of `GG` that generates a random, non-zero
  element in GF(p).

It is convenient in cryptographic applications to instantiate such
prime-order groups using elliptic curves, such as those detailed in
{{SEC2}}. For some choices of elliptic curves (e.g. those detailed in
{{RFC7748}} require accounting for cofactors) there are some
implementation issues that introduce inherent discrepancies between
standard prime-order groups and the elliptic curve instantiation. In
this document, all algorithms that we detail assume that the group is a
prime-order group, and this MUST be upheld by any implementer. That is,
any curve instantiation should be written such that any discrepancies
with a prime-order group instantiation are removed. In the case of
cofactors, for example, this can be done by building cofactor
multiplication into all elliptic curve operations.

## Other conventions

- We use the notation `x <-$ Q` to denote sampling `x` from the uniform
  distribution over the set `Q`.
- For two byte arrays `x` and `y`, write `x || y` to denote their
  concatenation.
- We assume that all numbers are stored in big-endian orientation.
- All algorithm descriptions are written in a Python-like pseudocode.
  We use the `ABORT()` function for presentation clarity to denote
  the process of terminating the algorithm or returning an error accordingly.

# OPRF Protocol {#protocol}

In this section, we define two OPRF variants: a base mode and verifiable mode.
In the base mode, a client and server interact to compute y = F(skS, x), where
x is the client's input, skS is the server's private key, and y is the OPRF output.
The client learns y and the server learns nothing. In the verifiable mode, the
client also gets proof that the server used skS in computing the function.

As in the original work of {{JKK14}}, we provide a zero-knowledge proof that the
key provided as input by the server in the `Evaluate` function is the
same key as it used to produce their public key. As an example of the nature
of attacks that this prevents, this ensures that Server uses the same private key
for computing the VOPRF output and does not attempt to "tag" individual Servers
with select keys. This proof must not reveal Server's long-term private key to Client.

The following one-byte values distinguish between these two modes:

| Mode            | Value |
|:================|:======|
| modeBase       | 0x00  |
| modeVerifiable | 0x01  |

## Overview

Both participants agree on the mode and a choice of ciphersuite that is used
before the protocol exchange. Once established, the core protocol works
as follows:

~~~
   Client(inputs, pkS, info)                 Server(skS, pkS)
  ----------------------------------------------------------
    tokens, blindTokens = Blind(inputs)

                        blindTokens
                        ---------->

                         evaluation = Evaluate(skS, pkS, blindTokens)

                         evaluation
                        <----------

    issuedTokens = Unblind(pkS, tokens, blindTokens, evaluation)
    outputs = []
    for i in range(inputs.length):
     outputs[i] = Finalize(inputs[i], issuedTokens[i], info)
    Output outputs
~~~

In `Blind` the client generates the tokens and blinding data. The Server
computes the (V)OPRF evaluation in `Evaluation` over the client's
blinded tokens. In `Unblind` the client unblinds the server response
(and verifies the Server's proof if verifiability is required). In
`Finalize`, the client outputs a byte array corresponding to each token
that was evaluated over.

Note that in the final output, the client computes Finalize over some
auxiliary input data `info`. This parameter SHOULD be used for domain
separation in the (V)OPRF protocol. Specifically, any system which has
multiple (V)OPRF applications should use separate auxiliary values to to
ensure finalized outputs are separate. Guidance for constructing info can
be found in {{I-D.irtf-cfrg-hash-to-curve}}; Section 3.1.

## Context Setup

Both modes of the OPRF involve an offline setup phase which establishes a context
used by the client or server in executing the online phase of the protocol.

~~~
def SetupBaseServer(suite):
  (skS, _) = KeyGen(GG)
  contextString = I2OSP(modeBase, 1) + I2OSP(suite.ID, 2)
  return ServerContext(contextString, skS)

def SetupBaseClient(suite):
  contextString = I2OSP(modeBase, 1) + I2OSP(suite.ID, 2)
  return ClientContext(contextString)

def SetupVerifiableServer(suite):
  (skS, pkS) = KeyGen(GG)
  contextString = I2OSP(modeVerifiable, 1) + I2OSP(suite.ID, 2)
  return VerifiableServerContext(contextString, skS), pkS

def SetupVerifiableClient(suite, pkS):
  contextString = I2OSP(modeVerifiable, 1) + I2OSP(suite.ID, 2)
  return VerifiableClientContext(contextString, pkS)
~~~

The `KeyGen` function used above takes a group `GG` and generates a private and public
key pair (skX, pkX), where skX is a random, non-zero element in the scalar field `GG`
and pkX is the product of skX and the group's fixed generator. For verifiable
modes, servers MUST make the resulting public key `pkS` accessible for clients.
(Indeed, it is a required parameter when configuring a verifiable client context.)

Each setup function takes a ciphersuite from the list defined in
{{ciphersuites}}. Each ciphersuite has two-byte identifier, referred
to as `suite.ID` in the pseudocode above, that identifies the suite.
{{ciphersuites}} lists these ciphersuite identifiers.

## Data Structures {#structs}

The following is a list of data structures that are defined for
providing inputs and outputs for each of the context interfaces
defined in {{api}}.

The following types are a list of aliases that are used throughout the
protocol.

A `ClientInput` is a byte array.

~~~
opaque ClientInput<1..2^16-1>;
~~~

A `SerializedElement` is also a byte array, representing the unique serialization
of an `Element`.

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
member `proof` is added only in the case where verifiability is
required.

~~~
struct {
  SerializedElement elements<1..2^16-1>;
  Scalar proof[2]; /* only for modeVerifiable */
} Evaluation;
~~~

## Context APIs {#api}

In this section, we detail the APIs available on the client and server
OPRF contexts. This document uses the types `Element` and `Scalar` to
denote elements of the group `GG` and its underlying scalar field,
respectively. For notational clarity, `PublicKey` and `PrivateKey` are items
of type `Element` and `Scalar`, respectively.

### Server Context

The ServerContext encapsulates the context string constructed during setup and
the OPRF key pair. It has a single function, `Evaluate()`, described below.

#### Evaluate

~~~
Input:

  PrivateKey skS
  PublicKey pkS
  SerializedElement blindedTokens[m]

Output:

  Evaluation Ev

def Evaluate(skS, pkS, blindedTokens):
  elements = []
  for i in 1..m:
    BT = GG.Deserialize(blindedTokens[i])
    Z = skS * BT
    elements[i] = GG.Serialize(Z)
  Ev = Evaluation{ elements: elements }
  return Ev
~~~

### Verifiable Server Context

The VerifiableServerContext extends the base ServerContext with an augmented
`Evaluate()` function. This function produces a proof that `skS` was used
in computing the result. It makes use of the helper functions `ComputeComposites`
and `GenerateProof`, described below.

#### Evaluate

~~~
Input:

  PrivateKey skS
  PublicKey pkS
  SerializedElement blindedTokens[m]

Output:

  Evaluation Ev

def Evaluate(skS, pkS, blindedTokens, Ev):
  elements = []
  for i in 1..m:
    BT = GG.Deserialize(blindedTokens[i])
    Z = skS * BT
    elements[i] = GG.Serialize(Z)
  proof = GenerateProof(skS, pkS, blindedTokens, Ev)
  Ev = Evaluation{ elements: elements, proof: proof }
  return Ev
~~~

The helper functions `GenerateProof` and `ComputeComposites`
are defined below.

#### GenerateProof

~~~
Input:

  PrivateKey skS
  PublicKey pkS
  SerializedElement blindedTokens[m]
  Evaluation ev

Output:

  Scalar proof[2]

def GenerateProof(skS, pkS, blindedTokens, ev)
  G = GG.Generator()
  gen = GG.Serialize(G)
  (a1, a2) = ComputeComposites(gen, pkS, blindedTokens, ev)
  M = GG.Deserialize(a1)
  r = GG.RandomScalar()
  a3 = GG.Serialize(r * G)
  a4 = GG.Serialize(r * M)

  challengeDST = "RFCXXXX-challenge-" + self.contextString
  h2Input = I2OSP(len(gen), 2) || gen ||
            I2OSP(len(pkS), 2) || pkS ||
            I2OSP(len(a1), 2) || a1 || I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 || I2OSP(len(a4), 2) || a4 ||
            I2OSP(len(challengeDST), 2) || challengeDST

  c = GG.HashToScalar(h2Input)
  s = (r - c * skS) mod p
  return (c, s)
~~~

We note here that it is essential that a different r value is used for
every invocation. If this is not done, then this may leak `skS` in a
similar fashion as is possible in Schnorr or (EC)DSA scenarios where
fresh randomness is not used.

#### ComputeComposites

~~~
Input:

  SerializedElement gen
  PublicKey pkS
  SerializedElement blindedTokens[m]
  SerializedElement elements

Output:

  SerializedElement composites[2]

def ComputeComposites(gen, pkS, blindedTokens, ev):
  seedDST = "RFCXXXX-seed-" + self.contextString
  compositeDST = "RFCXXXX-composite-" + self.contextString
  h1Input = I2OSP(len(gen), 2) || gen ||
            I2OSP(len(pkS), 2) || pkS ||
            I2OSP(len(blindedTokens), 2) || blindedTokens ||
            I2OSP(len(elements), 2) || elements ||
            I2OSP(len(seedDST), 2) || seedDST

  seed = Hash(h1Input)
  M = GG.Identity()
  Z = GG.Identity()
  for i = 0 to m:
    h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
              I2OSP(len(compositeDST), 2) || compositeDST
    di = GG.HashToScalar(h2Input)
    Mi = GG.Deserialize(blindedTokens[i])
    Zi = GG.Deserialize(ev.elements[i])
    M = di * Mi + M
    Z = di * Zi + Z
 return [GG.Serialize(M), GG.Serialize(Z)]
~~~

### Client Context

The ClientContext encapsulates the context string constructed during setup.
It has three functions, `Blind()`, `Unblind()`, and `Finalize()`, as described
below.

#### Blind

We note here that the blinding mechanism that we use can be modified
slightly with the opportunity for making performance gains in some
scenarios. We detail these modifications in {{blinding}}.

~~~
Input:

  ClientInput inputs[m]

Output:

  Token tokens[m]
  SerializedElement blindedTokens[m]

def Blind(inputs):
  tokens = []
  blindedTokens = []
  for i = 0 to m:
    r = GG.RandomScalar()
    P = GG.HashToGroup(inputs[i])
    tokens[i] = Token{ data: x, blind: r }
    blindedTokens[i] = GG.Serialize(r * P)
 return (tokens, blindedTokens)
~~~

#### Unblind

~~~
Input:

  PublicKey pkS
  Token tokens[m]
  SerializedElement blindedTokens[m]
  Evaluation Ev

Output:

  SerializedElement unblindedTokens[m]

def Unblind(pkS, tokens, blindedTokens, Ev):
  unblindedTokens = []
  for i = 0 to m:
    r = tokens[i].blind
    Z = GG.Deserialize(Ev.elements[i])
    N = (r^(-1)) * Z
    unblindedTokens[i] = GG.Serialize(N)
 return unblindedTokens
~~~

#### Finalize

~~~
Input:

  Token T
  SerializedElement E
  opaque info<1..2^16-1>

Output:

  opaque output<1..2^16-1>

def Finalize(T, E, info):
  finalizeDST = "RFCXXXX-Finalize-" + self.contextString
  hashInput = len(T.data) || T.data ||
              len(E) || E ||
              len(info) || info ||
              len(finalizeDST) || finalizeDST
  return Hash(hashInput)
~~~

### Verifiable Client Context {#verifiable-client}

The VerifiableClientContext extends the base ClientContext with the desired
server public key `pkS` with an augmented `Unblind()` function. This function
verifies an evaluation proof using `pkS`. It makes use of the helper function
`ComputeComposites` described above. It has one helper function, `VerifyProof()`,
defined below.

#### VerifyProof

This algorithm outputs a boolean `verified` which indicates whether the
proof inside of the evaluation verifies correctly, or not.

~~~
Input:

  PublicKey pkS
  SerializedElement blindedTokens[m]
  Evaluation Ev

Output:

  boolean verified

def VerifyProof(pkS, blindedTokens, Ev):
  G = GG.Generator()
  gen = GG.Serialize(G)
  (a1, a2) = ComputeComposites(gen, pkS, blindedTokens, Ev)
  A' = (Ev.proof[1] * G + Ev.proof[0] * pkS)
  B' = (Ev.proof[1] * M + Ev.proof[0] * Z)
  a3 = GG.Serialize(A')
  a4 = GG.Serialize(B')

  challengeDST = "RFCXXXX-challenge-" + self.contextString
  h2Input = I2OSP(len(gen), 2) || gen ||
            I2OSP(len(pkS), 2) || pkS ||
            I2OSP(len(a1), 2) || a1 ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            I2OSP(len(a4), 2) || a4 ||
            I2OSP(len(challengeDST), 2) || challengeDST

  c  = GG.HashToScalar(h2Input)
  return (c == Ev.proof[0] mod p)
~~~

#### Unblind

~~~
Input:

  PublicKey pkS
  Token tokens[m]
  SerializedElement blindedTokens[m]
  Evaluation Ev

Output:

  SerializedElement unblindedTokens[m]

def Unblind(pkS, tokens, blindedTokens, Ev):
  if VerifyProof(pkS, blindedTokens, Ev) == false:
    ABORT()

  unblindedTokens = []
  for i = 0 to m:
    r = tokens[i].blind
    Z = GG.Deserialize(Ev.elements[i])
    N = (r^(-1)) * Z
    unblindedTokens[i] = GG.Serialize(N)
 return unblindedTokens
~~~

# Ciphersuites {#ciphersuites}

A ciphersuite for the protocol wraps the functionality required for the
protocol to take place. This ciphersuite should be available to both
Client and Server, and agreement on the specific instantiation is
assumed throughout. A ciphersuite contains instantiations of the
following functionalities.

- `GG`: A prime-order group exposing the API detailed in {{pog}}.
- `Hash`: A cryptographic hash function that is indifferentiable from
  a Random Oracle.

This section specifies supported VOPRF group and hash function
instantiations. For each group, we specify the HashToGroup and Serialize functionalities.
The Deserialize functionality is the inverse of the corresponding Serialize functionality.

We only provide ciphersuites in the elliptic curve setting as these provide an  efficient way of
instantiating the OPRF. Our instantiation includes considerations for providing the DLEQ
proofs that make the instantiation a VOPRF. Supporting OPRF operations alone can be
allowed by simply dropping the relevant components.

Applications should take caution in using ciphersuites targeting P-256 and
curve25519. See {{cryptanalysis}} for related discussion.

## OPRF(curve25519, SHA-512)

- Group:
  - Elliptic curve: curve25519 {{RFC7748}}
  - Generator(): Return the point with the following affine coordinates:
    - x = `09`
    - y = `20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9`
  - HashToGroup(): curve25519_XMD:SHA-512_ELL2_RO_ {{I-D.irtf-cfrg-hash-to-curve}} with DST "RFCXXXX-curve25519_XMD:SHA-512_ELL2_RO_"
  - Serialization: The standard 32-byte representation of the public key {{!RFC7748}}
  - Order(): Returns `1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED`
  - Addition: Adding curve points directly corresponds to the group
    addition operation.
  - Scalar multiplication: Implementers must validate all untrusted
    input points to the scalar multiplication algorithm. Validation
    consists of checking that input points are members of the
    prime-order subgroup of the curve. See {{RFC7748}} for more details.
- Hash: SHA-512
- ID: 0x0001

## OPRF(curve448, SHA-512)

- Group:
  - Elliptic curve: curve448 {{RFC7748}}
  - Generator(): Return the point with the following affine coordinates:
    - x = `05`
    - y = `7D235D1295F5B1F66C98AB6E58326FCECBAE5D34F55545D060F75DC28DF3F6EDB8027E2346430D211312C4B150677AF76FD7223D457B5B1A`
  - HashToGroup(): curve448_XMD:SHA-512_ELL2_RO_ {{I-D.irtf-cfrg-hash-to-curve}} with DST "RFCXXXX-curve448_XMD:SHA-512_ELL2_RO_"
  - Serialization: The standard 56-byte representation of the public key {{!RFC7748}}
  - Order(): Returns `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF`
  - Addition: Adding curve points directly corresponds to the group
    addition operation.
  - Scalar multiplication: Implementers must validate all untrusted
    input points to the scalar multiplication algorithm. Validation
    consists of checking that input points are members of the
    prime-order subgroup of the curve. See {{RFC7748}} for more details.
- Hash: SHA-512
- ID: 0x0002

## OPRF(P-256, SHA-512)

- Group:
  - Elliptic curve: P-256 (secp256r1) {{x9.62}}
  - Generator(): Return the point with the following affine coordinates:
    - x = `6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296`
    - y = `4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5`
  - HashToGroup(): P256_XMD:SHA-256_SSWU_RO_ {{I-D.irtf-cfrg-hash-to-curve}} with DST "RFCXXXX-P256_XMD:SHA-256_SSWU_RO_"
  - Serialization: The compressed point encoding for the curve {{SEC1}} consisting of 33 bytes.
  - Order(): Returns `FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551`
  - Addition: Adding curve points directly corresponds to the group
    addition operation.
  - Scalar multiplication: Scalar multiplication of curve points
    directly corresponds with scalar multiplication in the group.
- Hash: SHA-512
- ID: 0x0003

## OPRF(P-384, SHA-512)

- Group:
  - Elliptic curve: P-384 (secp384r1) {{x9.62}}
  - Generator(): Return the point with the following affine coordinates:
    - x = `AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7`
    - y = `3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F`
  - HashToGroup(): P384_XMD:SHA-512_SSWU_RO_ {{I-D.irtf-cfrg-hash-to-curve}} with DST "RFCXXXX-P384_XMD:SHA-512_SSWU_RO_"
  - Serialization: The compressed point encoding for the curve {{SEC1}} consisting of 49 bytes.
  - Order(): Returns `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973`
  - Addition: Adding curve points directly corresponds to the group
    addition operation.
  - Scalar multiplication: Scalar multiplication of curve points
    directly corresponds with scalar multiplication in the group.
- Hash: SHA-512
- ID: 0x0004

## OPRF(P-521, SHA-512)

- Group:
  - Elliptic curve: P-521 (secp521r1) {{x9.62}}
  - Generator(): Return the point with the following affine coordinates:
    - x = `00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66`
    - y = `011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650`
  - HashToGroup(): P521_XMD:SHA-512_SSWU_RO_ {{I-D.irtf-cfrg-hash-to-curve}} with DST "RFCXXXX-P521_XMD:SHA-512_SSWU_RO_"
  - Serialization: The compressed point encoding for the curve {{SEC1}} consisting of 67 bytes.
  - Order(): Returns `1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409`
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

In other words, for an adversary that can pick inputs x from the domain
of F and can evaluate F on (k,x) (without knowledge of randomly sampled
k), then the output distribution F(k,x) is indistinguishable from the
uniform distribution in the range of F.

A consequence of showing that a function is pseudorandom, is that it is
necessarily non-malleable (i.e. we cannot compute a new evaluation of F
from an existing evaluation). A genuinely random function will be
non-malleable with high probability, and so a pseudorandom function must
be non-malleable to maintain indistinguishability.

An OPRF protocol must also satisfy the following property:

- Oblivious: Server must learn nothing about Client's input or the
  output of the function. In addition, Client must learn nothing about
  Server's private key.

Essentially, obliviousness tells us that, even if Server learns Client's
input x at some point in the future, then Server will not be able to
link any particular OPRF evaluation to x. This property is also known as
unlinkability {{DGSTV18}}.

Optionally, for any protocol that satisfies the above properties, there
is an additional security property:

- Verifiable: Client must only complete execution of the protocol if it
  can successfully assert that the OPRF output it computes is correct,
  with respect to the OPRF key held by Server.

Any OPRF that satisfies the 'verifiable' security property is known as a
verifiable OPRF, or VOPRF for short. In practice, the notion of
verifiability requires that Server commits to the key before the
actual protocol execution takes place. Then Client verifies that Server
has used the key in the protocol using this commitment. In the
following, we may also refer to this commitment as a public key.

## Cryptographic security {#cryptanalysis}

Below, we discuss the cryptographic security of the (V)OPRF protocol from
{{protocol}}, relative to the necessary cryptographic assumptions that
need to be made.

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
can perform multiple VOPRF evaluations in one go, whilst only constructing
one NIZK proof object. This is enabled using an established batching technique.

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
composability (UC) security model. Without the NIZK proof system, the
protocol instantiates an OPRF protocol only. See the paper for further
details.

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
128 bits of security. Then an adversary with access to a Q-sDH oracle
and makes Q=2^20 queries can reduce the security of the instantiation by
log_2(2^20) = 20 bits.

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

While it would require an informed and persistent attacker to launch a
highly expensive attack to reduce security to anything much below 100
bits of security, we see this possibility as something that may result
in problems in the future. Therefore, all of our ciphersuites in
{{ciphersuites}} come with a minimum group instantiation corresponding
to 196 bits of security. This would require an adversary to launch a
minimum of Q = 2^(68) queries to reduce security to 128 bits using the
Q-sDH attacks. As a result, it appears prohibitively expensive to launch
credible attacks on these parameters with our current understanding of
the attack surface.

## Hashing to curve

A critical aspect of implementing this protocol using elliptic curve
group instantiations is a method of instantiating the function Hash, that
maps inputs to group elements. In the elliptic curve setting, this must
be a deterministic function that maps arbitrary inputs x (as bytes) to
uniformly chosen points in the curve.

In the security proof of the construction Hash is modeled as a random
oracle. This implies that any instantiation of Hash must be pre-image and
collision resistant. In {{ciphersuites}} we give instantiations of this
functionality based on the functions described in
{{I-D.irtf-cfrg-hash-to-curve}}. Consequently, any OPRF implementation
must adhere to the implementation and security considerations discussed
in {{I-D.irtf-cfrg-hash-to-curve}} when instantiating the function Hash.

## Timing Leaks

To ensure no information is leaked during protocol execution, all
operations that use secret data MUST be constant time. Operations that
SHOULD be constant time include all prime-order group operations and
proof-specific operations (`GenerateProof()` and `VerifyProof()`). As
mentioned previously, {{I-D.irtf-cfrg-hash-to-curve}} describes various
algorithms for constant-time implementations of the `GG.HashToGroup()`
functionality.

## User segregation

The aim of the OPRF functionality is to allow clients receive
pseudorandom function evaluations on their own inputs, without
compromising their own privacy with respect to the server. In many
applications (for example, {{PrivacyPass}}) the client may choose to
reveal their original input, after an invocation of the OPRF protocol,
along with their OPRF output. This can prove to the server that it has
received a valid OPRF output in the past. Since the server does not
reveal learn anything about the OPRF output, it should not be able to
link the client to any previous protocol instantiation.

Consider a malicious server that manages to segregate the user base into
different sets. Then this reduces the effective privacy of all of the
clients involved, since the client above belongs to a smaller set of
users than previously hoped. In general, if the user-base of the OPRF
functionality is quite small, then the obliviousness of clients is
limited. That is, smaller user-bases mean that the server is able to
identify client's with higher certainty.

In summary, an OPRF instantiation effectively comes with an additional
privacy parameter pp. If all clients of the OPRF make one query and then
subsequently reveal their OPRF input afterwards, then the server should
be link the revealed input to a protocol instantiation with probability
1/pp.

Below, we provide a few techniques that could be used to abuse
client-privacy in the OPRF construction by segregating the user-base,
along with some mitigations.

### Linkage patterns

If the server is able to ascertain patterns of usage for some clients --
such as timings associated with usage -- then the effective privacy of
the clients is reduced to the number of users that fit each usage
pattern. Along with early registration patterns, where early adopters
initially have less privacy due to a low number of registered users,
such problems are inherent to any anonymity-preserving system.

### Evaluation on multiple keys {#multiple-keys}

Such an attack consists of the server evaluating the OPRF on multiple
different keys related to the number of clients that use the
functionality. As an extreme, the server could evaluate the OPRF with a
different key for each client. If the client then revealed their hidden
information at a later date then the server would immediately know which
initial request they launched.

The VOPRF variant helps mitigate this attack since each server
evaluation can be bound to a known public key. However, there are still
ways that the VOPRF construction can be abused. In particular:

- If the server successfully provisions a large number of keys that are
  trusted by clients, then the server can divide the user-base by the
  number of keys that are currently in use. As such, clients should only
  trust a small number (2 or 3 ideally) of server keys at any one time.
  Additionally, a tamper-proof audit log system akin to existing work on
  Key Transparency {{keytrans}} could be used to ensure that a server is
  abiding by the key policy. This would force the server to be held
  accountable for their key updates, and thus higher key update
  frequencies can be better managed on the client-side.

- If the server rotates their key frequently, then this may result in
  client's holding out-of-date information from a past interaction. Such
  information can also be used to segregate the user-base based on the
  last time that they accessed the OPRF protocol. Similarly to the
  above, server key rotations must be kept to relatively infrequent
  intervals (such as once per month). This will prevent too many clients
  from being segregated into different groups related to the time that
  they accessed the functionality. There are viable reasons for rotating
  the server key (for protecting against malicious clients) that we
  address more closely in {{key-rotation}}.

Since key provisioning requires careful handling, all public keys should
be accessible from a client-trusted registry with a way of auditing the
history of key updates. We also recommend that public keys have a
corresponding expiry date that clients can use to prevent the server
from using keys that have been provisioned for a long period of time.

## Key rotation {#key-rotation}

Since the server's key is critical to security, the longer it is exposed
by performing (V)OPRF operations on client inputs, the longer it is
possible that the key can be compromised. For instance, if the key is
kept in production for a long period of time, then this may grant the
client the ability to hoard large numbers of tokens. This has negative
impacts for some of the applications that we consider in {{apps}}. As
another example, if the key is kept in circulation for a long period of
time, then it also allows the clients to make enough queries to launch
more powerful variants of the Q-sDH attacks from {{qsdh}}.

To combat attacks of this nature, regular key rotation should be
employed on the server-side. A suitable key-cycle for a key used to
compute (V)OPRF evaluations would be between one week and six months.

As we discussed in {{multiple-keys}}, key rotation cycles that are too
frequent (in the order of days) can lead to large segregation of the
wider user base. As such, the length of the key cycles represent a
trade-off between greater server key security (for shorter cycles), and
better client privacy (for longer cycles). In situations where client
privacy is paramount, longer key cycles should be employed. Otherwise,
shorter key cycles can be managed if the server uses a Key
Transparency-type system {{keytrans}}; this allows clients to publicly
audit their rotations.

# Fixed-base blinding {#blinding}

Let `H` refer to the function `GG.HashToGroup`, in {{pog}} we assume
that the client-side blinding is carried out directly on the output of
`H(x)`, i.e. computing `r * H(x)` for some `r <-$ GF(p)`. In the {{OPAQUE}}
document, it is noted that it may be more efficient to use additive
blinding rather than multiplicative if the client can preprocess some
values. For example, a valid way of computing additive blinding would be
to instead compute `H(x) + (r * G)`, where `G` is the fixed generator for the
group `GG`.

We refer to the 'multiplicative' blinding as variable-base blinding
(VBB), since the base of the blinding (`H(x)`) varies with each
instantiation. We refer to the additive blinding case as fixed-base
blinding (FBB) since the blinding is applied to the same generator each
time (when computing `r * G`).

The advantage of fixed-base blinding is that it allows the client to
pre-process tables of blinded scalar multiplications for `G`. This may
give it a computational efficiency advantage. Pre-processing also
reduces the amount of computation that needs to be done in the online
exchange. Choosing one of these values `r * G` (where `r` is the scalar
value that is used), then computing `H(x) + (r * G)` is more efficient than
computing `r * H(x)` (due to a fixed-point multiplication is calculated faster
than a variable-point multiplication). Therefore, it may be
advantageous to define the OPRF and VOPRF protocols using additive
blinding rather than multiplicative blinding. In fact, the only
algorithms that need to change are Blind and Unblind (and similarly for
the VOPRF variants).

We define the FBB variants of the algorithms in {{api}} below, along
with a new algorithm Preprocess. The Preprocess algorithm can take place
offline and before the rest of the OPRF protocol. The Blind algorithm
takes the preprocessed values as inputs, but the signature of Unblind
remains the same.

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
  uint16 m

Output:

  PrepocessedBlind preprocs[m]

def Preprocess(pkS, m):
  preprocs = []
  PK = GG.Deserialize(pkS)
  for i = 0 to m:
    r = GG.RandomScalar()
    blindedGenerator = GG.Serialize(r * GG.Generator())
    blindedPublicKey = GG.Serialize(r * PK)
    preprocs[i] = PrepocessedBlind{
      blind: r,
      blindedGenerator: blindedGenerator,
      blindedPublicKey: blindedPublicKey,
    }
 return preprocs
~~~

## Blind

~~~
Input:

  ClientInput inputs[m]
  PreprocessedBlinds preprocs[m]

Output:

  Token tokens[m]
  SerializedElement blindedTokens[m]

def Blind(inputs, preprocs):
  tokens = []
  blindedTokens = []
  for i = 0 to m:
    pre = preprocs[i]
    Q = GG.Deserialize(pre.blindedGenerator) /* Q = r * G */
    P = GG.HashToGroup(inputs[i])
    tokens[i] = Token{ data: x, blind: pre.blindedPublicKey }
    blindedTokens[i] = GG.Serialize(P + Q) /* P + r * G */
  return (tokens, blindedTokens)
~~~

## Unblind

~~~
Input:

  Token tokens[m]
  Evaluation ev
  SerializedElement blindedTokens[m]

Output:

 SerializedElement unblinded[m]

def Unblind(tokens, ev, blindedTokens):
  unblindedTokens = []
  for i = 0 to m:
    PKR = GG.Deserialize(tokens[i].blind)
    Z = GG.Deserialize(ev.elements[i])
    N := Z - PKR
    unblindedTokens[i] = GG.Serialize(N)
  return unblindedTokens
~~~

Let `P = GG.HashToGroup(x)`. Notice that Unblind computes:

~~~
Z - PKR = k * (P + r * G) - r * pkS
        = k * P + k * (r * G) - r * (k * G)
        = k * P
~~~

by the commutativity of scalar multiplication in GG. This is the same
output as in the `Unblind` algorithm for variable-based blinding.

Note that the verifiable variant of `Unblind` works as above but includes
the step to `VerifyProof`, as specified in {{verifiable-client}}.

# Applications {#apps}

This section describes various applications of the (V)OPRF protocol.

## Privacy Pass

This VOPRF protocol is used by the Privacy Pass system {{PrivacyPass}}
to help Tor users bypass CAPTCHA challenges. Their system works as
follows. Client C connects -- through Tor -- to an edge server E serving
content. Upon receipt, E serves a CAPTCHA to C, who then solves the
CAPTCHA and supplies, in response, n blinded points. E verifies the
CAPTCHA response and, if valid, signs (at most) n blinded points, which
are then returned to C along with a batched DLEQ proof. C stores the
tokens if the batched proof verifies correctly. When C attempts to
connect to E again and is prompted with a CAPTCHA, C uses one of the
tokens to derive a shared symmetric key sk used to MAC the CAPTCHA
challenge. C sends the CAPTCHA, MAC, and token input x to E, who can use
x to derive sk and verify the CAPTCHA MAC. Thus, each token is used at
most once by the system.

The Privacy Pass implementation uses the P-256 instantiation of the
VOPRF protocol. For more details, see {{DGSTV18}}.

## Private Password Checker

In this application, let D be a collection of plaintext passwords
obtained by prover P. For each password p in D, P computes Evaluate on
`GG.HashToGroup(p)`, and stores the result in a separate collection D'.
P then publishes D' with `pkS`, its public key. If a client C wishes to
query D' for a password p', it runs the VOPRF protocol using p as input
x to obtain output y. By construction, y will be the OPRF evaluation of
p hashed onto the curve. C can then search D' for y to determine if
there is a match.

Concrete examples of important applications in the password domain
include:

- password-protected storage {{JKK14}}, {{JKKX16}};
- perfectly-hiding password management {{SJKS17}};
- password-protected secret-sharing {{JKKX17}}.

### Parameter Commitments

For some applications, it may be desirable for Server to bind tokens to
certain parameters, e.g., protocol versions, ciphersuites, etc. To
accomplish this, Server should use a distinct scalar for each parameter
combination. Upon redemption of a token T from Client, Server can later
verify that T was generated using the scalar associated with the
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
