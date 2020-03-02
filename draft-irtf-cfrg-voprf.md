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
    email: adavidson@cloudflare.com
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
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: cawood@apple.com

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
--- abstract

An Oblivious Pseudorandom Function (OPRF) is a two-party protocol for computing
the output of a PRF. One party (the server) holds the PRF secret key, and the
other (the client) holds the PRF input. The 'obliviousness' property ensures
that the server does not learn anything about the client's input during the
evaluation. The client should also not learn anything about the server's secret
PRF key. Optionally, OPRFs can also satisfy a notion 'verifiability' (VOPRF). In
this setting, the client can verify that the server's output is indeed the
result of evaluating the underlying PRF with just a public key. This document
specifies OPRF and VOPRF constructions instantiated within prime-order groups,
including elliptic curves.

--- middle

# Introduction

A pseudorandom function (PRF) F(k, x) is an efficiently computable function with
secret key k on input x. Roughly, F is pseudorandom if the output y = F(k, x) is
indistinguishable from uniformly sampling any element in F's range for random
choice of k. An oblivious PRF (OPRF) is a two-party protocol between a prover P
and verifier V where P holds a PRF key k and V holds some input x. The protocol
allows both parties to cooperate in computing F(k, x) with P's secret key k and
V's input x such that: V learns F(k, x) without learning anything about k; and P
does not learn anything about x. A Verifiable OPRF (VOPRF) is an OPRF wherein P
can prove to V that F(k, x) was computed using key k, which is bound to a
trusted public key Y = kG. Informally, this is done by presenting a
non-interactive zero-knowledge (NIZK) proof of equality between (G, Y) and (Z,
M), where Z = kM for some point M.

OPRFs have been shown to be useful for constructing: password-protected secret
sharing schemes {{JKK14}}; privacy-preserving password stores {{SJKS17}}; and
password-authenticated key exchange or PAKE {{OPAQUE}}. VOPRFs are useful for
producing tokens that are verifiable by V. This may be needed, for example, if V
wants assurance that P did not use a unique key in its computation, i.e., if V
wants key consistency from P. This property is necessary in some applications,
e.g., the Privacy Pass protocol {{PrivacyPass}}, wherein this VOPRF is used to
generate one-time authentication tokens to bypass CAPTCHA challenges. VOPRFs
have also been used for password-protected secret sharing schemes e.g.
{{JKKX16}}.

This document introduces an OPRF protocol built in prime-order groups, applying
to finite fields of prime-order and also elliptic curve (EC) settings. The
protocol has the option of being extended to a VOPRF with the addition of a NIZK
proof for proving discrete log equality relations. This proof demonstrates
correctness of the computation using a known public key that serves as a
commitment to the server's secret key. The document describes the protocol, its
security properties, and provides preliminary test vectors for experimentation.
The rest of the document is structured as follows:

- {{background}}: Describe background, related work, and use cases of OPRF/VOPRF
  protocols.
- {{properties}}: Discuss security properties of OPRFs/VOPRFs.
- {{protocol}}: Specify an authentication protocol from OPRF functionality,
  based in prime-order groups (with an optional verifiable mode). Algorithms are
  stated formally for OPRFs in {{oprf}} and for VOPRFs in {{voprf}}.
- {{dleq}}: Specify the NIZK discrete logarithm equality (DLEQ) construction
  used for constructing the VOPRF protocol.
- {{batch}}: Specifies how the DLEQ proof mechanism can be batched for multiple
  VOPRF invocations, and how this changes the protocol execution.
- {{ciphersuites}}: Considers explicit instantiations of the protocol in the
  elliptic curve setting.
- {{sec}}: Discusses the security considerations for the OPRF and VOPRF
  protocol.
- {{apps}}: Discusses some existing applications of OPRF and VOPRF protocols.
- {{testvecs}}: Specifies test vectors for implementations in the elliptic curve
  setting.

## Change log

[draft-01](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-00):

- Updated ciphersuites to be in line with
  https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04
- Made some necessary modular reductions more explicit

## Terminology {#terminology}

The following terms are used throughout this document.

- PRF: Pseudorandom Function.
- OPRF: Oblivious PRF.
- VOPRF: Verifiable Oblivious Pseudorandom Function.
- Verifier (V): Protocol initiator when computing F(k, x), also known as client.
- Prover (P): Holder of secret key k, also known as server.
- NIZK: Non-interactive zero knowledge.
- DLEQ: Discrete Logarithm Equality.

## Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in {{RFC2119}}.

# Background {#background}

OPRFs are functionally related to blind signature schemes. In such a scheme, a
client can receive signatures on private data, under the signing key of some
server. The security properties of such a scheme dictate that the client learns
nothing about the signing key, and that the server learns nothing about the data
that is signed. One of the more popular blind signature schemes is based on the
RSA cryptosystem and is known as Blind RSA {{ChaumBlindSignature}}.

OPRF protocols can thought of as symmetric alternatives to blind signatures.
Essentially the client learns y = PRF(k,x) for some input x of their choice,
from a server that holds k. Since the security of an OPRF means that x is hidden
in the interaction, then the client can later reveal x to the server along with
y.

The server can verify that y is computed correctly by recomputing the PRF on x
using k. In doing so, the client provides knowledge of a 'signature' y for their
value x. The verification procedure is thus symmetric as it requires knowledge
of the key k. This is discussed more in the following section.

# Preliminaries

We start by detailing some necessary cryptographic definitions.

## Security Properties {#properties}

The security properties of an OPRF protocol with functionality y = F(k, x)
include those of a standard PRF. Specifically:

- Pseudorandomness: F is pseudorandom if the output y = F(k,x) on any input x is
  indistinguishable from uniformly sampling any element in F's range, for a
  random sampling of k.

In other words, for an adversary that can pick inputs x from the domain of F and
can evaluate F on (k,x) (without knowledge of randomly sampled k), then the
output distribution F(k,x) is indistinguishable from the uniform distribution in
the range of F.

A consequence of showing that a function is pseudorandom, is that it is
necessarily non-malleable (i.e. we cannot compute a new evaluation of F from an
existing evaluation). A genuinely random function will be non-malleable with
high probability, and so a pseudorandom function must be non-malleable to
maintain indistinguishability.

An OPRF protocol must also satisfy the following property:

- Oblivious: P must learn nothing about V's input or the output of the function.
  In addition, V must learn nothing about P's private key.

Essentially, obliviousness tells us that, even if P learns V's input x at some
point in the future, then P will not be able to link any particular OPRF
evaluation to x. This property is also known as unlinkability {{DGSTV18}}.

Optionally, for any protocol that satisfies the above properties, there is an
additional security property:

- Verifiable: V must only complete execution of the protocol if it can
  successfully assert that the OPRF output computed by V is correct, with
  respect to the OPRF key held by P.

Any OPRF that satisfies the 'verifiable' security property is known as a
verifiable OPRF, or VOPRF for short. In practice, the notion of verifiability
requires that P commits to the key k before the actual protocol execution takes
place. Then V verifies that P has used k in the protocol using this commitment.
In the following, we may also refer to this commitment as a public key.

## Prime-order group instantiation

In this document, we assume the construction of a prime-order group GG for
performing all mathematical operations. Such a group MUST provide the interface
provided by cyclic group under the addition operation (for example, well-defined
addition of group elements). We also assume the presence of a fixed generator G
that can be detailed as a fixed parameter in the description of the group. We
write p = order(GG) to represent the order of the group throughout this
document.

It is common in cryptographic applications to instantiate such prime-order
groups using elliptic curves, such as those detailed in {{SEC2}}. For some
choices of elliptic curves (e.g. those detailed in {{RFC7748}} require
accounting for cofactors) there are some implementation issues that introduce
inherent discrepancies between standard prime-order groups and the elliptic
curve instantiation. In this document, all algorithms that we detail assume that
the group is a prime-order group, and this MUST be upheld by any implementer.
That is, any curve instantiation shoudl be written such that any discrepancies
with a prime-order group instantiation are removed. In the case of cofactors,
for example, this can be done by building cofactor multiplication into all
elliptic curve operations.

## Conventions

We detail a list of conventions that we use throughout this document.

### Binary strings

- We use the notation x <-$ Q to denote sampling x from the uniform distribution
  over the set Q.
- We use x <- {0,1}^u to denote sampling x uniformly from the set of binary
  strings of length u. We may interpret x afterwards as a byte array.
- We say that x is a binary string of arbitrary-length (or alternatively sampled
  from {0,1}^*) if there is no fixed-size requirement on x.
- For two byte arrays x & y, write x .. y to denote their concatenation.

### Group notation

- We use the letter p to denote the order of a group GG throughout, where the
  instantiation of the specific group is defined by context.
- For elements A & B of GG, we write A + B to denote the addition of thr group
  elements.
- We use GF(p) to denote the Galois Field of scalar values associated with the
  group GG.
- For a scalar r in GF(p), and a group element A, we write rA to denote the
  scalar multiplication of A.
- For two scalars r, s in GF(p), we use r+s to denote the resulting scalar in
  GF(p) (we may optionally write r+s mod p to make the modular reduction
  explicit).

# OPRF Protocol {#protocol}

In this section we describe the OPRF and VOPRF protocols. Recall that such a
protocol takes place between a verifier (V) and a prover (P). Commonly, V is a
client and P is a server, and so we use these names interchangeably throughout.
We always operate under the assumption that the verifier is a client, and the
prover is a server in the interaction (and so we will use these names
interchangeably throughout). The server holds a secret key k for a PRF. The
protocol allows the client to learn PRF evaluations on chosen inputs x in such a
way that the server learns nothing of x.

Our OPRF construction is based on the VOPRF construction known as 2HashDH-NIZK
given by {{JKK14}}; essentially without providing zero-knowledge proofs that
verify that the output is correct. Our VOPRF construction (including the NIZK
DLEQ proofs from {{dleq}}) is identical to the {{JKK14}} construction. With
batched proofs ({{batch}}) our construction differs slightly in that we can
perform multiple VOPRF evaluations in one go, whilst only constructing one NIZK
proof object.

In this section we describe the OPRF and VOPRF protocols. Recall that such a
protocol takes place between a verifier (V) and a prover (P). We may commonly
think of the verifier as the client, and the prover as the server in the
interaction (we will use these names interchangeably throughout). The server
holds a key k for a PRF. The protocol allows the client to learn PRF evaluations
on chosen inputs x without revealing x to the server.

Our OPRF construction is based on the VOPRF construction known as 2HashDH-NIZK
given by {{JKK14}}; essentially without providing zero-knowledge proofs that
verify that the output is correct. Our VOPRF construction (including the NIZK
DLEQ proofs from {{dleq}}) is identical to the {{JKK14}} construction. With
batched proofs ({{batch}}) our construction differs slightly in that we can
perform multiple VOPRF evaluations in one go, whilst only constructing one NIZK
proof object.

## Design

Let GG be an additive group of prime-order p, let GF(p) be the Galois field
defined by the integers modulo p. Define distinct hash functions H_1 and H_2,
where H_1 maps arbitrary input onto GG (H_1: {0,1}^* -> GG) and H_2 maps
two arbitrary inputs to a fixed-length (w) output (H_2: {0,1}^u x {0,1}^v ->
{0,1}^w), e.g., HMAC_SHA256. All hash functions in the protocol are modeled as
random oracles. Let L be the security parameter. Let k be the prover's secret
key, and Y = kG be its corresponding 'public key' for some fixed generator G
taken from the description of the group GG. This public key Y is also referred
to as a commitment to the OPRF key k, and the pair (G,Y) as a commitment pair.
Let x be the binary string that is the verifier's input to the OPRF protocol
(this can be of arbitrary length).

The OPRF protocol begins with V blinding its input for the OPRF evaluator such
that it appears uniformly distributed GG. The latter then applies its secret key
to the blinded value and returns the result. To finish the computation, V then
removes its blind and hashes the result (along with a domain separating label
DST) using H_2 to yield an output. This flow is illustrated below.

~~~
     Verifier(x)                   Prover(k)
  ----------------------------------------------------------
     r <-$ GF(p)
     M = rH_1(x) mod p
                           M
                        ------->
                                  Z = kM mod p
                                  [D = DLEQ_Generate(k,G,Y,M,Z)]
                          Z[,D]
                        <-------
    [b = DLEQ_Verify(G,Y,M,Z,D)]
    N = Zr^(-1) mod p
    Output H_2(DST, x .. N) mod p [if b=1, else "error"]
~~~

Steps that are enclosed in square brackets (DLEQ_Generate and DLEQ_Verify) are
optional for achieving verifiability. These are described in {{dleq}}. In the
verifiable mode, we assume that P has previously committed to their choice of
key k with some values (G,Y=kG) and these are publicly known by V. Notice that
revealing (G,Y) does not reveal k by the well-known hardness of the discrete log
problem.

Strictly speaking, the actual PRF function that is computed is:

~~~
F(k, x) = N = kH_1(x)
~~~

It is clear that this is a PRF H_1(x) maps x to a random element in GG, and GG
is cyclic. This output is computed when the client computes Zr^(-1) by the
commutativity of the multiplication. The client finishes the computation by
outputting H_2(DST, x .. N). Note that the output from P is not the PRF value
because the actual input x is blinded by r.

The security of our construction is discussed in more detail in
{{protocol-sec}}. We discuss the considerations that should be made when
embedding (V)OPRF protocols into wider protocols in {{embed}}.

## Protocol functionality

This protocol may be decomposed into a series of steps, as described below:

- Setup(l): Let GG=GG(l) be a group with a prime-order p=p(l) (e.g., p is
  l-bits long). Randomly sample an integer k in GF(p) and output (k,GG)
- Blind(x): Compute and return a blind, r, and blinded representation of x
  in GG, denoted M.
- Evaluate(k,M,h?): Evaluates on input M using secret key k to produce Z, the
  input h is optional and equal to the cofactor of an elliptic curve. If h is
  not provided then it defaults to 1.
- Unblind(r,Z): Unblind blinded OPRF evaluation Z with blind r, yielding N
  and output N.
- Finalize(x,N,aux): Finalize N by first computing dk := H_2(DST, x .. N).
  Subsequently output y := H_2(dk, aux), where aux is some auxiliary data.

For verifiability (VOPRF) we modify the algorithms of VerifiableSetup, VerifiableEvaluate
and VerifiableUnblind to be the following:

- VerifiableSetup(l): Run (k,GG) = Setup(l), compute Y = kG, where G is a
  generator of the group GG. Output (k,GG,Y).
- VerifiableEvaluate(k,G,Y,M,h?): Evaluates on input M using secret key k to produce Z.
  Generate a NIZK proof D = DLEQ_Generate(k,G,Y,M,Z), and output (Z, D). The
  optional cofactor h can also be provided, as in Evaluate.
- VerifiableUnblind(r,G,Y,M,Z,D): Unblind blinded OPRF evaluation Z with blind r,
  yielding N. Output N if 1 = DLEQ_Verify(G,Y,M,Z,D). Otherwise, output "error".

We leave the rest of the OPRF algorithms unmodified. When referring explicitly
to VOPRF execution, we replace 'OPRF' in all method names with 'VOPRF'. We
describe explicit instantiations of these functions in {{oprf}} and {{voprf}}.

### Generalized OPRF {#general-oprf}

Using the API provided by the functions above, we can restate the OPRF protocol
using the following descriptions. The first protocol refers to the OPRF setup
phase that is run by the server. This generates the secret input used by the
server and the public information that is given to the client.

OPRF setup phase:

~~~
     Verifier()                   Prover(l)
  ----------------------------------------------------------
                                  (k,GG) = Setup(l)
                           GG
                        <-------
~~~

OPRF evaluation phase:

~~~
     Verifier(x,aux)                   Prover(k)
  ----------------------------------------------------------
     (r, M) = Blind(x)
                            M
                        ------->
                                  Z = Evaluate(k,M)
                            Z
                        <-------
    N = Unblind(r,Z)
    Output Finalize(x,N,aux)
~~~

Note that in the final output, the client computes Finalize over some
auxiliary input data aux.

### Generalized VOPRF {#general-voprf}

The generalized VOPRF functionality differs slightly from the OPRF protocol
above. Firstly, the server sends over an extra commitment value Y = kG, where G
is a common generator known to both participants. Secondly, the server sends
over both outputs from VerifiableEvaluate in the evaluation phase, and the client also
verifies the server's output.

VOPRF setup phase:

~~~
     Verifier()                   Prover(l)
  ----------------------------------------------------------
                                  (k,GG,Y) = VerifiableSetup(l)
                         (GG,Y)
                        <-------
~~~

VOPRF evaluation phase:

~~~
     Verifier(x,Y,aux)            Prover(k)
  ----------------------------------------------------------
     (r, M) = VerifiableBlind(x)
                            M
                        ------->
                                  (Z,D) = VerifiableEvaluate(k,G,Y,M)
                          (Z,D)
                        <-------
    N = VerifiableUnblind(r,G,Y,M,Z,D)
    Output VerifiableFinalize(x,N,aux)
~~~

## Protocol correctness

Protocol correctness requires that, for any key k, input x, and (r, M) =
Blind(x), it must be true that:

~~~
  Finalize(x, Unblind(r,M,Evaluate(k,M)), aux)
      == H_2(H_2(DST, x .. F(k,x)), aux)
~~~

with overwhelming probability. Likewise, in the verifiable setting, we require
that:

~~~
  VerifiableFinalize(x, VerifiableUnblind(r,G,Y,M,(VerifiableEvaluate(k,G,Y,M))), aux)
      == H_2(H_2(DST, x .. F(k,x)), aux)
~~~

with overwhelming probability, where (r, M) = VerifiableBlind(x). In other words,
the inner H_2 invocation effectively derives a key, dk, from the input data DST,
x, N. The outer invocation derives the output y by evaluating H_2 over dk and
auxiliary data aux.

## Instantiations of GG

As we remarked above, GG is a group with associated prime-order p. While we
choose to write operations in the setting where GG comes equipped with an
additive operation, we could also define the operations in the multiplicative
setting. In the multiplicative setting we can choose GG to be a prime-order
subgroup of a finite field FF_p. For example, let p be some large prime (e.g. >
2048 bits) where p = 2q+1 for some other prime q. Then the subgroup of squares
of FF_p (elements u^2 where u is an element of FF_p) is cyclic, and we can pick
a generator of this subgroup by picking G from FF_p (ignoring the identity
element).

For practicality of the protocol, it is preferable to focus on the cases where
GG is an additive subgroup so that we can instantiate the OPRF in the elliptic
curve setting. This amounts to choosing GG to be a prime-order subgroup of an
elliptic curve over base field GF(p) for prime p. There are also other settings
where GG is a prime-order subgroup of an elliptic curve over a base field of
non-prime order, these include the work of Ristretto {{RISTRETTO}} and Decaf
{{DECAF}}.

We will use p > 0 generally for constructing the base field GF(p), not just
those where p is prime. To reiterate, we focus only on the additive case, and so
we focus only on the cases where GF(p) is indeed the base field.

Unless otherwise stated, we will always assume that the generator G that we use
for the group GG is a fixed generator. This generator should be available to
both the client and the server ahead of the protocol, or derived for each
different group instantiation using a fixed method. In the elliptic curve
setting, we recommend using the fixed generators that are given as part of the
curve description.

## OPRF algorithms {#oprf}

This section provides descriptions of the algorithms used in the generalized
protocols from {{general-oprf}}. We describe the VOPRF analogues for the
protocols in {{general-voprf}} later in {{voprf}}.

We note here that the blinding mechanism that we use can be modified slightly
with the opportunity for making performance gains in some scenarios. We detail
these modifications in Section {{blinding}}.

### Setup

~~~
Input:

 l: Some suitable choice of prime length for instantiating a group structure
    (e.g. as described in [NIST]).

Output:

 k:  A key chosen from {0,1}^l and interpreted as a scalar in [1,p-1].
 GG: A cyclic group with prime-order p of length l bits.

Steps:

 1. Construct a group GG = GG(l) with prime-order p of length l bits
 2. k <-$ GF(p)
 3. Output (k,GG)
~~~

### Blind

~~~
Input:

 x: Binary string taken from {0,1}^*.

Output:

 r: Random scalar in [1, p - 1].
 M: An element in GG.

Steps:

 1.  r <-$ GF(p)
 2.  M := rH_1(x)
 3.  Output (r, M)
~~~

### Evaluate

~~~
Input:

 k: A scalar value taken from [1,p-1].
 M: An element in GG.

Output:

 Z: An element in GG.

Steps:

 1. Z := kM
 2. Output Z
~~~

### Unblind

~~~
Input:

 r: Random scalar in [1, p - 1].
 Z: An element in GG.

Output:

 N: An element in GG.

Steps:

 1. N := (r^(-1))Z
 2. Output N
~~~

### Finalize

~~~
Input:

 x: Binary string taken from {0,1}^*.
 N: An element in GG.
 aux: Arbitrary auxiliary data (as bytes).

Output:

 y: Random element in {0,1}^L.

Steps:

 1. DST := "oprf_derive_output"
 2. dk := H_2(DST, x .. N)
 3. y := H_2(dk, aux)
 4. Output y
~~~

## VOPRF algorithms {#voprf}

We make modifications to the aforementioned algorithms in the VOPRF setting.

### VerifiableSetup

~~~
Input:

 G: Public fixed generator of GG.
 l: Some suitable choice of key-length (e.g. as described in [NIST]).

Output:

 k:  A key chosen from {0,1}^l and interpreted as a scalar in [1,p-1].
 GG: A cyclic group with prime-order p of length l bits.
 Y:  A group element in GG.

Steps:

  1. (k,GG) <- Setup(l)
  2. Y := kG
  3. Output (k,GG,Y)
~~~

### VerifiableBlind

~~~
Input:

 x: V's PRF input.

Output:

 r: Random scalar in [1, p - 1].
 M: An element in GG.

Steps:

 1.  r <-$ GF(p)
 2.  M := rH_1(x)
 3.  Output (r,M)
~~~

### VerifiableEvaluate

~~~
Input:

 k: A random scalar in [1,p-1].
 G: Public fixed generator of group GG.
 Y: An element in GG.
 M: An element in GG.

Output:

 Z: An element in GG.
 D: DLEQ proof that log_G(Y) == log_M(Z).

Steps:

 1. Z := kM
 2. Z <- hZ
 3. D = DLEQ_Generate(k,G,Y,M,Z)
 4. Output (Z, D)
~~~

### VerifiableUnblind

~~~
Input:

 r: Random scalar in [1, p - 1].
 G: Public fixed generator of group GG.
 Y: An element in GG.
 M: An element in GG.
 Z: An element in GG.
 D: DLEQ proof object.

Output:

 N: An element in GG.

Steps:

 1. if DLEQ_Verify(G,Y,M,Z,D) == false: output "error"
 2. N := (r^(-1))Z
 3. Output N
~~~

### VerifiableFinalize

~~~
Input:

 x:   Binary string in {0,1}^*.
 N:   An element in GG, or "error".
 aux: Arbitrary auxiliary data in {0,1}^*.

Output:

 y:   Random element in {0,1}^L, or "error"

Steps:

 1. If N == "error", output "error".
 2. DST := "voprf_derive_output"
 3. dk := H_2(DST, x .. N)
 4. y := H_2(dk, aux)
 5. Output y
~~~

## Efficiency gains with pre-processing and fixed-base blinding {#blinding}

In Section {{oprf}} we assume that the client-side blinding is carried out
directly on the output of H_1(x), i.e. computing rH_1(x) for some r <-$ GF(p).
In the {{OPAQUE}} draft, it is noted that it may be more efficient to use
additive blinding rather than multiplicative if the client can preprocess some
values. For example, a valid way of computing additive blinding would be to
instead compute H_1(x)+rG, where G is the fixed generator for the group GG.

We refer to the 'multiplicative' blinding as variable-base blinding (VBB), since
the base of the blinding (H_1(x)) varies with each instantiation. We refer to
the additive blinding case as fixed-base blinding (FBB) since the blinding is
applied to the same generator each time (when computing rG).

By pre-processing tables of blinded scalar multiplications for the specific
choice of G it is possible to gain a computational advantage. Choosing one of
these values rG (where r is the scalar value that is used), then computing
H_1(x)+rG is more efficient than computing rH_1(x) (one addition against
log_2(r)). Therefore, it may be advantageous to define the OPRF and VOPRF
protocols using additive blinding rather than multiplicative blinding. In fact,
the only algorithms that need to change are Blind and Unblind (and
similarly for the VOPRF variants).

We define the FBB variants of the algorithms in {{oprf}} below along with a new
algorithm Preprocess that defines how preprocessing is carried out. The
equivalent algorithms for VOPRF are almost identical and so we do not redefine
them here. Notice that the only computation that changes is for V, the necessary
computation of P does not change.

### Preprocess

~~~
Input:

 G:  Public fixed generator of GG

Output:

 r:  Random scalar in [1, p-1]
 rG: An element in GG.
 rY: An element in GG.

Steps:

 1.  r <-$ GF(p)
 2.  Output (r, rG, rY)
~~~

### Blind

~~~
Input:

 x:  Binary string in {0,1}^*.
 rG: An element in GG.

Output:

 M: An element in GG.

Steps:

 1.  M := H_1(x)+rG
 2.  Output M
~~~

### Unblind

~~~
Input:

 rY: An element in GG.
 M:  An element in GG.
 Z:  An element in GG.

Output:

 N: An element in GG.

Steps:

 1. N := Z-rY
 2. Output N
~~~

Notice that Unblind computes (Z-rY) = k(H_1(x)+rG) - rkG = kH_1(x) by the
commutativity of scalar multiplication in GG. This is the same output as in the
original Unblind algorithm.

## Recommended protocol integration {#embed}

We describe some recommendations and suggestions on the topic of integrating the
(V)OPRF protocol from {{protocol}} into wider protocols. It should be noted that
since {{JKK14}} provides a security proof of the VOPRF construction in the UC
security model, then any UC-secure protocol that uses the OPRF construction as
an atomic instantiation will remain UC-secure.

Thus, it is RECOMMENDED that any protocol that wishes to include an OPRF stage
does so by implementing all OPRF evaluation functionality as a contiguous block
of operations during the protocol. This does not include the OPRF setup phase,
which should be run before the entire protocol interaction. For example, such an
instantiation for a wider protocol W would look like the following.

~~~
    ================================================================
                           OPRF setup phase
    ================================================================

    > ...
    > BEGIN(protocol W)
    > ...
    > PAUSE(protocol W)

    ================================================================
                         OPRF evaluation phase
    ================================================================

    > RESTART(protocol W)
    > ...
    > END(protocol W)
~~~

In other words, no messages from protocol W should take place during the OPRF
protocol instantiation. This DOES NOT preclude the participants in protocol W
from using the outputs of the OPRF evaluation, once the OPRF protocol is
complete. Note that the OPRF protocol can involve batched evaluations, as well
as single evaluations.

### Setup phase

In the VOPRF setting, the server must send to the client Y (the commitment to
the server key k. From this information, the client and server must agree on a
generator G for the group description. It is important that the generator G of
GG is not chosen by the server, and that it is agreed upon before the protocol
starts. In the elliptic curve setting, we recommend that G is chosen as the
standard generator for the curve.

As we mentioned above, if an implementer wants to embed OPRF evaluation as part
of a wider protocol, then we recommend that this setup phase should occur before
all communication takes place; including all communication required for the
wider protocol. We recommend that any server implementation only implements one
group instantiation at any one time. This means that the client does not have to
pick a specific instantiation when it sends the first evaluation message.

### Evaluation phase

The evaluation phase of the OPRF results in a client receiving pseudorandom
function evaluations from the server. It is important that the client is able to
link the computation that it performs in the first step, with the output that it
receives from the server. In other words, the client must store the data (r,M)
output by Blind(x). When it receives Z from the server, it must then use
(r,M) as inputs to Blind.

In the batched setting, the client stores multiple values (ri,Mi) and sends each
Mi to the server. Both client and server should preserve this ordering
throughout the evaluation phase so that the client can successfully finalize the
output in the final step.

### Additional requirements

The client input to the OPRF evaluation phase is a set of bytes x. These bytes
are RECOMMENDED to be uniformly distributed. If the bytes are sampled from a
predictable distribution instead, then it is likely that the server will also be
able to predict the client's input to the OPRF. Therefore client privacy is
reduced.

Protocols that embed an OPRF evaluation MUST specify exactly how group elements
are encoded in messages.

The server need not not preserve any information during the evaluation exchange.
For efficiency and client-privacy reasons, we recommend that all data received
from the client in the evaluation phase is destroyed after the server has
responded.

In the VOPRF setting, when the server sends the response, it needs to indicate
which version of key that it has used. This enables the client to retrieve the
correct commitment from the public registry. The server MUST include a key
identifier as part of its response, to ensure that the client can verify the
contents of D correctly.

# NIZK Discrete Logarithm Equality Proof {#dleq}

For the VOPRF protocol we require that V is able to verify that P has used its
private key k to evaluate the PRF. We can do this by showing that the original
commitment (G,Y) output by VerifiableSetup(l) satisfies log_G(Y) == log_M(Z) where Z
is the output of VerifiableEvaluate(k,G,Y,M).

This may be used, for example, to ensure that P uses the same private key for
computing the VOPRF output and does not attempt to "tag" individual verifiers
with select keys. This proof must not reveal the P's long-term private key to V.

Consequently, this allows extending the OPRF protocol with a (non-interactive)
discrete logarithm equality (DLEQ) algorithm built on a Chaum-Pedersen
{{ChaumPedersen}} proof. This proof is divided into two procedures:
DLEQ_Generate and DLEQ_Verify. These are specified below.

## DLEQ_Generate

~~~
Input:

 k: Evaluator secret key.
 G: Public fixed generator of GG.
 Y: Evaluator public key (= kG).
 M: An element in GG.
 Z: An element in GG.
 H_3: A hash function from GG to {0,1}^L, modeled as a random oracle.

Output:

 D: DLEQ proof (c, s).

Steps:

 1. r <-$ GF(p)
 2. A := rG
 3. B := rM
 4. c <- H_3(G,Y,M,Z,A,B) (mod p)
 5. s := (r - ck) (mod p)
 6. Output D := (c, s)
~~~

We note here that it is essential that a different r value is used for every
invocation. If this is not done, then this may leak the key k in a similar
fashion as is possible in Schnorr or (EC)DSA scenarios where fresh randomness is
not used.

## DLEQ_Verify

~~~
Input:

 G: Public fixed generator of GG.
 Y: Evaluator public key.
 M: An element in GG.
 Z: An element in GG.
 D: DLEQ proof (c, s).

Output:

 True if log_G(Y) == log_M(Z), False otherwise.

Steps:

 1. A' := (sG + cY)
 2. B' := (sM + cZ)
 3. c' <- H_3(G,Y,M,Z,A',B') (mod p)
 4. Output c == c' (mod p)
~~~

# Batched VOPRF evaluation {#batch}

Common applications (e.g. {{PrivacyPass}}) require V to obtain multiple PRF
evaluations from P. In the VOPRF case, this would naïvely require running
multiple protocol invocations. This is costly, both in terms of computation and
communication. To get around this, applications can use a 'batching' procedure
for generating and verifying DLEQ proofs for a finite number of PRF evaluation
pairs (Mi,Zi). For n PRF evaluations:

- Proof generation is slightly more expensive from 2n modular exponentiations to
  2n+2.
- Proof verification is much more efficient, from 4n modular exponentiations to
  2n+4.
- Communications falls from 2n to 2 group elements.

Since P is the VOPRF server, it may be able to tolerate a slight increase in
proof generation complexity for much more efficient communication and proof
verification.

In this section, we describe algorithms for batching the DLEQ generation and
verification procedure. For these algorithms we require two additional hash
functions H_4: GG^(2n+2) -> {0,1}^a, and H_5: {0,1}^a x ZZ^3 -> {0,1}^b (both
modeled as random oracles).

We can instantiate the random oracle function H_4 using the same hash function
that is used for H_3 previosuly. For H_5, we can also use a similar
instantiation, or we can use a variable-length output generator. For example,
for groups with an order of 256-bit, valid instantiations include functions such
as SHAKE-256 {{SHAKE}} or HKDF-Expand-SHA256 {{RFC5869}}. This is preferable in
situations where we may require outputs that are larger than 512 bits in length,
for example.

## Batched_DLEQ_Generate

~~~
Input:

 k: Evaluator secret key.
 G: Public fixed generator of group GG (with order p).
 Y: Evaluator public key (= kG).
 n: Number of PRF evaluations.
 [ Mi ]: An array of points in GG of length n.
 [ Zi ]: An array of points in GG of length n.
 H_4: A hash function from GG^(2n+2) to {0,1}^a, modeled as a random oracle.
 H_5: A hash function from {0,1}^a x ZZ^2 to {0,1}^b, modeled as a random oracle.
 label: An integer label value for the splitting the domain of H_5

Output:

 D: DLEQ proof (c, s).

Steps:

 1. seed <- H_4(G,Y,[Mi,Zi]))
 2. i' := i
 3. for i in [m]:
    1. di <- H_5(seed,i',info)
    2. if di > p:
       1. i' = i'+1
       2. i = i-1 // decrement and try again
       3. continue
 4. c1,...,cn := (int)d1,...,(int)dn
 5. M := c1M1 + ... + cnMn
 6. Z := c1Z1 + ... + cnZn
 7. Output DLEQ_Generate(k,G,Y,M,Z)
~~~

## DLEQ_Batched_Verify

~~~
Input:

 G: Public fixed generator of group GG (with order p).
 Y: Evaluator public key.
 [ Mi ]: An array of points in GG of length n.
 [ Zi ]: An array of points in GG of length n.
 D: DLEQ proof (c, s).

Output:

 True if log_G(Y) == log_(Mi)(Zi) for each i in 1...n, False otherwise.

Steps:

 1. seed <- H_4(G,Y,[Mi,Zi]))
 2. i' := i
 3. for i in [m]:
    1. di <- H_5(seed,i',info)
    2. if di > p:
       1. i' = i'+1
       2. i = i-1 // decrement and try again
       3. continue
 4. c1,...,cn := (int)d1,...,(int)dn
 5. M := c1M1 + ... + cnMn
 6. Z := c1Z1 + ... + cnZn
 7. Output DLEQ_Verify(G,Y,M,Z,D)
~~~

## Modified algorithms

The VOPRF protocol from Section {{protocol}} changes to allow specifying
multiple blinded PRF inputs `[ Mi ]` for i in 1...n. P computes the array `[ Zi
]` and replaces DLEQ_Generate with DLEQ_Batched_Generate over these arrays.
Concretely, we modify the following algorithms:

### VerifiableBlind

~~~
Input:

 [ xi ]: An array of m binary strings taken from {0,1}^*.

Output:

 [ ri ]: An array of m random scalars in [1, p - 1].
 [ Mi ]: An array of elements in GG.

Steps:

 1.  groupElems = []
 2.  blinds = []
 3.  for i in [m]:
     1.  ri <-$ GF(p)
     2.  Mi := rH_1(xi)
     3.  blinds.push(ri)
     4.  groupElems.push(Mi)
 4.  Output (blinds, groupElems)
~~~

### VerifiableEvaluate

~~~
Input:

 k:      Evaluator secret key.
 G:      Public fixed generator of group GG.
 Y:      Evaluator public key (= kG).
 [ Mi ]: An array of m elements in GG.

Output:

 [ Zi ]: An array of m elements in GG.
 D:      Batched DLEQ proof object.

Steps:

 1.  outputElems = []
 2.  for i in [m]:
     1. Zi := kMi
     2. outputElems.push(Zi)
 3. D = Batched_DLEQ_Generate(k,G,Y,[ Mi ],outputElems)
 4. Output (outputElems, D)
~~~

### VerifiableUnblind

~~~
Input:

 G:      Public fixed generator of group GG.
 Y:      Evaluator public key (= kG).
 [ Mi ]: An array of m elements in GG.
 [ Zi ]: An array of m elements in GG.
 [ ri ]: An array of m random scalars in [1, p - 1].
 D:      Batched DLEQ proof object.

Output:

 [ Ni ]: An array of n elements in GG.

Steps:

 1. if !Batch_DLEQ_Verify(G,Y,[ Mi ],[ Zi ],D): Output "error"
 2. N = []
 3.  for i in [m]:
     1. Ni := (ri^(-1))Zi
     2. N.push(Ni)
 4. Output N
~~~

### VerifiableFinalize

The description of this algorithm does not change in the batched case. Instead,
the protocol description in {{general-voprf}} changes so that `VerifiableFinalize`
runs once for each of the outputs of `VerifiableUnblind`.

## Random oracle instantiations for proofs

We can instantiate the random oracle function H_4 using the same hash function
that is used for H_1,H_2,H_3. For H_5, we can also use a similar instantiation,
or we can use a variable-length output generator. For example, for groups with
an order of 256-bit, valid instantiations include functions such as SHAKE-256
{{SHAKE}} or HKDF-Expand-SHA256 {{RFC5869}}.

~~~
Input:

 [ ri ]: Random scalars in [1, p - 1].
 G: Public fixed generator of group GG.
 Y: Evaluator public key.
 [ Mi ]: Blinded elements of GG.
 [ Zi ]: Server-generated elements in GG.
 D: A batched DLEQ proof object.

Output:

 N: element in GG, or "error".

Steps:

 1. N := (r^(-1))Z
 2. If 1 = DLEQ_Batched_Verify(G,Y,[ Mi ],[ Zi ],D), output N
 3. Output "error"
~~~

# Supported ciphersuites {#ciphersuites}

This section specifies supported VOPRF group and hash function instantiations.
We only provide ciphersuites in the EC setting as these provide the most
efficient way of instantiating the OPRF. Our instantiation includes
considerations for providing the DLEQ proofs that make the instantiation a
VOPRF. Supporting OPRF operations alone can be allowed by simply dropping the
relevant components. For reasons that are detailed in {{cryptanalysis}}, we only
consider ciphersuites that provide strictly greater than 128 bits of security
{{NIST}}.

## OPRF-curve448-HKDF-SHA512-ELL2-RO:

- GG: curve448 {{RFC7748}}
- H_1: curve448-SHA512-ELL2-RO {{I-D.irtf-cfrg-hash-to-curve}}
  - hash-to-curve DST: "RFCXXXX-OPRF-curve448-SHA512-ELL2-RO-"
- H_2: HMAC_SHA512 {{RFC2104}}
- H_3: SHA512

## OPRF-P384-HKDF-SHA512-SSWU-RO:

- GG: secp384r1 {{SEC2}}
- H_1: P384-SHA512-SSWU-RO {{I-D.irtf-cfrg-hash-to-curve}}
  - hash-to-curve DST: "RFCXXXX-OPRF-P384-SHA512-SSWU-RO-"
- H_2: HMAC_SHA512 {{RFC2104}}
- H_3: SHA512

## OPRF-P521-HKDF-SHA512-SSWU-RO:

- GG: secp521r1 {{SEC2}}
- H_1: P521-SHA512-SSWU-RO {{I-D.irtf-cfrg-hash-to-curve}}
  - hash-to-curve DST: "RFCXXXX-OPRF-P521-SHA512-SSWU-RO-"
- H_2: HMAC_SHA512 {{RFC2104}}
- H_3: SHA512

## VOPRF-curve448-HKDF-SHA512-ELL2-RO:

- GG: curve448 {{RFC7748}}
- H_1: curve448-SHA512-ELL2-RO {{I-D.irtf-cfrg-hash-to-curve}}
  - hash-to-curve DST: "RFCXXXX-VOPRF-curve448-SHA512-ELL2-RO-"
- H_2: HMAC_SHA512 {{RFC2104}}
- H_3: SHA512
- H_4: SHA512
- H_5: HKDF-Expand-SHA512

## VOPRF-P384-HKDF-SHA512-SSWU-RO:

- GG: secp384r1 {{SEC2}}
- H_1: P384-SHA512-SSWU-RO {{I-D.irtf-cfrg-hash-to-curve}}
  - hash-to-curve DST: "RFCXXXX-VOPRF-P384-SHA512-SSWU-RO-"
- H_2: HMAC_SHA512 {{RFC2104}}
- H_3: SHA512
- H_4: SHA512
- H_5: HKDF-Expand-SHA512

## VOPRF-P521-HKDF-SHA512-SSWU-RO:

- GG: secp521r1 {{SEC2}}
- H_1: P521-SHA512-SSWU-RO {{I-D.irtf-cfrg-hash-to-curve}}
  - hash-to-curve DST: "RFCXXXX-VOPRF-P521-SHA512-SSWU-RO-"
- H_2: HMAC_SHA512 {{RFC2104}}
- H_3: SHA512
- H_4: SHA512
- H_5: HKDF-Expand-SHA512

We remark that the 'hash-to-curve DST' field is necessary for domain separation of the
hash-to-curve functionality.

# Recommended protocol integration

We describe some recommendations and suggestions on the topic of integrating the
(V)OPRF protocol from {{protocol}} into wider protocols. It should be noted that
since {{JKK14}} provides a security proof of the VPRF construction in the UC
security model, then any UC-secure protocol that uses the OPRF construction as
an atomic instantiation will remain UC-secure.

As a result we recommend that any protocol that wishes to include an OPRF stage
does so by implementing all OPRF evaluation functionality as a contiguous block
of operations during the protocol. This does not include the OPRF setup phase,
which should be run before the entire protocol interaction. For example, such an
instantiation for a wider protocol W would look like the following.

~~~
    ================================================================
                           OPRF setup phase
    ================================================================

    > ...
    > BEGIN(protocol W)
    > ...
    > PAUSE(protocol W)

    ================================================================
                         OPRF evaluation phase
    ================================================================

    > RESTART(protocol W)
    > ...
    > END(protocol W)
~~~

In other words, no messages from protocol W should take place during the OPRF
protocol instantiation. This DOES NOT preclude the participants in protocol W
from using the outputs of the OPRF evaluation, once the OPRF protocol is
complete. Note that the OPRF protocol can involve batched evaluations, as well
as single evaluations.

## Setup phase

In the VOPRF setting, the server must send Y to the client where Y is a
commitment to the server key k. From this information, the client and server
must agree on a generator G for the group description. It is important that the
generator G of GG is not chosen by the server, and that it is agreed upon before
the protocol starts. In the elliptic curve setting, we recommend that G is
chosen as the standard generator for the curve.

As we mentioned above, if an implementer wants to embed OPRF evaluation as part
of a wider protocol, then we recommend that this setup phase should occur before
all communication takes place; including all communication required for the
wider protocol. We recommend that any server implementation only implements one
group instantiation at any one time. This means that the client does not have to
pick a specific instantiation when it sends the first evaluation message.

## Evaluation phase

The evaluation phase of the OPRF results in a client receiving pseudorandom
function evaluations from the server. It is important that the client is able to
link the computation that it performs in the first step, with the output that it
receives from the server. In other words, the client must store the data (r,M)
output by Blind(x). When it receives Z from the server, it must then use
(r,M) as inputs to Blind.

In the batched setting, the client stores multiple values (ri,Mi) and sends each
Mi to the server. Both client and server should preserve this ordering
throughout the evaluation phase so that the client can successfully finalize the
output in the final step.

## Client-specific considerations

### Inputs

The client input to the OPRF evaluation phase is a set of bytes x. These bytes
do not have to be uniformly distributed. However, we should note that if the
bytes are sampled from a predictable distribution, then it is likely that the
server will also be able to predict the client's input to the OPRF. Therefore
the utility of client privacy is reduced somewhat.

### Output

The client receives y = H_2(DST, x .. N) at the end of the protocol. We suggest
that clients store the pair (x, y) as bytes. This allows the client to use the
the output of the protocol in conjunction with the input used to create it
later.

### Messages

The client message contains a group element and should be encoded as bytes. In
the elliptic curve setting this corresponds to an encoded curve point. Both
compressed and uncompressed point encodings should be supported by the server.
The length of the point encoding should be enough to determine the encoding of
the point.

## Server-specific considerations

### Setup

As mentioned previously, the server should pick a single group instantiation and
advertise this as the only way of evaluating the OPRF.

### Inputs

The server input to the evaluation phase is a key k. This key can be stored
simply as bytes. The key must be protected at all times. If the server ever
suspects that the key has been compromised then it must be rotated immediately.
In addition, the key should be rotated somewhat frequently for security reasons
to reduce the impact of an unknown compromise. For more information on
appropriate key schedules, see {{key-rotation}}.

Every time the server key is rotated, a new setup phase will have to be run. The
server should publish public key commitments (Y) to a public, trusted registry
to avoid notifying all client's individually. The registry should be considered
tamper-proof from the client perspective and should retain a history of all
edits. We recommend that all commitments come with an expiry date to enforce
rotation policies, and optionally a signature using a long-term signing key
(with public verification key made available via another public beacon). The
signature is only necessary to prevent active attackers that may be able to
route the client to an untrusted registry.

Below, we recommend the following proposed JSON structure for holding public
commitment data.

~~~
{
  "Y": <bytes_of_commitment>,
  "expiry": <date-of-expiry>,
  "sig": <commitment_signature>
}
~~~

This data should be retrieved and validated by the client when verifying VOPRF
messages from the server. For efficiency reasons, the client may want to cache
the value of "Y" and "expiry". Any commitment that has expired should not be
used by the client.

Each commitment should be versioned according to some obvious convention. After
a key rotation the server should append a new commitment object with a new
version tag.

### Outputs

The server need not not preserve any information during the evaluation exchange.
For efficiency and client-privacy reasons, we recommend that all data received
from the client in the evaluation phase is destroyed after the server has
responded.

### Messages

In the VOPRF setting, when the server sends the response, it needs to indicate
which version of key that it has used. This enables the client to retrieve the
correct commitment from the public registry. We recommend that the server sends
it's response as a JSON object that specifies separate members for the values Z
and D, along with the key version that is used.

# Security Considerations {#sec}

This section discusses the cryptographic security of our protocol, along with
some suggestions and trade-offs that arise from the implementation of the
implementation of an OPRF.

## Cryptographic security {#cryptanalysis}

We discuss the cryptographic security of the OPRF protocol from {{protocol}},
relative to the necessary cryptographic assumptions that need to be made.

### Computational hardness assumptions {#assumptions}

Each assumption states that the problems specified below are computationally
difficult to solve in relation to sp (the security parameter). In other words,
the probability that an adversary has in solving the problem is bounded by a
function negl(sp), where negl(sp) < 1/f(sp) for all polynomial functions f().

Let GG = GG(sp) be a group with prime-order p, and let FFp be the finite field
of order p.

#### Discrete-log (DL) problem {#dl}

Given G, a generator of GG, and H = hG for some h in FFp; output h.

#### Decisional Diffie-Hellman (DDH) problem {#ddh}

Sample a uniformly random bit d in {0,1}. Given (G, aG, bG, C), where:

- G is a generator of GG;
- a,b are elements of FFp;
- if d == 0: C = abG; else: C is sampled uniformly GG(sp).

Output d' == d.

### Protocol security {#protocol-sec}

As aforementioned, our OPRF and VOPRF constructions are based heavily on the
2HashDH-NIZK construction given in {{JKK14}}, except for considerations on how
we instantiate the NIZK DLEQ proof system. This means that the cryptographic
security of our construction is also based on the assumption that the One-More
Gap DH is computationally difficult to solve.

The (N,Q)-One-More Gap DH (OMDH) problem asks the following.

~~~
    Given:
    - G, kG, G_1, ... , G_N where G, G1, ... GN are elements of the group GG;
    - oracle access to an OPRF functionality using the key k;
    - oracle access to DDH solvers.

    Find Q+1 pairs of the form below:

    (G_{j_s}, kG_{j_s})

    where the following conditions hold:
      - s is a number between 1 and Q+1;
      - j_s is a number between 1 and N for each s;
      - Q is the number of allowed queries.
~~~

The original paper {{JKK14}} gives a security proof that the 2HashDH-NIZK
construction satisfies the security guarantees of a VOPRF protocol
{{properties}} under the OMDH assumption in the universal composability (UC)
security model. Without the NIZK proof system, the protocol instantiates an OPRF
protocol only. See the paper for further details.

### Q-strong-DH oracle {#qsdh}

A side-effect of our OPRF design is that it allows instantiation of a oracle for
constructing Q-strong-DH (Q-sDH) samples. The Q-Strong-DH problem asks the
following.

~~~
    Given G1, G2, h*G2, (h^2)*G2, ..., (h^Q)*G2; for G1 and G2 generators of GG.

    Output ( (1/(k+c))*G1, c ) where c is an element of FFp
~~~

The assumption that this problem is hard was first introduced in {{BB04}}. Since
then, there have been a number of cryptanalytic studies that have reduced the
security of the assumption below that implied by the group instantiation (for
example, {{BG04}} and {{Cheon06}}). In summary, the attacks reduce the security
of the group instantiation by log_2(Q) bits.

As an example, suppose that a group instantiation is used that provides 128 bits
of security. Then an adversary with access to a Q-sDH oracle and makes Q=2^20
queries can reduce the security of the instantiation by log_2(2^20) = 20 bits.

Notice that it is easy to instantiate a Q-sDH oracle using the OPRF
functionality that we provide. A client can just submit sequential queries of
the form (G, kG, (k^2)G, ..., (k^(Q-1))G), where each query is the output of
the previous interaction. This means that any client that submit Q queries to
the OPRF can use the aforementioned attacks to reduce security of the group
instantiation by log_2(Q) bits.

Recall that from a malicious client's perspective, the adversary wins if they
can distinguish the OPRF interaction from a protocol that computes the ideal
functionality provided by the PRF.

### Implications for ciphersuite choices

The OPRF instantiations that we recommend in this document are informed by the
cryptanalytic discussion above. In particular, choosing elliptic curves
configurations that describe 128-bit group instantiations would appear to in
fact instantiate an OPRF with 128-log_2(Q) bits of security.

While it would require an informed and persistent attacker to launch a highly
expensive attack to reduce security to anything much below 100 bits of security,
we see this possibility as something that may result in problems in the future.
Therefore, all of our ciphersuites in {{ciphersuites}} come with a minimum group
instantiation corresponding to 196 bits of security. This would require an
adversary to launch a minimum of Q = 2^(68) queries to reduce security to 128
bits using the Q-sDH attacks. As a result, it appears prohibitively expensive to
launch credible attacks on these parameters with our current understanding of
the attack surface.

## Hashing to curve

A critical aspect of implementing this protocol using elliptic curve group
instantiations is a method of instantiating the function H1, that maps inputs to
group elements. In the elliptic curve setting, this must be a deterministic
function that maps arbitrary inputs x (as bytes) to uniformly chosen points in
the curve.

In the security proof of the construction H1 is modeled as a random oracle. This
implies that any instantiation of H1 must be pre-image and collision resistant.
In {{ciphersuites}} we give instantiations of this functionality based on the
functions described in {{I-D.irtf-cfrg-hash-to-curve}}. Consequently, any OPRF
implementation must adhere to the implementation and security considerations
discussed in {{I-D.irtf-cfrg-hash-to-curve}} when instantiating the function H1.

## Timing Leaks

To ensure no information is leaked during protocol execution, all operations
that use secret data MUST be constant time. Operations that SHOULD be constant
time include: H_1() (hashing arbitrary strings to curves) and DLEQ_Generate().
As mentioned previously, {{I-D.irtf-cfrg-hash-to-curve}} describes various
algorithms for constant-time implementations of H_1.

## User segregation

The aim of the OPRF functionality is to allow clients receive pseudorandom
function evaluations on their own inputs, without compromising their own privacy
with respect to the server. In many applications (for example, {{PrivacyPass}})
the client may choose to reveal their original input, after an invocation of the
OPRF protocol, along with their OPRF output. This can prove to the server that
it has received a valid OPRF output in the past. Since the server does not
reveal learn anything about the OPRF output, it should not be able to link the
client to any previous protocol instantiation.

Consider a malicious server that manages to segregate the user base into
different sets. Then this reduces the effective privacy of all of the clients
involved, since the client above belongs to a smaller set of users than
previously hoped. In general, if the user-base of the OPRF functionality is
quite small, then the obliviousness of clients is limited. That is, smaller
user-bases mean that the server is able to identify client's with higher
certainty.

In summary, an OPRF instantiation effectively comes with an additional privacy
parameter pp. If all clients of the OPRF make one query and then subsequently
reveal their OPRF input afterwards, then the server should be link the revealed
input to a protocol instantiation with probability 1/pp.

Below, we provide a few techniques that could be used to abuse client-privacy in
the OPRF construction by segregating the user-base, along with some mitigations.

### Linkage patterns

If the server is able to ascertain patterns of usage for some clients -- such as
timings associated with usage -- then the effective privacy of the clients is
reduced to the number of users that fit each usage pattern. Along with early
registration patterns, where early adopters initially have less privacy due to a
low number of registered users, such problems are inherent to any
anonymity-preserving system.

### Evaluation on multiple keys {#multiple-keys}

Such an attack consists of the server evaluating the OPRF on multiple different
keys related to the number of clients that use the functionality. As an extreme,
the server could evaluate the OPRF with a different key for each client. If the
client then revealed their hidden information at a later date then the server
would immediately know which initial request they launched.

The VOPRF variant helps mitigate this attack since each server evaluation can be
bound to a known public key. However, there are still ways that the VOPRF
construction can be abused. In particular:

- If the server successfully provisions a large number of keys that are trusted
  by clients, then the server can divide the user-base by the number of keys
  that are currently in use. As such, clients should only trust a small number
  (2 or 3 ideally) of server keys at any one time. Additionally, a tamper-proof
  audit log system akin to existing work on Key Transparency {{keytrans}} could
  be used to ensure that a server is abiding by the key policy. This would force
  the server to be held accountable for their key updates, and thus higher key
  update frequencies can be better managed on the client-side.

- If the server rotates their key frequently, then this may result in client's
  holding out-of-date information from a past interaction. Such information can
  also be used to segregate the user-base based on the last time that they
  accessed the OPRF protocol. Similarly to the above, server key rotations must
  be kept to relatively infrequent intervals (such as once per month). This will
  prevent too many clients from being segregated into different groups related
  to the time that they accessed the functionality. There are viable reasons for
  rotating the server key (for protecting against malicious clients) that we
  address more closely in {{key-rotation}}.

Since key provisioning requires careful handling, all public keys should be
accessible from a client-trusted registry with a way of auditing the history of
key updates. We also recommend that public keys have a corresponding expiry date
that clients can use to prevent the server from using keys that have been
provisioned for a long period of time.

## Key rotation {#key-rotation}

Since the server's key is critical to security, the longer it is exposed by
performing (V)OPRF operations on client inputs, the longer it is possible that
the key can be compromised. For instance, if the key is kept in production for a
long period of time, then this may grant the client the ability to hoard large
numbers of tokens. This has negative impacts for some of the applications that
we consider in {{apps}}. As another example, if the key is kept in circulation
for a long period of time, then it also allows the clients to make enough
queries to launch more powerful variants of the Q-sDH attacks from {{qsdh}}.

To combat attacks of this nature, regular key rotation should be employed on the
server-side. A suitable key-cycle for a key used to compute (V)OPRF evaluations
would be between one week and six months.

As we discussed in {{multiple-keys}}, key rotation cycles that are too frequent
(in the order of days) can lead to large segregation of the wider user base. As
such, the length of the key cycles represent a trade-off between greater server
key security (for shorter cycles), and better client privacy (for longer
cycles). In situations where client privacy is paramount, longer key cycles
should be employed. Otherwise, shorter key cycles can be managed if the server
uses a Key Transparency-type system {{keytrans}}; this allows clients to
publicly audit their rotations.

# Applications {#apps}

This section describes various applications of the (V)OPRF protocol.

## Privacy Pass

This VOPRF protocol is used by the Privacy Pass system {{PrivacyPass}} to help
Tor users bypass CAPTCHA challenges. Their system works as follows. Client C
connects -- through Tor -- to an edge server E serving content. Upon receipt, E
serves a CAPTCHA to C, who then solves the CAPTCHA and supplies, in response, n
blinded points. E verifies the CAPTCHA response and, if valid, signs (at most) n
blinded points, which are then returned to C along with a batched DLEQ proof. C
stores the tokens if the batched proof verifies correctly. When C attempts to
connect to E again and is prompted with a CAPTCHA, C uses one of the unblinded
and signed points, or tokens, to derive a shared symmetric key sk used to MAC
the CAPTCHA challenge. C sends the CAPTCHA, MAC, and token input x to E, who can
use x to derive sk and verify the CAPTCHA MAC. Thus, each token is used at most
once by the system.

The Privacy Pass implementation uses the P-256 instantiation of the VOPRF
protocol. For more details, see {{DGSTV18}}.

## Private Password Checker

In this application, let D be a collection of plaintext passwords obtained by
prover P. For each password p in D, P computes VerifiableEvaluate on H_1(p), where H_1
is as described above, and stores the result in a separate collection D'. P then
publishes D' with Y, its public key. If a client C wishes to query D' for a
password p', it runs the VOPRF protocol using p as input x to obtain output y.
By construction, y will be the OPRF evaluation of p hashed onto the curve. C can
then search D' for y to determine if there is a match.

Concrete examples of important applications in the password domain include:

- password-protected storage {{JKK14}}, {{JKKX16}};
- perfectly-hiding password management {{SJKS17}};
- password-protected secret-sharing {{JKKX17}}.

### Parameter Commitments

For some applications, it may be desirable for P to bind tokens to certain
parameters, e.g., protocol versions, ciphersuites, etc. To accomplish this, P
should use a distinct scalar for each parameter combination. Upon redemption of
a token T from V, P can later verify that T was generated using the scalar
associated with the corresponding parameters.

# Acknowledgements

This document resulted from the work of the Privacy Pass team {{PrivacyPass}}.
The authors would also like to acknowledge the helpful conversations with Hugo
Krawczyk. Eli-Shaoul Khedouri provided additional review and comments on key
consistency.

--- back

# Test Vectors {#testvecs}

We provide test vectors for each of the supported VOPRF ciphersuites below. The
test vectors are also available at
https://github.com/alxdavids/voprf-poc/tree/master/test_vectors.

## VOPRF-P384-HKDF-SHA512-SSWU-RO

[
    {
        "key": "731eb0cbe382f110010d354e3fa36f6512bd056daf3f3d00996ae3ac642e
        db4726d410db80c2321771a93f0308ded9c9",
        "pub_key": "025f59ac8471663cc47be651b3e4315467aff9ec595a82d65fb7b11c
        33ca0e387c0238299040e2c7ae852795b0696d987c",
        "inputs": [
            "00",
            "01",
            "0100010001000100",
            "0001000100010001",
            "0101010101010101",
            "01000100010001000100010001000100",
            "00010001000100010001000100010001",
            "01010101010101010101010101010101"
        ],
        "blinds": [
            "7b",
            "04d2",
            "3039",
            "01e240",
            "12d687",
            "bc614e",
            "075bcd15",
            "499602d2"
        ],
        "dleq_scalar": "9d92c4cc962347d56c05e4b749b57e70461145af696ab61cdefb
        29f8f88162980410d27fdebad4440431ca0efbffead2",
        "expected": {
            "outputs": [
                "62862c10cc62001c0ead55317caf37fd66de419cab18bbaf9965989c269
                d8717dcd09871ff7023b9f5ab118d9c47c87476b3217ddd30ac8a23373b9
                55349f6ed",
                "0f167282edf6cc354ba2adcf9df5b9819e4e08daf4cff5dc51848c75b83
                fb12aea8def4a6963c5a651891aa2d71a4f963d42cd31dc61f5ab671ea37
                8cf372e30",
                "e2357a8e13c73fba80828c6c0760997c374918c9837b424ea0c4d15a825
                b1dfd10a4a9646fd81b620714cb0dc1ea17c6871fac174b22e6b665b7e21
                b6082cd1e",
                "da1e53c0b880bded06ebd105e7bb60354b745c08b772232f53c50850ef1
                798e81fc9461e26a9f9df40c17bfac0c7dd58a3bfceae0c0883c80bb7fdd
                46c8bee7f",
                "91acbbac2668f75ff231d862cd32a635f73b1f624b93ac9d36f13942752
                0ca50d5f657533fa657ae1322eb19ed6a7f65d89281c59fcaa560d46121d
                877981679",
                "7b532ca7b02b5a531a4444e0c85f82ed7f8d9f073eb4979841cb843a385
                11d16fa7724b78b2b7d656b12478d062b4ce21ed130f8b9b9db841bd67c9
                f6bd87689",
                "3271c215ddb5cf3d1ad3fe6513a2765905fd6be207c8fc9062e00430329
                340ec285677aec5c7a8ed75348d92ff8086234ffcee88b626bfa0b4974d0
                4e32556b7",
                "f440b7bbb4e02a2088b70577b4d6fc523b4c6dbe14ab7d492a77115f93b
                ea45a7fc12c9abc4ce6ece8a68bd0dd33ae9004e73573d70c8c1018b15e1
                7394458df"
            ],
            "elems": [
                "02650b114365827575dd44c4f5d969f946e2c2268b12b05bd3741743c26
                11cf3bf61606ca0d3b6cec3ab70c4bd845f3a59",
                "03d2a8d7a707ac847b01bd031ae37f60fd16a7be869eb0d79653d84b44b
                df845abc233d7f7bc66152565574c46dfa085d6",
                "02e92fdca59a89094862f7853fe7ce0c963d01ea67bdd10feebd3c9d98b
                0734b1735d69b014a84f9ef9fe6eba2e18948ae",
                "0389f765b94a34a794f047f85e8d46b3f17fd6461d4227278c607b92d0c
                b64530117b1f7ede0daed2ddb43b347a3c0a583",
                "0358a580794075880be347f0b006f13c497b612b2f2030602ed1c14b0fd
                d520d1dbff8c0c9d15b0e703e57817d227b0736",
                "03e916ee7f684cd9d735af868ae4e39bffa4cfe28bba6327444201afffa
                4d431e4481b778a3454784bf4586a08db03e55e",
                "026b8b35916b3217f7203fc96f51fb6fbabb17ff34f6fcc2548bbaa989a
                f3f42de5ad58196cf9523a9052602ea2a8a88d1",
                "023c70ab988399d3e7c7dc915444b3ed9ae1071e607c99a1e48df17a20
                39b1f19a32ee1a90570ba5daf4744877bcf16fc4"
            ],
            "proof": [
                "03b2c30d1477bb76b6904acb2ddc9d952295bade5648797c12e103db68db
                54aa03e900bf75c0d24a59aaae6f832d9077",
                "60baab33479cbf74bb946629d7befcbe415331d1a0584ff7e56abe73f5a2
                e5aa93f563a3a1f1448538adda6f54ddd2f4"
            ]
        }
    },
    {
        "key": "e03aa64d63cee2619a115eaa935078020a1c79634afaa163d867061a68b9
        bd7eb821badf2d1a725263fc11e4c712c40a",
        "pub_key": "030f290e5d9ec013f30968a4db66f36c20fd204a06bb8edf805a1936
        af744acde2f906f7190f2c206516fc49d23c65a424",
        "inputs": [
            "00",
            "01",
            "0100010001000100",
            "0001000100010001",
            "0101010101010101",
            "01000100010001000100010001000100",
            "00010001000100010001000100010001",
            "01010101010101010101010101010101"
        ],
        "blinds": [
            "7b",
            "04d2",
            "3039",
            "01e240",
            "12d687",
            "bc614e",
            "075bcd15",
            "499602d2"
        ],
        "dleq_scalar": "7e9d53e392518f0f7ec1ae1189ac5165288aa242849127a60764
        fd72b7f394c5d2f014830c18359000eb0f3e50815ae6",
        "expected": {
            "outputs": [
                "e7fb4f4619e5541e113bf0e68767086855072ff2cd1e3e222307ffe6f5a
                f14f9cb4424fbbbb1e2eaec4631104d5645e58855e22c35509f647f72d3f
                4b29d8373",
                "3ae97f3b02ffe5d6c4d75dd6d77712ce6b817b8f827790e728e10e14b8b
                4ca61266d737d1995499f1646c668d0273092de491864f6fef91abe0c50a
                89d54faf7",
                "565e61b03b1422701d782bf1935278591c00b200eb72ede7d8f7169e77c
                336490183c2dc89fccebb62da0c43c34ef9d0d0824a42f5c5397563d5349
                49044e248",
                "42a63aceed782bd8b08b7fd12941c04e3baa7255dae026cc95c5d714f97
                a25c0180239c21ab847f6dfcebb968e0c3f99cc1d84eb87cf413cc089e90
                27c52a9d1",
                "06c22db36f0876f53c6ff4b1875f609abddf7208e3e747b81f0c772292d
                a60f0363d27c1b4caee154f76a0a39a7826bea0cee7882ed210ff3134ccf
                89b6168ef",
                "6b8784f44a66f46e30a0c24aee3abbec7f5a044a522f57261e3b3d3644c
                a50d3c6450296058acc83355ec350261c40fcd7ac4dff6fcf59dac6dadab
                2808ffd66",
                "f88759ca0a7cf2ceab7ae80d6d8906e9bc0e2250f6170068e727cb92883
                2da8f06c02f40b78d0f65402e3ad368f9520be59049eaea4ade7f792096a
                7a9682afe",
                "a3ff55d06b8639a297d243ed042b582ca44dc7085960bb0c8e3f6825608
                c209acaae543f7376541beb5c68ed87b3118e3a1579a8f919f7aa245c901
                1e06a2536"
            ],
            "elems": [
                "0220a62ad299995beb3dc0ff790e168ba282f0ed8e18aa2508d3e0e8636
                236db77a76ac1cceebd51c0b1f5f97506f4f938",
                "03fbd3c7d896b794eee0e099ebfe3c17d38015d787d235e264d5284bcbc
                0cd701323ced2cf83bfda3110d3df6465f00f2c",
                "03b0ebebb7d92348e9e42d0645be49cebbcbbf4344faf677ddd35eb2ef4
                473608fca28e98d34f6846f5d585af01ff68957",
                "036d05eb00b87c438dce33afddb4cfac65c2d954507e7063afded3b424a
                742e6f810af9b4e309d174d587da86286317d57",
                "02d5257532756b69525f5984f4adbb3b16e1178d3a6a1498bbef84671f8
                0dd8a2dcf8bbc0c25f59b631a017420061f020b",
                "02fda5f164854a7e08c9b1e91e3ec8369caac04ac7cb21feae9f5a22218
                5e150f14bf987efcbb674ff491795f4bb1ea490",
                "02cc7734abaccc99eefbff344f5f018dc58788ccb816afd4be7545b284e
                cbf709a8a5f27a3e229c8b8f5bb1c7acbb35c3b",
                "03334b715f7f876bf8e45a359cd81ba51f8717fda6a96ea86c4260ad02
                4f47a159315fbcce2fcfb15c212b1417de20f6f3"
            ],
            "proof": [
                "bbc63167511afe845c7b6497e72db2ff200fc2d68017f79f8591b0f82f23
                aea378cd5d22c1a0b0bb9fc8ac68b5fb112b",
                "b10ff924f1b6a38f917583c1b1fc611a1cf42bdf7a31c7b8954f00ab012d
                70dc29414e29020e12a969c8e3d9ea6b056d"
            ]
        }
    },
    {
        "key": "add920962f2357f2a25e8a7598e61adddee59a6260bf6e7de812d275192a
        c827e59cf4379b3394f5f32a0f69e9feae58",
        "pub_key": "02212af8bde4c9992406b9537fe7c3d232b5fd8328eb4bbc5965f735
        24cdf5d982c69ea565dcafd73f86f330fc64cfbefe",
        "inputs": [
            "00",
            "01",
            "0100010001000100",
            "0001000100010001",
            "0101010101010101",
            "01000100010001000100010001000100",
            "00010001000100010001000100010001",
            "01010101010101010101010101010101"
        ],
        "blinds": [
            "7b",
            "04d2",
            "3039",
            "01e240",
            "12d687",
            "bc614e",
            "075bcd15",
            "499602d2"
        ],
        "dleq_scalar": "82fd80c3fe595bb7108bdbb3247736141c0b4575bcd04216ae6a
        c988b6a001f80913ce0bfe639cd69a31f0f9739676b6",
        "expected": {
            "outputs": [
                "81cc43d3192c0bcdd55f4835f92cc65cc42d6957a9480b50d33484b8779
                341c96be34ad58adac00b20b8b661d594be3da0f0d255ec6ead2a23d7f0b
                cbb6d77c2",
                "29a0a4ea5f3920dba0f3be05e5f7918274289d53ccc5e514ac138bfd4e7
                b8b29a27fbc68bb4cf0447afbb9201c3ff9bf294694905577bfc468a9103
                f3efe7fc6",
                "8e1a78d70858444282e7f7044aa60d75faaf0d36878a5bc8cc6ef7c11e8
                d030a59356fb1b801b0505497988a9e9e31659bc69debedd1ed3edbd246c
                8d23f1362",
                "e374b45a66809de3613ca14342e5776ed10469e7c4bc51c97deb3c91b2d
                419355b56d58b295894b0f151d5bf98ccefef378ab3f4204be47dc8fb9fd
                2facdeb17",
                "87dbaa98580b29d9c948e2c749d4db4dc7d190eb324d414d05c6f1580b5
                499277da756e72fb57539ff9327df538b5871daa1e9ccc7f256c031a3508
                271ddd754",
                "303aa570854f0115e01ef6b6059619811f2344650a578942f3a11a7a3af
                6e2606980e0af0eb5d940e4b87eed7aa7d15f3ede36084f242a0d3deecd6
                2ef96740a",
                "3d94987ae147f0e61148a9b0373b9e2cbab628aef6a625f3e406cfea4d9
                9e6a71dfa34b8b741b522c8bd7f5972781f055f01e1d11665984406dd579
                7cacc7b8e",
                "c1a838ad9fd0cf835842badfbe0cf68a17eacba2ce26fe5ca8b76c7acef
                1241103ce8a0ad487ae63492f8f51ffe5e207ff150767e200b7594dfb9e5
                f4e6a6b5b"
            ],
            "elems": [
                "0353c281491fc064dc3a94f519354e885048b8424161e0d9d296aac4c62
                6a02ac84e99610853ba10b84edc33875dd12599",
                "03c1729c9aa01a7ba5249054877f0fde1538c88ac962e974c0af138da8d
                216e93cd9086bc269b39c24f3b02797ef451fd1",
                "03817ab7c49061eaf67feb2e4f4af1e81d1a05db10620f9f56a76b52ce8
                dad827ff81764eac236b892a5c485e27a166457",
                "026a61d2690a9f6b56d5165f2aa76485eeef202b403b707451684ae8eb3
                80d14f31bc1649719c3dbc84b39745ba305988a",
                "034bd094d573498d6bf42fa2b9c79fdae00b3af2438a3c73be77922eedf
                020b4bed8326136002ca86a0c1012cde4c93b91",
                "0261bca0c977b096fb6d4dfdd45c6c58b0b33c12cc10bd1aa70fc277904
                a7bdea498616ed038c327d147f68d7e93a0a79a",
                "030f53c77480802aa5ee57b6cc8c9b44eae49f8ff2872c6d4a678c0baf6
                c2c59ea39f2720fbde590e62eeb3031bfb77d32",
                "022417e7f823c64c769851cad880c633c0d90fe94c3203fb8c458621ab
                2536c89445eb9d3c4c8bb72e174f8939fdfde537"
            ],
            "proof": [
                "c00d1ca2d523623158ba96c756f7ac154bf0a66f2af736699f5dbf38417d
                fe3f100c13cedd356b23d90bbd1951e76847",
                "7be22583c315fb855073d04f1fe4d42f1052a2cb48232a22ec6bd790093b
                49753eafa4c3247a3222d833df44abce9914"
            ]
        }
    },
    {
        "key": "45dbb94555268dec4da829517204d7ef091e5014ec0a3ec71da7eaf6377a
        74c303c143ca79449543a5801beed9be8213",
        "pub_key": "028b2a0de4e013318fc62a4f36adebb313de6692ea56787cf4a21590
        bfb632390a9b16595eb39b34b88c40a50544b2c2df",
        "inputs": [
            "0100010001000100"
        ],
        "blinds": [
            "499602d2"
        ],
        "dleq_scalar": "7341a6b54c0e52215b38deec13c05b9c9d6a12deda973a206815
        75ef4971888dd8f8bc1eee970bd8dead370e542c5ebe",
        "expected": {
            "outputs": [
                "01d699e0ef4628c9e8be646ed9b6ded78c9799f3b09afe1c57dbff6dd4e
                3265952a5c8fcd329c40f70fe84a001952a071c60ff0e4b735f2c6f79bd8
                160d561bc"
            ],
            "elems": [
                "0315f23b8840f0ef58926e12de984b5d5cc3db0fea0e001f78229cdff33
                1852d47888120ef8c0837796691ca6a523aab48"
            ],
            "proof": [
                "d494b90b014ec77c34f41d0dffb21d717182d62c5c58fcaf5ec084d0904b
                1a8a1fe6fa65a65b59eff0660e931bc24fb3",
                "45b3b04b0bbdbf3884c0d48a4946d75c57fa509c3373acf5069844ceb6e6
                0dfa90624a0576d4723b09c876e990976d2b"
            ]
        }
    },
    {
        "key": "45dbb94555268dec4da829517204d7ef091e5014ec0a3ec71da7eaf6377a
        74c303c143ca79449543a5801beed9be8213",
        "pub_key": "028b2a0de4e013318fc62a4f36adebb313de6692ea56787cf4a21590
        bfb632390a9b16595eb39b34b88c40a50544b2c2df",
        "inputs": [
            "01000100010001000100010001000100"
        ],
        "blinds": [
            "075bcd15"
        ],
        "dleq_scalar": "7341a6b54c0e52215b38deec13c05b9c9d6a12deda973a206815
        75ef4971888dd8f8bc1eee970bd8dead370e542c5ebe",
        "expected": {
            "outputs": [
                "ef53462fbdee3cdb84a703fa350d16cd672bc6a96a63e65cf5196ee8973
                8336e94a8e275e151435ef3bd199cac74bf2fecfb31aed41501e2ec4626a
                130375ff4"
            ],
            "elems": [
                "02345ccbedb2230e12bebb1274a90776e129cd0b29e13e38befe8a011f9
                0277b27cf1a473b049fc879bc033c998c72b961"
            ],
            "proof": [
                "018d8dec1c6d4cfbbbdd1c3cd2cf219c3515fdaa90b8a558478b59f8c0f7
                df78d52ae81cca2f254e7d4a176884d744e3",
                "9ef6939141fd402efc88ad66812cfced0e97d083b9a8d6eae7422773074c
                673080f2d51955dd852e8f9fb8a2480f5aea"
            ]
        }
    },
    {
        "key": "45dbb94555268dec4da829517204d7ef091e5014ec0a3ec71da7eaf6377a
        74c303c143ca79449543a5801beed9be8213",
        "pub_key": "028b2a0de4e013318fc62a4f36adebb313de6692ea56787cf4a21590
        bfb632390a9b16595eb39b34b88c40a50544b2c2df",
        "inputs": [
            "00"
        ],
        "blinds": [
            "bc614e"
        ],
        "dleq_scalar": "7341a6b54c0e52215b38deec13c05b9c9d6a12deda973a206815
        75ef4971888dd8f8bc1eee970bd8dead370e542c5ebe",
        "expected": {
            "outputs": [
                "988f7df7c7c9f5a274cd6662f91fe12092296d729828b5bf59d99bd3b66
                aaf2461f912e4f84a0a22ce7f5286ee78b00eb228df301ef5e57cce81e91
                ff9582bc1"
            ],
            "elems": [
                "02f620116d4da317e40787a4761bd30f8336c259c1b14816bee7da85e4e
                f3f8ba08a618622de76148a0ef47812bef88600"
            ],
            "proof": [
                "ab3ce8f601a732fc2049abd6ebdccda37a1eea4fc27899ba2ec9d9eb9c70
                8ae430ae22bdd84bbda6d6f1e5803dbc526b",
                "f013292302443c28f502b86d99a06612d4a22a36443b70845b875e249411
                5f57f10cb13e89e4c36a80318a419b09ff36"
            ]
        }
    },
    {
        "key": "2a96a10ef8cf94bcc978736079c0771392e76d7b3d87085ef04752b2e8d4
        e037965d233cc63ab10513294140ded230ae",
        "pub_key": "035b266efc0c4277a09e0ba29e333f7c140b401ddc6f1ef99a9bc706
        451098c4f50eac251243e0daaa5cf675aeadbb47e1",
        "inputs": [
            "0100010001000100"
        ],
        "blinds": [
            "499602d2"
        ],
        "dleq_scalar": "ed0263634549a9f7618c32871f81080e036ccebb58f78d7d1d22
        affece91a06775249f9ce3eeb6b8c61a0d6f66bce610",
        "expected": {
            "outputs": [
                "e78e0ad1e24b4dca808634f5190b42c9a3ca129b83174fdeef6af8496ba
                0b949e54fb0f64be3ad0cdeb0cf550a16a6e30b6aa1da8b4fb6508676963
                28c8dbbed"
            ],
            "elems": [
                "02828a27221d4e1f077c38a228f8674150b9bf1cb6527917ebcf3b0686c
                4570878ae949c341126dd2c49df6b6baf23eedd"
            ],
            "proof": [
                "1d9139062e2d6d0a974a60cea6544dead5411c8e9ac46ed789150c97268c
                14504ede590ed823a970cc4939d97bd42d90",
                "b6ddb0239170248b3ffef46f619aef9f33ba483c63adeb6c52a08a223142
                9d59ec1e140049546c6ceb3a9d5cbb47f26b"
            ]
        }
    },
    {
        "key": "2a96a10ef8cf94bcc978736079c0771392e76d7b3d87085ef04752b2e8d4
        e037965d233cc63ab10513294140ded230ae",
        "pub_key": "035b266efc0c4277a09e0ba29e333f7c140b401ddc6f1ef99a9bc706
        451098c4f50eac251243e0daaa5cf675aeadbb47e1",
        "inputs": [
            "01000100010001000100010001000100"
        ],
        "blinds": [
            "075bcd15"
        ],
        "dleq_scalar": "ed0263634549a9f7618c32871f81080e036ccebb58f78d7d1d22
        affece91a06775249f9ce3eeb6b8c61a0d6f66bce610",
        "expected": {
            "outputs": [
                "9cecf434b60237a22b05546764f73b61c31c207d961934566a734d6f55c
                f0b7c133c62486947a3c5c820b0cee83d0d5fa159825f6b24af57cf43b21
                bc3f78b1e"
            ],
            "elems": [
                "0333726022a973c46964c2fb943adb298eade71609c594d04492c1d1a38
                23d55b6e874f809cae86aa3726362a47b3eea56"
            ],
            "proof": [
                "d8140109b9468e3e49e8adef611d15fab8eddbbbec32273665b35b35d46e
                a223d41abc1ca5bd9a5be32decfb9905fe2c",
                "aa43e41f83c2c59344b07637fb45f4934cf20608a97ad9c1be2d16dd949a
                d0819d7a39ecc453c0386409aa4a7a5111bc"
            ]
        }
    },
    {
        "key": "2a96a10ef8cf94bcc978736079c0771392e76d7b3d87085ef04752b2e8d4
        e037965d233cc63ab10513294140ded230ae",
        "pub_key": "035b266efc0c4277a09e0ba29e333f7c140b401ddc6f1ef99a9bc706
        451098c4f50eac251243e0daaa5cf675aeadbb47e1",
        "inputs": [
            "00"
        ],
        "blinds": [
            "bc614e"
        ],
        "dleq_scalar": "ed0263634549a9f7618c32871f81080e036ccebb58f78d7d1d22
        affece91a06775249f9ce3eeb6b8c61a0d6f66bce610",
        "expected": {
            "outputs": [
                "67f4c9221b309e4c1605eaba6e6ace091d8e8a80dda4662e4fd165ec4b1
                04ba4428409dabaf7573fc58553aa5d19dae06dcd42532b84efbe94ec52c
                205eeb85f"
            ],
            "elems": [
                "03d8206a434fe2775c46894c05972015a8b8754b82f9e3e34a16371a3ae
                7e31621d30d3199d87a5471b3769cc90a03b4c9"
            ],
            "proof": [
                "5c888a6d080a4d143684c441c2e5399fa1ac1b7e779d62ddbd347232db5a
                21a56ba5184f4782cbebdd462fbb7f8928f9",
                "20c39f9a26a0af45a1448e3f2b1e842311c5a824b59350b4fedf0919c7b4
                1ad8f4fb009029bfbd08fad3234a0cffc855"
            ]
        }
    }
]

## VOPRF-P521-HKDF-SHA512-SSWU-RO

TODO: P521 test vectors

## VOPRF-curve448-HKDF-SHA512-ELL2-RO

TODO: curve448 test vectors