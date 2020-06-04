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
function with secret key k on input x. Roughly, F is pseudorandom if the
output y = F(k, x) is indistinguishable from uniformly sampling any
element in F's range for random choice of k. An oblivious PRF (OPRF) is
a two-party protocol between a Server and a Client, where Server holds a
PRF key k and Client holds some input x. The protocol allows both parties to
cooperate in computing F(k, x) with Server's secret key k and Client's input x
such that: Client learns F(k, x) without learning anything about k; and P
does not learn anything about x. A Verifiable OPRF (VOPRF) is an OPRF
wherein Client can prove to Server that F(k, x) was computed using key
k, which is bound to a trusted public key Y = k * G, and G is the
generator of a group. Informally, this is done by presenting a
non-interactive zero-knowledge (NIZK) proof of equality between (G, Y)
and (Z, M), where Z and M are group elements such that Z = k * M.

OPRFs have been shown to be useful for constructing: password-protected
secret sharing schemes {{JKK14}}; privacy-preserving password stores
{{SJKS17}}; and password-authenticated key exchange or PAKE {{OPAQUE}}.
VOPRFs are useful for producing tokens that are verifiable by Client. This
may be needed, for example, if Client wants assurance that Server did not use a
unique key in its computation, i.e., if Client wants key consistency from Server.
This property is necessary in some applications, e.g., the Privacy Pass
protocol {{PrivacyPass}}, wherein this VOPRF is used to generate
one-time authentication tokens to bypass CAPTCHA challenges. VOPRFs have
also been used for password-protected secret sharing schemes e.g.
{{JKKX16}}.

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
  functionality using prime-order groups.
- {{api}}: A list of API functions that are used to instantiate the
  protocols from {{protocol}}.
- {{dleq}}: Specify the NIZK discrete logarithm equality (DLEQ)
  construction used for constructing the VOPRF protocol.
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

We start by detailing some necessary cryptographic definitions.

## Security Properties {#properties}

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

- Oblivious: Server must learn nothing about Client's input or the output of the
  function. In addition, Client must learn nothing about Server's private key.

Essentially, obliviousness tells us that, even if Server learns Client's input x
at some point in the future, then Server will not be able to link any
particular OPRF evaluation to x. This property is also known as
unlinkability {{DGSTV18}}.

Optionally, for any protocol that satisfies the above properties, there
is an additional security property:

- Verifiable: Client must only complete execution of the protocol if it can
  successfully assert that the OPRF output it computes is correct,
  with respect to the OPRF key held by Server.

Any OPRF that satisfies the 'verifiable' security property is known as a
verifiable OPRF, or VOPRF for short. In practice, the notion of
verifiability requires that Server commits to the key k before the actual
protocol execution takes place. Then Client verifies that Server has used k in the
protocol using this commitment. In the following, we may also refer to
this commitment as a public key.

## Prime-order group API {#pog}

In this document, we assume the construction of an additive, prime-order
group `GG` for performing all mathematical operations. Such groups are
uniquely determined by the choice of the prime `p` that defines the
order of the group. The fundamental group operation is addition (+) Specifically, for any 
elements `A` and `B` that are members of the group `GG`, `A + B = B + A` is also a member 
of `GG`. Scalar multiplication (*) is an efficient method for repeated addition operations. 
Given a scalar `r` in `GF(p)` and element `A` in `GG`, `r*A = A + ... + A` (`r` times). 

Note that prime-order groups also define an inverse function such that
the following property holds:

- for any `A` in `GG` there exists `-A` where `A + (-A) = (-A) + A = I`.

However, we don't explicit use of the inverse property in our protocol,
and so we don't explicitly assume these properties within the public
API.

We now detail a number of member functions that can be invoked on a
prime-order group.

- Order(): Outputs the order of the group as a scalar (i.e. `p`).
- Generator(): Takes no inputs and outputs a fixed generator `G` for the
  group.
- Identity(): Takes no inputs and outputs the identity element of the
  group.
- Serialize(): A member function of `GG` that maps a group element `A`
  to a unique array of bytes `buf` that corresponds uniquely to the
  point `A`.
- Deserialize(): A member function of `GG` that maps an array of bytes
  `buf` to a group element `A`.
- HashToGroup(): A member function of `GG` that deterministically maps
  an array of bytes `x` to a random element of `GG`. The map should be
  implemented in such a way that it is computationally difficult for any
  adversary that receives: `R = HashToGroup(x)` without knowing `x` to
  reverse the mapping. For an example of such a mapping to prime-order
  (sub)groups of elliptic curves, see {{I-D.irtf-cfrg-hash-to-curve}}.

Lastly, for any scalar `r` that is an element of the galois field of
scalars `GF(p)` associated with `GG`, we assume it is always written in
network-order byte array format for the purpose of providing wherever it
is supplied as an input or give as an output of a function.

### Group instantiations

It is common in cryptographic applications to instantiate such
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

# Protocol {#protocol}

In this section we describe the OPRF and VOPRF protocols. Recall that
these protocols take place between a client and a server. We will
refer to these participants by Client and Server, respectively, throughout. The Server holds a secret key k for a PRF. The protocol
allows the client to learn PRF evaluations on chosen inputs x in such a
way that the Server learns nothing of x.

## Overview {#overview}

Let GG be an additive group of prime-order p with the interface defined
in {{pog}}, let GF(p) be the Galois field defined by the integers modulo
p. Define distinct hash functions H_1 and H_2, where:

- `H_1(x) = GG.HashToGroup(x)` for a byte array `x`;
- `H_2(x, y) = z`, where `x`, `y`, `z` are fixed-length byte arrays.

All hash functions in the protocol are modeled as random oracles. Let
`k` be the Server's private key, and `Y = k * G` be its corresponding
public key, for the fixed generator `G` of `GG`. This public key is also
referred to as a commitment to the OPRF key `k`. Let x be the byte array
that is the Server's input to the OPRF protocol (this can be of
arbitrary length). We provide an overview of the protocol below as an
introduction to the general flow. We will describe the functionality
using interface function calls in {{api}}.

The OPRF protocol begins with Client blinding its input for the OPRF
evaluator such that it appears uniformly distributed from GG. The
Server then multiplies the blinded value by its private key and returns
the resulting element. To finish the protocol, Client then removes its blind
and uses H_2 to hash the result (along with a domain separating label
DST) yielding an output. This flow is illustrated below.

~~~
     Client(x)                   Server(k)
  ----------------------------------------------------------
     r <-$ GF(p)
     M = rH_1(x)
                           M
                        ------->

                              Z = k * M mod p
                              [[ D = generate_zk_proof(k,G,Y,M,Z) ]]

                          Z[[, D]]
                        <-------
    [[ b = verify_zk_proof(G,Y,M,Z,D) ]]
    N = r^(-1) * Z mod p
    Output H_2(DST, x || N) mod p [if (b=0): abort]
~~~

Steps enclosed in `[[ ]]` are REQUIRED for verifiability.
These functions are described in {{dleq}}. In the verifiable mode, 
we assume that Server's public key is known by Client. 

Strictly speaking, the actual PRF function that is computed is:

~~~
F(k, x) = N = kH_1(x)
~~~

This output is computed when the Client computes r^(-1) * Z by the
commutativity of the multiplication. Client finishes the computation
by outputting H_2(DST, x || N). Note that the output from Server is not the
PRF value because the actual input x is blinded by r.

The security of our construction is discussed in more detail in
{{protocol-sec}}.

# Protocol API {#api}

We restate the (V)OPRF protocol using a concrete API that we describe in
{{algorithms}} below.

Firstly, we assume that the server chooses a valid ciphersuite from
{{ciphersuites}} and instantiates the prime-order group `GG` associated
with the ciphersuite. It samples a PrivateKey `k` from `GF(p)`, and
computes the public key `public_key = GG.Serialize(k * G)` where
`G=GG.generator()`. It publishes `(ciphersuite, public_key)` publicly,
so that it is available to any possible clients.

Secondly, before the protocol samples an array of `ClientInput` objects
and provides these as `ins` as their protocol input, along with a DST
`aux`.

Both participants also provide a boolean input `vv` and `vp` for the
Client and Server respectively. These boolean values should be equal,
and correspond to whether the protocol is executed with verifiability
intended, or not. In other words, whether the functionality computes an
OPRF protocol (`vv = vp = 0`), or a VOPRF protocol (`vv = vp = 1`). If
`vv = 1 && vp = 0`, then the protocol will abort in `Unblind` when the
client attempts to verify the zero-knowledge proof.

~~~
   Client(ins,aux,vv)                  Server(k,vp)
  ----------------------------------------------------------
    toks, bts = Blind(inputs)

                          bts
                      ---------->

                                  ev = Evaluate(k,public_key,bts,vp)

                           ev
                      <----------
    unb_toks = Unblind(public_key,toks,bts,ev,vv)
    outputs = []
    for i in [ins.length]:
     outputs[i] = Finalize(ins[i],unb_toks[i],aux)
    Output outputs
~~~

In `Blind` the client generates the tokens and blinding data. The Server
computes the (V)OPRF evaluation in `Evaluation` over the client's
blinded tokens. In `Unblind` the client unblinds the server response
(and verifies the Server's proof if verifiability is required). In
`Finalize`, the client outputs a byte array corresponding to each token
that was evaluated over.

Note that in the final output, the client computes Finalize over some
auxiliary input data `aux`. This parameter SHOULD be used for domain
separation in (V)OPRF the protocol. Specifically, any system which has
multiple (V)OPRF applications should use separate aux values to to
ensure finalized outputs are separate. Guidance for constructing aux can
be found in {{I-D.irtf-cfrg-hash-to-curve}}; Section 3.1.

## Data structures {#structs}

The following is a list of data structures that are defined for
providing inputs and outputs for each of the API functions defined in
{{algorithms}}.

The following types are a list of aliases that are used throughout the
protocol.

```
opaque group_id<1..2^16-1>
opaque Scalar<1..2^16-1>;
opaque SerializedGroupElement<1..2^16-1>;
Scalar PrivateKey;
SerializedGroupElement PublicKey;
SerializedGroupElement BlindedToken;
```

A `ClientInput` is simply a byte array.

```
opaque ClientInput<1..2^16-1>
```

A `Token` is an object created by a client when constructing a (V)OPRF
protocol input. It is stored so that it can be used after receiving the
server response.

```
struct {
  opaque input_data<1..2^16-1>;
  opaque blind<1..2^16-1>;
} Token;
```

An `Evaluation` is the type output by the `Evaluate` and
`VerifiableEvaluate` algorithms. The member `proof` is added in the
output of `VerifiableEvaluate` only.

```
struct {
  SerializedGroupElement elements<1..2^16-1>;
  Scalar proof<0...2^16-1>; /* optional */
} Evaluation;
```

## Algorithms

The `verifiable` mode of the protocol (VOPRF) is controlled by a boolean
input to a subset of the functions. Each function assumes knowledge of a
global group `GG` (satisfying the API in {{pog}}) that is published
publicly by the server before the protocol exchange. Note that any
algorithm that takes inputs, or issues outputs of the form `T x[m]`
refers to an array of fixed-size relative to an integer parameter `m`
chosen by the client.

### Blind

~~~
Input:

 ClientInput inputs[m]

Output:

 Token tokens[m]
 BlindedToken blinded_tokens[m]

Steps:

 1. tokens = []
 2. blinded_tokens = []
 3. for i = 0 to m:
    1. r <-$ GF(p)
    2. if r == 0: return to the previous step
    3. P = GG.HashToGroup(inputs[i])
    4. tokens[i] = Token{ data: x, blind: r }
    5. blinded_tokens[i] = GG.Serialize(r * P)
 4. Output (tokens, blinded_tokens)
~~~

This blinding mechanism can be modified slightly with the opportunity
for making performance gains in some scenarios. We detail these
modifications in {{blinding}}.

### Evaluate

~~~
Input:

 PrivateKey k
 PublicKey public_key
 BlindedToken blinded_tokens[m]
 boolean verifiable

Output:

 Evaluation Ev

Steps:

 1. elements = []
 2. for i in 1..m:
    1. BT = GG.Deserialize(blinded_tokens[i])
    2. Z = k * BT
    3. elements[i] = GG.Serialize(Z)
 3. Ev = Evaluation{ elements: elements }
 4. if verifiable:
    1. proof = GenerateProof(k, public_key, blinded_tokens, elements)
    2. Ev.proof = proof
 5. Output Ev
~~~

### Unblind

~~~
Input:

 PublicKey public_key
 Token tokens[m]
 BlindedToken blinded_tokens[m]
 Evaluation ev
 boolean verifiable

Output:

 SerializedGroupElement unblinded_tokens[m]

Steps:

 1. if verifiable:
    1. if (VerifyProof(public_key, blinded_tokens, ev) == false): abort
 2. unblinded_tokens = []
 3. for i = 0 to m:
    1. r = tokens[i].blind
    2. Z = GG.Deserialize(Evaluation.elements[i])
    3. N = (r^(-1)) * Z
    4. unblinded_tokens[i] = GG.Serialize(N)
 4. Output unblinded_tokens
~~~

### Finalize

~~~
Input:

 Token T
 SerializedGroupElement E
 opaque aux<1..2^16-1>

Output:

 opaque output<1..2^16-1>

Steps:

 1. DST = "oprf_derive_output"
 2. dk = H_2(DST, T.data || E)
 3. output = H_2(dk, aux)
 4. Output output
~~~

## Fixed-base blinding {#blinding}

Let `H_1` refer to the function `GG.HashToGroup`, in Section
{{algorithms}} we assume that the client-side blinding is carried out
directly on the output of H_1(x), i.e. computing r * H_1(x) for some r
<-$ GF(p). A more efficient alternative to multiplication blinding is to
to use 'additive blinding' rather than multiplicative if the client can
preprocess some values. For example, a valid way of computing additive
blinding would be to instead compute H_1(x) + r * G, where G is the
fixed generator for the group GG.

The advantage of additive blinding is that it allows the client to
pre-process tables of blinded scalar multiplications for the fixed
generator G. This may give it a computational efficiency advantage.
Pre-processing also reduces the amount of computation that needs to be
done in the online exchange. Choosing one of these values `r * G` (where
`r` is the scalar value that is used), then computing `H_1(x)+r * G` is
more efficient than computing `r * H_1(x)` (one addition against
log_2(r)). Therefore, it may be advantageous to implement the OPRF and
VOPRF protocols using additive blinding rather than multiplicative
blinding. In fact, the only algorithms that need to change are Blind and
Unblind (and similarly for the VOPRF variants).

We define the additive variants of the algorithms in {{algorithms}}
below, along with a new algorithm Preprocess. The Proprocess algorithm
can take place offline and before the rest of the OPRF protocol. The
Blind algorithm takes the proprocessed values as inputs, but the
signature of Unblind remains the same.

### Preprocess

~~~
struct {
  Scalar blind;
  SerializedGroupElement blinded_generator;
  SerializedGroupElement blinded_public_key;
} PreprocessedBlind;
~~~

~~~
Input:

 PublicKey public_key;
 uint16 m;

Output:

 PrepocessedBlind preprocs[m];

Steps:

 1. preprocs = []
 2. PK = GG.Deserialize(public_key)
 3. for i = 0 to m:
    1. r <-$ GF(p)
    2. if r == 0: return to the previous step
    3. blinded_generator = GG.Serialize(r * GG.Generator())
    4. blinded_public_key = GG.Serialize(r * PK)
    5. preprocs[i] = PrepocessedBlind{
         blind: r,
         blinded_generator: blinded_generator,
         blinded_public_key: blinded_public_key,
       }
 4. Output preprocs
~~~

### Blind

~~~
Input:

 ClientInput inputs[m]
 PreprocessedBlinds preprocs[m]

Output:

 Token tokens[m]
 BlindedToken blinded_tokens[m]

Steps:

 1. tokens = []
 2. blinded_tokens = []
 3. for i = 0 to m:
    1. pre = preprocs[i]
    2. r = pre.blind
    3. r * G = GG.Deserialize(pre.blinded_generator)
    4. P = GG.HashToGroup(inputs[i])
    5. tokens[i] = Token{ data: x, blind: pre.blinded_public_key }
    6. blinded_tokens[i] = GG.Serialize(P + r * G)
 4. Output (tokens, blinded_tokens)
~~~

### Unblind

~~~
Input:

 Token tokens[m]
 Evaluation ev
 PublicKey public_key
 BlindedToken blinded_tokens[m]
 boolean verifiable

Output:

 SerializedGroupElement unblinded[m]

Steps:

 1. if (verifiable):
    1. if (VerifyProof(public_key, blinded_tokens, ev) == false): ABORT
 2. unblinded_tokens = []
 3. for i = 0 to m:
    1. PKR = GG.Deserialize(tokens[i].blind)
    2. Z = GG.Deserialize(ev.elements[i])
    3. N := Z - PKR
    4. unblinded_tokens[i] = GG.Serialize(N)
 4. Output unblinded_tokens
~~~

Notice that Unblind computes (Z-PKr) = k(H_1(x)+r * G) - rk * G =
kH_1(x) by the commutativity of scalar multiplication in GG. 

# NIZK Discrete Logarithm Equality Proof {#dleq}

For the VOPRF protocol we require that Client is able to verify that Server has
used its private key k to evaluate the PRF. As in the original work of
{{JKK14}}, we provide a zero-knowledge proof that the key provided as
input by the server in the `Evaluate` function is the same key as it
used to produce their public key.

As an example of the nature of attacks that this prevents, this ensures
that Server uses the same private key for computing the VOPRF output and does
not attempt to "tag" individual Servers with select keys. This proof
must not reveal Server's long-term private key to Client.

Consequently, this allows extending the OPRF protocol with a
(non-interactive) discrete logarithm equality (DLEQ) algorithm built on
a Chaum-Pedersen {{ChaumPedersen}} proof. This proof is divided into two
procedures: GenerateProof and VerifyProof. These are specified below.

The proof generation and verification algorithms are denoted by
`GenerateProof` and `VerifyProof` respectively, see below for
descriptions. Note that both algorithms create a batched proof for
multiple evaluations of the VOPRF. Note further that both algorithms can
be domain-separated using the global `opaque DST_dleq<1..2^16-1>` value.

## GenerateProof

~~~
Input:

 PrivateKey k
 PublicKey public_key
 BlindedTokens blinded_tokens[m]
 Evaluation ev

Output:

 Scalar proof[2]

Steps:

 1.  G = GG.Generator()
 2.  gen = GG.Serialize(G)
 3.  (a1, a2) = ComputeComposites(
                  gen, public_key, blinded_tokens, ev, DST_dleq
                )
 4.  r <-$ GF(p)
 5.  if (r == 0): go back to the previous step
 6.  a3 = GG.Serialize(r * G)
 7.  a4 = GG.Serialize(rM)
 8.  c = H_3(gen || public_key || a1 || a2 || a3 || a4) mod p
 9.  s = (r - ck) mod p
 10. Output (c, s)
~~~

We note here that it is essential that a different r value is used for
every invocation. If this is not done, then this may leak the key k in a
similar fashion as is possible in Schnorr or (EC)DSA scenarios where
fresh randomness is not used.

## VerifyProof

This algorithm outputs a boolean `verified` which indicates whether the
proof verifies correctly, or not.

~~~
Input:

 PublicKey public_key
 BlindedTokens blinded_tokens[m]
 Evaluation ev
 Scalar proof[2]

Output:

 boolean verified

Steps:

 1. G = GG.Generator()
 2. gen = GG.Serialize(G)
 3. (a1, a2) = ComputeComposites(
                 gen, public_key, blinded_tokens, ev, DST_dleq
               )
 4. A' = (proof[1] * G + proof[0] * Y)
 5. B' = (proof[1] * M + proof[0] * Z)
 6. a3 = GG.Serialize(A')
 7. a4 = GG.Serialize(B')
 8. c  = H_3(gen || public_key || a1 || a2 || a3 || a4) mod p
 9. Output c == proof[0] mod p
~~~

## ComputeComposites

`ComputeComposites` is a utility function used in both
`GenerateProof` and `VerifyProof`.

~~~
Input:

 SerializedGroupElement gen
 PublicKey public_key
 BlindedTokens blinded_tokens[m]
 Evaluation ev
 opaque DST_dleq<1..2^16-1>

Output:

 SerializedGroupElement composites[2]

Steps:

 1. seed = H_4(gen || public_key || blinded_tokens || ev.elements)
 2. i' = 0
 3. M = GG.Identity()
 4. Z = GG.Identity()
 5. for i = 0 to m:
    1. di = 1
    2. Mi = GG.Deserialize(blinded_tokens[i])
    3. Zi = GG.Deserialize(ev.elements[i])
    4. if (m > 1):
       1. di = H_3(seed || i' || DST_dleq)
       2. if (di > GG.order()):
          1. i = i-1 # decrement and try again
       3. i  = i + 1
       4. i' = i' + 1
    5. M = di * Mi + M
    6. Z = di * Zi + Z
 6. Output [GG.Serialize(M), GG.Serialize(Z)]
~~~

## Hash function instantiations

In the above algorithmms, we define two new functions `H_3` and `H_4`.
The function `H_3` should induce an output distribution in
`GF(GG.Order())` that is statistically close to uniformly random. The
function `H_4` maps arbitrary length byte outputs to a fixed size output
depending on the security profile of the application. Both functions are
modelled as random oracles for the purpose of arguing security.

# Supported ciphersuites {#ciphersuites}

This section specifies supported VOPRF group and hash function
instantiations. We only provide ciphersuites in the EC setting as these
provide the most efficient way of instantiating the OPRF. Our
instantiation includes considerations for providing the DLEQ proofs that
make the instantiation a VOPRF. Supporting OPRF operations alone can be
allowed by simply dropping the relevant components. For reasons that are
detailed in {{cryptanalysis}}, we only consider ciphersuites that
provide strictly greater than 128 bits of security {{NIST}}.

## OPRF-curve448-HKDF-SHA512-ELL2-RO:

- GG: curve448 {{RFC7748}}
- H_1: curve448-SHA512-ELL2-RO {{I-D.irtf-cfrg-hash-to-curve}}
  - hash-to-curve DST: "RFCXXXX-OPRF-curve448-SHA512-ELL2-RO-"
- H_2: HMAC_SHA512 {{RFC2104}}

## OPRF-P384-HKDF-SHA512-SSWU-RO:

- GG: secp384r1 {{SEC2}}
- H_1: P384-SHA512-SSWU-RO {{I-D.irtf-cfrg-hash-to-curve}}
  - hash-to-curve DST: "RFCXXXX-OPRF-P384-SHA512-SSWU-RO-"
- H_2: HMAC_SHA512 {{RFC2104}}

## OPRF-P521-HKDF-SHA512-SSWU-RO:

- GG: secp521r1 {{SEC2}}
- H_1: P521-SHA512-SSWU-RO {{I-D.irtf-cfrg-hash-to-curve}}
  - hash-to-curve DST: "RFCXXXX-OPRF-P521-SHA512-SSWU-RO-"
- H_2: HMAC_SHA512 {{RFC2104}}

## VOPRF-curve448-HKDF-SHA512-ELL2-RO:

- GG: curve448 {{RFC7748}}
- H_1: curve448-SHA512-ELL2-RO {{I-D.irtf-cfrg-hash-to-curve}}
  - hash-to-curve DST: "RFCXXXX-VOPRF-curve448-SHA512-ELL2-RO-"
- H_2: HMAC_SHA512 {{RFC2104}}
- H_3: HKDF-Expand-SHA512
- H_4: SHA512

## VOPRF-P384-HKDF-SHA512-SSWU-RO:

- GG: secp384r1 {{SEC2}}
- H_1: P384-SHA512-SSWU-RO {{I-D.irtf-cfrg-hash-to-curve}}
  - hash-to-curve DST: "RFCXXXX-VOPRF-P384-SHA512-SSWU-RO-"
- H_2: HMAC_SHA512 {{RFC2104}}
- H_3: HKDF-Expand-SHA512
- H_4: SHA512

## VOPRF-P521-HKDF-SHA512-SSWU-RO:

- GG: secp521r1 {{SEC2}}
- H_1: P521-SHA512-SSWU-RO {{I-D.irtf-cfrg-hash-to-curve}}
  - hash-to-curve DST: "RFCXXXX-VOPRF-P521-SHA512-SSWU-RO-"
- H_2: HMAC_SHA512 {{RFC2104}}
- H_3: HKDF-Expand-SHA512
- H_4: SHA512

We remark that the 'hash-to-curve DST' field is necessary for domain
separation of the hash-to-curve functionality.

# Security Considerations {#sec}

This section discusses the cryptographic security of our protocol, along
with some suggestions and trade-offs that arise from the implementation
of an OPRF.

## Cryptographic security {#cryptanalysis}

We discuss the cryptographic security of the OPRF protocol from
{{protocol}}, relative to the necessary cryptographic assumptions that
need to be made.

### Computational hardness assumptions {#assumptions}

Each assumption states that the problems specified below are
computationally difficult to solve in relation to sp (the security
parameter). In other words, the probability that an adversary has in
solving the problem is bounded by a function negl(sp), where negl(sp) <
1/f(sp) for all polynomial functions f().

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
construction (including the NIZK DLEQ proofs from {{dleq}}) is identical
to the {{JKK14}} construction, except that we can perform multiple VOPRF
evaluations in one go, whilst only constructing one NIZK proof object.
This is enabled using an established batching technique.

Consequently the cryptographic security of our construction is based on
the assumption that the One-More Gap DH is computationally difficult to
solve.

The (N,Q)-One-More Gap DH (OMDH) problem asks the following.

~~~
    Given:
    - G, k * G, G_1, ... , G_N where G, G1, ... GN are elements of GG;
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
group instantiations is a method of instantiating the function H1, that
maps inputs to group elements. In the elliptic curve setting, this must
be a deterministic function that maps arbitrary inputs x (as bytes) to
uniformly chosen points in the curve.

In the security proof of the construction H1 is modeled as a random
oracle. This implies that any instantiation of H1 must be pre-image and
collision resistant. In {{ciphersuites}} we give instantiations of this
functionality based on the functions described in
{{I-D.irtf-cfrg-hash-to-curve}}. Consequently, any OPRF implementation
must adhere to the implementation and security considerations discussed
in {{I-D.irtf-cfrg-hash-to-curve}} when instantiating the function H1.

## Timing Leaks

To ensure no information is leaked during protocol execution, all
operations that use secret data MUST be constant time. Operations that
SHOULD be constant time include: H_1() (hashing arbitrary strings to
curves) and GenerateProof(). As mentioned previously,
{{I-D.irtf-cfrg-hash-to-curve}} describes various algorithms for
constant-time implementations of H_1.

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
unblinded and signed points, or tokens, to derive a shared symmetric key
sk used to MAC the CAPTCHA challenge. C sends the CAPTCHA, MAC, and
token input x to E, who can use x to derive sk and verify the CAPTCHA
MAC. Thus, each token is used at most once by the system.

The Privacy Pass implementation uses the P-256 instantiation of the
VOPRF protocol. For more details, see {{DGSTV18}}.

## Private Password Checker

In this application, let D be a collection of plaintext passwords
obtained by Server. For each password p in D, Server computes
`Evaluate` on H_1(p), where H_1 is as described above, and
stores the result in a separate collection D'. Server then publishes D' with
Y, its public key. If Client wishes to query D' for a password p',
it runs the VOPRF protocol using p as input x to obtain output y. By
construction, y will be the OPRF evaluation of p hashed onto the curve.
Then Client can search D' for y to determine if there is a match.

Concrete examples of important applications in the password domain
include:

- password-protected storage {{JKK14}}, {{JKKX16}};
- perfectly-hiding password management {{SJKS17}};
- password-protected secret-sharing {{JKKX17}}.

### Parameter Commitments

For some applications, it may be desirable for Server to bind tokens to
certain parameters, e.g., protocol versions, ciphersuites, etc. To
accomplish this, Server should use a distinct scalar for each parameter
combination. Upon redemption of a token T from Client, Server can later verify
that T was generated using the scalar associated with the corresponding
parameters.

# Contributors

- Alex Davidson         (alex.davidson92@gmail.com)
- Nick Sullivan         (nick@cloudflare.com)
- Chris Wood            (cawood@apple.com)
- Eli-Shaoul Khedouri   (eli@intuitionmachines.com)
- Armando Faz Hernandez (armfazh@cloudflare.com)

# Acknowledgements

This document resulted from the work of the Privacy Pass team
{{PrivacyPass}}. The authors would also like to acknowledge the helpful
conversations with Hugo Krawczyk. Eli-Shaoul Khedouri provided
additional review and comments on key consistency.

--- back
