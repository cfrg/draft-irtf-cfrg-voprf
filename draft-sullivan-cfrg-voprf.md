---
title: Verifiable Oblivious Pseudorandom Functions (VOPRFs)
abbrev: VOPRFs
docname: draft-sullivan-cfrg-voprf
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
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
    street: 1 Infinite Loop
    city: Cupertino, Califoarnia 95014
    country: United States of America
    email: cawood@apple.com

normative:
  RFC2119:
  RFC7748:
  RFC8032:
  PrivacyPass:
    title: Privacy Pass
    target: https://github.com/privacypass/challenge-bypass-server
  ChaumPedersen:
    title: Wallet Databases with Observers
    target: https://chaum.com/publications/Wallet_Databases.pdf
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
    authors:
      -
        ins: D. Chaum
        org: University of California, Santa Barabara, USA

--- abstract

A Verifiable Oblivious Pseudorandom Function (VOPRF) is a two-party
protocol for computing a PRF in which the secret key holder learns
nothing of the input while simultaneously providing proof that its
private key was used during execution. VOPRFs are useful for computing
one-time unlinkable tokens that are verifiable by secret key holders.
This document specifies a VOPRF construction based on Elliptic Curves.

--- middle

# Introduction

A pseudorandom function (PRF) F(k, x) is an efficiently computable function with
secret key k on input x whose output is indistinguishable from any element in
F's range for some random key k. An oblivious PRF (OPRF) is a two-party protocol between 
a prover P and verifier V wherein both parties cooperate to compute F(k, x) with P's 
secret key k and V's input x such only V learns F(k, x) without learning anything about k. 
A Verifiable OPRF (VOPRF) is an OPRF wherein P can prove to V that its value F(k, x) 
was computed using key k, which is bound to its trusted public key Y = kG. Informally,
this is done by presenting a non-interactive zero-knowledge (NIZK) proof of equality
between (G, Y) and (Z, M), where Z = kM. 

VOPRFs are useful for producing tokens that are verifiable by V. This may be needed,
for example, if V wants assurance that P did not use a unique key in its computation,
i.e., if V wants key consistency from P. This propery is necessary in some applications,
e.g., the Privacy Pass protocol {{PrivacyPass}}, wherein this VOPRF is used to generate 
one-time authentic tokens to bypass CAPTCHA challenges.

This document is structured as follows:

- Section {{background}}: Describe background, related related, and use cases of VOPRF protocols.
- Section {{properties}}: Discuss security properties of VOPRFs.
- Section {{protocol}}: Specify a VOPRF protocol based on elliptic curves. 
- Section {{dleq}}: Specify the NIZK discrete logarithm equality construction used for verifying
protocol outputs. 

## Terminology {#terminology}

The following terms are used throughout this document.

- PRF: Pseudorandom Function.
- OPRF: Oblivious PRF.
- VOPRF: Verifiable Oblivious Pseudorandom Function.
- Requestor (R): Protocol initiator when computing F(k, x).
- Signer (S): Holder of private VOPRF key k.
- NIZK: Non-interactive zero knowledge.
- DLEQ: Discrete Logarithm Equality.

## Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}.

# Background {#background}

VOPRFs are functionally related to RSA-based blind signature schemes, e.g., {{ChaumBlindSignature}}.
Such a scheme works as follows. 
Let m be a message to be signed by a server. It is assumed to be a member of the 
RSA group. Also, let N be the RSA modulus, and e and d be the public and private keys, 
respectively. The Requestor and Signer engage in the following protocol given input m. 

1. Requestor generates a random blinding element r from the RSA group, and 
compute m' = m^r (mod N). Send m' to the Signer.
2. Signer uses m' to compute s' = (m')^d (mod N), and sends s' to the Requestor.
3. Requestor removes the blinding factor r to obtain the original 
signature as s = (s')^(r^-1) (mod N).

By the properties of RSA, s is clearly a valid signature for m. 
(V)OPRF protocols differ from blind signatures in the same way that 
traditional digital signatures differ from PRFs. This is discussed more
in the following section.
  
# Security Properties {#properties}

The security properties of a VOPRF protocol with functionality y = F(k, x) are similar 
to that of a PRF. Specifically:

- Given value x, it is infeasible to learn y = F(k, x) without knowledge of k.
- Output y = F(k, x) is indistinguishable from a random value in the domain of F. 

Additionally, we require the following additional properties:

- Non-malleable: Given (x, y = F(k, x)), V must not be able to generate (x', y') where 
x' != x and y' = F(k, x'). 
- Verifiable:: V must only complete execution of the protocol if it asserts
that P used its secret key k, associated with public key Y = kG, in execution.
- Oblivious: P must learn nothing about the V's input, and V must learn nothing about the P's private key.
- Unlinkable: Given (x, y = F(k, x)), if V reveals x to P, P cannot link x to
the protocol instance in which y = F(k, x) was computed.

# Elliptic Curve VOPRF Protocol {#protocol}

In this section we describe the ECVOPRF protocol. Let G be an elliptic curve group over 
base field F, of prime order p, with two distinct hash functions H_1 and H_2, where H_1 maps 
arbitrary input onto G and H_2 maps arbitrary input to a fixed-length output, e.g., SHA256.
Let L be the security parameter. Let k be the signer's secret key,
and Y = kG be its corresponding public key. Let x be the requestor's input to
the VOPRF protocol. (Commonly, it is a random L-bit string, though this 
is not required.) ECVOPRF begins with the requestor randomly blinding
its input for the signer. The latter then applies its secret key to the blinded
value and returns the result. To finish the computation, the requestor then 
removes its blind and hashes the result using H_2 to yield an output. 
This flow is illustrated below.

~~~
    Requestor               Signer
     r <-$ G
     M = rH_1(x) 
                   M
                ------->    
                           Z = kM
                           D = DLEQ(Z/M == Y/G)
                   Z,D
                <-------
    N = Zr^(-1)
~~~

DLEQ(Z/M == Y/G) is described in Section {{dleq}}. The actual PRF function computed is as follows:

~~~
F(k, x) = y = H_2(k, kH_1(x))
~~~

Note that R finishes this computation upon receiving kH_1(x) from S. The output
from S is not the PRF value.

This protocol may be decomposed into a series of steps, as described below:

- ECVOPRF_Blind(x): Compute and return a blind, r, and blinded representation of x, M.
- ECVOPRF_Sign(M): Sign input M using secret key k to produce Z, generate a 
proof D of DLEQ(Z/M == Y/G), and output (Z, D).
- ECVOPRF_Unblind((Z, D), r): Unblind blinded signature Z with blind r, yielding N. 
Output N if D is a valid proof. Otherwise, output an error.
- ECVOPRF_Finalize(N): Finalize N to produce PRF output F(k, x).

Protocol correctness requires that, for any key k, input x, and (r, M) = ECVOPRF_Blind(x), 
it must be true that:

~~~
ECVOPRF_Finalize(ECVOPRF_Unblind(ECVOPRF_Sign(M), M, r)) = F(k, x)
~~~

with overwhelming probability. 

## Algorithmic Details 

This section provides algorithms for each step in the VOPRF protocol.

1. V computes T = H_1(t) and a random element r from G. (The latter is the
blinding factor.) The requestor computes M = rT.
2. V sends M to P. 
3. P computes Z = xM = rxT, and D = DLEQ(Z/M == Y/G).
4. P sends (Z, D) to V.
5. V verifies D using Y. If invalid, V outputs an error.
6. V unblinds Z to compute N = r^(-1)Z = xT.
7. V outputs the pair H_2(N).

### ECVOPRF_Blind

~~~
Input:

 x - R's PRF input.

Output:

 r - Random scalar in [1, p - 1]
 M - Blinded representation of x using blind r, a point on G.

Steps:

 1.  r <-$ Fp
 2.  M := rH_1(x)
 5.  Output (r, M)
~~~

### ECVOPRF_Sign

~~~
Input:

 M - Point on G.

Output:

 Z - Scalar multiplication of k and M, point on G.
 D - DLEQ proof that log_G(Y) == log_M(Z).

Steps:

 1. Z := kM
 2. D = DLEQ_Generate(Y, M, Z)
 2. Output (Z, D)
~~~

### ECVOPRF_Unblind

~~~
Input:

 Z - Point on G.
 D - DLEQ proof that log_G(Y) == log_M(Z).
 M - Blinded representation of x using blind r, a point on G.
 r - Random scalar in [1, p - 1].

Output:

 N - Unblinded signature, point on G.

Steps:

 1. N := (-r)Z
 2. If DLEQ_Verify(G, Y, M, Z, D) output N.
 3. Output "error"
~~~

### ECVOPRF_Finalize

~~~
Input:

 N - Point on G, or "error".

Output:

 y - Random element in {0,1}^L, or "error"

Steps:

 1. If N == "error", output "error".
 2. y := H_2(N)
 3. Output y
~~~

# NIZK Discrete Logarithm Equality Proof {#dleq}

In some cases, it may be desirable for the V to have proof that P
used its private key to compute Z from M. Specifically, this is done by confirming
that log_G(Y) == log_M(Z). This may be used, for example, to ensure that 
P uses the same private key for computing the VOPRF output and does not
attempt to "tag" individual verifiers with select keys. This proof must
not reveal the P's long-term private key to V. Consequently,
we extend the protocol in the previous section with a (non-interactive) discrete 
logarithm equality (DLEQ) algorithm built on a Chaum-Pedersen {{ChaumPedersen}} proof.
This proof is divided into two procedures: DLEQ_Generate and DLEQ_Verify. These are specified
below.

## DLEQ_Generate

~~~
Input: 

  G: Generator of group with prime order q
  Y: Signer public key
  M: Point on G
  Z: Point on G

Output:

  D: DLEQ proof (c, s)

Steps:

1. r <-$ Z_q
2. A = rG and B = rM.
2. c = H_3(G,E,M,Z,A,B)
3. s = (r - ck) (mod q)
4. Output D = (c, s)
~~~

## DLEQ_Verify

~~~
Input: 

  G: Generator of group with prime order q
  Y: Signer public key
  M: Point on G
  Z: Point on G
  D: DLEQ proof (c, s)

Output:

  True if log_G(Y) == log_M(Z), False otherwise

Steps:

1. A' = (sG + cY)
2. B' = (sM + cZ)
3. c' = H_3(G,E,M,Z,A',B')
4. Output c == c'
~~~

## Group and Hash Function Instantiations

This section specifies supported VOPRF group and hash function instantiations.

EC-VOPRF-P256-SHA256:

- G: P-256
- H_1: ((TODO: reference hash-to-curve draft))
- H_2: SHA256

EC-VOPRF-P256-SHA512:

- G: P-256
- H_1: ((TODO: reference hash-to-curve draft))
- H_2: SHA512

EC-VOPRF-P384-SHA256:

- G: P-384
- H_1: ((TODO: reference hash-to-curve draft))
- H_2: SHA256

EC-VOPRF-P384-SHA512:

- G: P-384
- H_1: ((TODO: reference hash-to-curve draft))
- H_2: SHA512

EC-VOPRF-CURVE25519-SHA256:

- G: Curve25519 {{RFC7748}}
- H_1: ((TODO: reference hash-to-curve draft))
- H_2: SHA256

EC-VOPRF-CURVE25519-SHA512:

- G: Curve25519 {{RFC7748}}
- H_1: ((TODO: reference hash-to-curve draft))
- H_2: SHA512

EC-VOPRF-CURVE448-SHA256:

- G: Curve448 {{RFC7748}} 
- H_1: ((TODO: reference hash-to-curve draft))
- H_2: SHA256

EC-VOPRF-CURVE448-SHA512:

- G: Curve448 {{RFC7748}} 
- H_1: ((TODO: reference hash-to-curve draft))
- H_2: SHA512

# Security Considerations

- key generation and secrecy
- hashing to curve reliance

## Timing Attacks

To ensure no information is leaked during protocol execution, all operations
MUST be constant time.

XXX

# Privacy Considerations

## Key Consistency

DLEQ proofs are essential to the protocol to allow V to check that P's designated private 
key was used in the computation. A side effect of this property is that it prevents P
from using unique key for select verifiers as a way of "tagging" them. If all verifiers
expect use of a certain private key, e.g., by locating P's public key key published from
a trusted registry, then P cannot present unique keys to an indivdual verifier.

## XXX

# Acknowledgments

This document is a direct result of the Privacy Pass team.

--- back

# Test Vectors

This section includes test vectors for the primary VOPRF protocol, 
excluding DLEQ output. ((TODO: add DLEQ vectors.))

~~~
P-224
X: 0403cd8bc2f2f3c4c647e063627ca9c9ac246e3e3ec74ab76d32d3e999c522d60ff7aa1c8b0e4 \
   X: 0403cd8bc2f2f3c4c647e063627ca9c9ac246e3e3ec74ab76d32d3e999c522d60ff7aa1c8b0e4
r: c4cf3c0b3a334f805d3ce3c3b4d007fbbdaf078a42a8cbdc833e54a9
M: 046b2b8482c36e65f87528415e210cff8561c1c8e07600a159893973365617ee2c1c33eb0662d \
   M: 046b2b8482c36e65f87528415e210cff8561c1c8e07600a159893973365617ee2c1c33eb0662d
k: a364119e1c932a534a8d440fef2169a0e4c458d702eca56746655845
Z: 04ed11656b4981e39242b170025bf8d5314bef75006e6c4c9afcdb9a85e21fb5fcf9055eb95d3 \
   Z: 04ed11656b4981e39242b170025bf8d5314bef75006e6c4c9afcdb9a85e21fb5fcf9055eb95d3
Y: 04fd80db5301a54ee2cbc688d47cbcae9eb84f5d246e3da3e2b03e9be228ed6c57a936b6b5faf \
   Y: 04fd80db5301a54ee2cbc688d47cbcae9eb84f5d246e3da3e2b03e9be228ed6c57a936b6b5faf

P-224
X: 0429e41b7e1a58e178afc522d0fb4a6d17ae883e6fd439931cf1e81456ab7ed6445dbe0a231be \
   X: 0429e41b7e1a58e178afc522d0fb4a6d17ae883e6fd439931cf1e81456ab7ed6445dbe0a231be
r: 86a27e1bd51ac91eae32089015bf903fe21da8d79725edcc4dc30566
M: 04d8c8ffaa92b21aa1cc6056710bd445371e8afebd9ef0530c68cd0d09536423f78382e4f6b20 \
   M: 04d8c8ffaa92b21aa1cc6056710bd445371e8afebd9ef0530c68cd0d09536423f78382e4f6b20
k: ab449c896261dc3bd1f20d87272e6c8184a2252a439f0b3140078c3d
Z: 048ac9722189b596ffe5cb986332e89008361e68f77f12a931543f63eaa01fabf6f63d5d4b3b6 \
   Z: 048ac9722189b596ffe5cb986332e89008361e68f77f12a931543f63eaa01fabf6f63d5d4b3b6
Y: 046e83dff2c9b6f9e88f1091f355ad6fa637bdbd829072411ea2d74a5bf3501ccf3bcc2789d48 \
   Y: 046e83dff2c9b6f9e88f1091f355ad6fa637bdbd829072411ea2d74a5bf3501ccf3bcc2789d48

P-256
X: 041b0e84c521f8dcd530d59a692d4ffa1ca05b8ba7ce22a884a511f93919ac121cc91dd588228 \
   X: 041b0e84c521f8dcd530d59a692d4ffa1ca05b8ba7ce22a884a511f93919ac121cc91dd588228
r: a3ec1dc3303a316fc06565ace0a8910da65cf498ea3884c4349b6c4fc9a2f99a
M: 04794c5a54236782088594ccdb1975e93b05ff742674cc400cb101f55c0f37e877c5ada0d72fb \
   M: 04794c5a54236782088594ccdb1975e93b05ff742674cc400cb101f55c0f37e877c5ada0d72fb
k: 9c103b889808a8f4cb6d76ea8b634416a286be7fa4a14e94f1478ada7f172ec3
Z: 0484cfda0fdcba7693672fe5e78f4c429c096ece730789e8d00ec1f7be33a6515f186dcf7aa38 \
   Z: 0484cfda0fdcba7693672fe5e78f4c429c096ece730789e8d00ec1f7be33a6515f186dcf7aa38
Y: 044ff2e31de9fda542c2c63314e2bce5ce2d5ccb8332dbe1115ff5740e5e60bb867994e196ead \
   Y: 044ff2e31de9fda542c2c63314e2bce5ce2d5ccb8332dbe1115ff5740e5e60bb867994e196ead

P-256
X: 043ea9d81b99ac0db002ad2823f7cab28af18f83419cce6800f3d786cc00b6fd030858d073916 \
   X: 043ea9d81b99ac0db002ad2823f7cab28af18f83419cce6800f3d786cc00b6fd030858d073916
r: ed7294b42792760825645b635e9d92ef5a3baa70879dd59fdb1802d4a44271b2
M: 04ec894e496d0297756a17365f866d9449e6ebc51852ab1ffa57bc29c843ef003b116f5ef1f60 \
   M: 04ec894e496d0297756a17365f866d9449e6ebc51852ab1ffa57bc29c843ef003b116f5ef1f60
k: a324338a7254415dbedcd1855abd2503b4e5268124358d014dac4fc2c722cd67
Z: 04a477c5fefd9bc6bcd8e893a1b0c6dc73b0bd23ebe952dcad810de73b8a99f5e1e216a833b32 \
   Z: 04a477c5fefd9bc6bcd8e893a1b0c6dc73b0bd23ebe952dcad810de73b8a99f5e1e216a833b32
Y: 04ffe55e2a95a21e1605c1ed11ac6bea93f00fa15a6b27e90adad470ad27f0e0fe5b8607b4689 \
   Y: 04ffe55e2a95a21e1605c1ed11ac6bea93f00fa15a6b27e90adad470ad27f0e0fe5b8607b4689

P-384
X: 04c0b51e5dcd6a309c77bb5720bf9850279e8142b6127952595ab9092578de810a13795bceff3 \
   d358f0480a61469f17ad62ebaecd0f817c1e9c7d41d536ab410e7a2b5d7a7905d1bef5499b654b0e \
   d358f0480a61469f17ad62ebaecd0f817c1e9c7d41d536ab410e7a2b5d7a7905d1bef5499b654b0e
r: 889b5e4812d683c4df735971240741ff869ccf77e10c2e97bef67d6fe6b8350abe59ec8fe2bfa \
   r: 889b5e4812d683c4df735971240741ff869ccf77e10c2e97bef67d6fe6b8350abe59ec8fe2bfa
M: 044e2d86fa6e53ebba7f2a9b661a2de884a8ccc68e29b68586d517eb66e8b4b7dac334c6e769d \
   485d672fac3a0311877572254754e318077aec3631208c6b503c5cdfe57716e1232da64cebe46f0d \
   485d672fac3a0311877572254754e318077aec3631208c6b503c5cdfe57716e1232da64cebe46f0d
k: b8c854a33c8c564d0598b1ac179546acdccad671265cff1ea5a329279272e8d21c94b7e5b6bea \
   k: b8c854a33c8c564d0598b1ac179546acdccad671265cff1ea5a329279272e8d21c94b7e5b6bea
Z: 047bf23eef00e83e6cb6fb9ade5e5995cf81abb8dc73a570ff4cb7be48f21281edfed9bf76cc2 \
   88b35d2df615ff711ed2a1fb85cd0b22812438665cdd300039685b3f593f4b574f9e8b294982c2a2 \
   88b35d2df615ff711ed2a1fb85cd0b22812438665cdd300039685b3f593f4b574f9e8b294982c2a2
Y: 04ab4886ecf7e489a0be8529ff4b537941c95ba4ce570db537dcfad5cabc064c43f1b0a1d1b89 \
   101facd93f2f9a8b5f28431489be4664f446af8a51cc7c4221f633adb4f8f2f2a073dfd83ddf8d77 \
   101facd93f2f9a8b5f28431489be4664f446af8a51cc7c4221f633adb4f8f2f2a073dfd83ddf8d77

P-384
X: 047511a846277a2009f37b3583f14c8ea3af17e3a146e0e737fdc1260b6d4a18ff01f21ec3bbc \
   e39e1cade76d455feadc1bb16f65cd54042e1bc5aba1dee2434f59d00698a963b902148750240f8f \
   e39e1cade76d455feadc1bb16f65cd54042e1bc5aba1dee2434f59d00698a963b902148750240f8f
r: e514ef9b3ea87eafdb78da48e642daa79f036ac00228997ab8da6ac198fb888cd2fec84d52010 \
   r: e514ef9b3ea87eafdb78da48e642daa79f036ac00228997ab8da6ac198fb888cd2fec84d52010
M: 04fd9b68973b0fcefcf4458b4faa1c3815bdad8975b7fb0bfc4c1db7e3f169fb3a26ddabe1b25 \
   c4a23cf8a2faeb12c18f06f2227e87ede6039f55a61ef0c89ca3c582e2864fe130ea0c709f92519d \
   c4a23cf8a2faeb12c18f06f2227e87ede6039f55a61ef0c89ca3c582e2864fe130ea0c709f92519d
k: bcc73da3b2adace9c4f4c32eeadef57436c97f8d395614e78aa91523e1e5d7f551ebb55e87da2 \
   k: bcc73da3b2adace9c4f4c32eeadef57436c97f8d395614e78aa91523e1e5d7f551ebb55e87da2
Z: 042d885d2945cde40e490dd8497975eaeb54e4e10c5986a9688c9de915b16cf43572fd155e159 \
   9e2233a75056a72b54d30092e30bb2edc70e0d90da934c27362e0e6303bafae12f13bf3d5be322e6 \
   9e2233a75056a72b54d30092e30bb2edc70e0d90da934c27362e0e6303bafae12f13bf3d5be322e6
Y: 044833fba4973c1c6eae6745850866ebbb23783ea0d4d8b867e2c93acb2f01fd3d36d9cb5c491 \
   ff9440c8c8e325db326bf88ddf0ba6008158a67999e18cd378d701d1f8a6a7b088dc261c85b6a78b \
   ff9440c8c8e325db326bf88ddf0ba6008158a67999e18cd378d701d1f8a6a7b088dc261c85b6a78b

P-521
X: 040039d290b20c604b5c59cb85dfacd90cbf9f5e275ee8c38a8ff80df0872e8e1dd214a9ec3b2 \
   2c8d75bf634739afdc09acc342542abacf35bf2a6488d084825c5d96003be29e201e75c1b78667f5 \
   a64cc7207722796b225b49edaaf457fcafff4f644252ebe8057291d317f30109f1526aacbfff2308 \
   a64cc7207722796b225b49edaaf457fcafff4f644252ebe8057291d317f30109f1526aacbfff2308
r: 010606612666705556ac3c28dde30f134e930b0c31bfc9715f0812e0b99f0212dc427e344cb97 \
   r: 010606612666705556ac3c28dde30f134e930b0c31bfc9715f0812e0b99f0212dc427e344cb97
M: 040065366112a0598e4e5997e79e42f287f7202e5d956bef29890e963169d9eaab8d21501283c \
   47dd37aca1710c8b5f456b1c044c8582ba6feef3edc997fecef7d4f40180ceb9bbbe3ab1907ea2d1 \
   21ec00156848e04e323744d86444111fc09a21ca316df2cae925a0bb079d0faa2474ec8d5a96e6fa \
   21ec00156848e04e323744d86444111fc09a21ca316df2cae925a0bb079d0faa2474ec8d5a96e6fa
k: 01297d92cfe6895269aa5406f2ba6cbfffbba66a11ab0db34655213624fa238c50e27177aea5d \
   k: 01297d92cfe6895269aa5406f2ba6cbfffbba66a11ab0db34655213624fa238c50e27177aea5d
Z: 040151d2dc5290ebd47065680dcb4db350c4d81346680c5589f94acfb1e28418585e7f2cbfa11 \
   5945d9f7b98157ea8c2ab190c6a47b939502c2f793b77ceff671f5e60086fdd1ebf960f29bf5d590 \
   f8f7511d248df22d964637e2286adab4654991d338691f4673a006ff116e61afe65c914b27c3ef4c \
   f8f7511d248df22d964637e2286adab4654991d338691f4673a006ff116e61afe65c914b27c3ef4c
Y: 04009534bd720bd4ebe703968a8496eec352711a81b7fe594a72ef318c2ce582b41880262a1c6 \
   05079231de91e71b1301d1be4e9618e96081ccfd4f6cab92f52b860e01beec2c58cb01713e941035 \
   adbe882ab4f3eaa31e27a96d210d35f6161b1487dd28d8da4a11a915182752b1450a89aad2a013c2 \
   adbe882ab4f3eaa31e27a96d210d35f6161b1487dd28d8da4a11a915182752b1450a89aad2a013c2

P-521
X: 04012ea416842dfad169a9eb860b0af2af3c0140e1918ccd043650d83ad261633f20c5ca02c1b \
   ffb857ab72814cf46cfc16ac9ba79887044709f72480358c4b990e46010a62336bb57b87b494b064 \
   4d2b6a385f3d5b5da29e22cae33c624f561513a5e8e6669b4e99704c56157dde83994a3c0800a64b \
   4d2b6a385f3d5b5da29e22cae33c624f561513a5e8e6669b4e99704c56157dde83994a3c0800a64b
r: 019d02efd97add5facc5defbb63fd74daaacda04ae7321abec0da1551b4cc980b8ce6855a28a1 \
   r: 019d02efd97add5facc5defbb63fd74daaacda04ae7321abec0da1551b4cc980b8ce6855a28a1
M: 040066e3d0b5b9758c9288a725ce6724fdc3bd797a8222f07233897a5916dc167531ebc6a4710 \
   cbb240684c9a02eb82214b009d636f24abb8e409e78ff1f02a1dbfb90069056693e96acd760887f9 \
   6c9b1f487441b7142fb13a67deb7332194ff454b3aac89f9cf02c338dae69a700bd26844881e6106 \
   6c9b1f487441b7142fb13a67deb7332194ff454b3aac89f9cf02c338dae69a700bd26844881e6106
k: 018eeea896de104bf1e772155836f6ceddab0b4c2e3e4c33ba08a6fd6db0291cfb15faff0b3c7 \
   k: 018eeea896de104bf1e772155836f6ceddab0b4c2e3e4c33ba08a6fd6db0291cfb15faff0b3c7
Z: 04016825ea754324d5761ada130a1b87b03b5e2a6b0f403343925c67df39bbf85bc782909124d \
   d297a1edfb049efa7ce61c626c0ad99d8cf462abcce1ee1967d8a355011e2c5a7ce621fc822a7d95 \
   bf7359d938ee4a5c3431e7dd270b7fb6e95fda29cf460d89454763bb0db9b8b705503170a9ac1c7a \
   bf7359d938ee4a5c3431e7dd270b7fb6e95fda29cf460d89454763bb0db9b8b705503170a9ac1c7a
Y: 04006b0413e2686c4bb62340706de7723471080093422f02dd125c3e72f3507b9200d11481468 \
   74bbaa5b6108b834c892eeebab4e21f3707ee20c303ebc1e34fcd3c701f2171131ee7c5f07c1ccad \
   240183d777181259761741343959d476bbc2591a1af0a516e6403a6b81423234746d7a2e8c2ce60a \
   240183d777181259761741343959d476bbc2591a1af0a516e6403a6b81423234746d7a2e8c2ce60a
~~~

# Tamarin Model

~~~
theory VOPRFs
begin

/*
Protocol:
 Requestor               Signer
     r <-$ G
     M = rH_1(x) 
                   M
                ------->    
                           Z = kM
                   Z
                <-------
    N = Zr^(-1)    
*/

builtins: hashing, asymmetric-encryption, diffie-hellman

/* Generate ephemeral keypair */
rule generate_ephemeral:
   [ Fr(~secretk)] 
   -->
   [ Keys(~secretk, 'g'^~secretk) ]

/* Key Reveals */
rule key_reveal:
   [ Keys(~secretk, 'g'^~secretk) ]--[ Key_reveal(~secretk) ]-> [ Out(~secretk) ]

/* Signed message reveal */
rule Message_reveal:
  let token = ('g'^~secretk)^~x
  in
  [ Finalize(token) ] --[ Reveal_message(token)]-> [ Out(token)]

/* Protocol rules */
rule SendRandomBlindedValue:
  let blinded_input = ('g'^~x)^~r
  in
    [ 
      Fr(~r), // choose random r
      Fr(~x)  // choose random x -- this is supposed to be input to the protocol, though that is not necessary.
    ]
    -->
    [ 
      Out(blinded_input), // output g^{xr}
      StoreBlindedValue(~r, ~x)
    ]

rule SendRandomFixedValue:
  let x = h('voprf')
      blinded_input = ('g'^x)^~r
  in
    [ 
      Fr(~r) // choose random r
    ]
    -->
    [ 
      Out(blinded_input), // output g^{xm}
      StoreBlindedValue(~r, x)
    ]

rule SignAndSendBlindedValue:
    let blinded_value = ('g'^~x)^~r
    in
    [
      Keys(~secretk, 'g'^~secretk),
      In(blinded_value)
    ]
    -->
    [
      Out(blinded_value^~secretk)
    ]

rule UnblindAndFinalizeSignedValue:
  let signed_value = (('g'^~x)^~r)^~secretk
  in
    [ 
      StoreBlindedValue(~r, ~x),
      In(signed_value)
    ]
    --[ Finalize(signed_value^inv(~r)) ]->
    [
      // pass
    ]

// Message secrecy lemma
lemma message_secrecy:
  "(All #i1 t .
    (
      Finalize(t) @ i1 
      &
      not ( (Ex A #ia . Key_reveal( A ) @ ia ) 
          | (Ex B #ib . Reveal_message( B ) @ ib )
          )
    )
    ==> not (Ex #i2. K( t ) @ i2 )
  )"

end
~~~
