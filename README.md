# Elliptic Curve El Gamal $\Sigma$ Protocol

This is a **non-interactive zero-knowledge proof of knowedge** (NIZKPoK) protocol to prove that you know the preimage of an El Gamal ciphertext. More specifically, it allows a prover to convince a verifier that **a commitment is of the preimage of an El Gamal ciphertext**. This protocol can be useful in situations where you want to prove knowledge of what the encrypted message is without revealing the data. 

> This is a work in progress and not safe for production use.

## Usage

### Setup

Build and test the project with cargo:

``` sh
cargo build
cargo test
```

### Usage

Example with JubJub ([see the tests](./src/lib.rs)).

``` rust
let mut rng = test_rng();
// the secret key
let x = <JubJub as Group>::ScalarField::rand(&mut rng);
let g: JubJub = JubJub::generator().into();
// the public key
let h: JubJub = g.mul(x).into();

let params = Params { g, h };

let (commitment, ciphertext, proof) = 
    ElGamalSigmaProtocol::prove(x, params.clone(), test_rng());
let result = 
    ElGamalSigmaProtocol::verify(commitment, ciphertext, proof, params);
assert_eq!(result, true);
```

## Details

This section contains technical details on how the protocol works.

###  $\Sigma$-Protocols
A sigma protocol is an *interactive* public 3-move public coin flip protocol where a prover convinces a verifier that they know the witness $w$ of a public instance $x$ without disclosing $x$. With a Fiat-Shamir transform, this can be transformed into a *non-interactive* protocol, where each participant only makes a single move.

### The Protocol

The protocol works over elliptic curves. Let $p$ be a large prime and choose a prime $q$ s.t. $q | p- 1$. We will assume we have an elliptic curve group $\mathbb{G}$ with an additive group operation (since we are using the arkworks library and the programming model assumes an additive operation). 

Let $P$ be the prover and $V$ be the verifier. Choose $x \xleftarrow{R} \mathbb{Z}_q$ and set $H := xG$ where $G \in \mathbb{G}$ is a generator. Let $s \in \mathbb{Z}_q$ be the secret that we want to prove knowledge of. Then the protocol is as follows:

**Prover**

1. Encrypt the message $s$ for the public key $H$ using El Gamal:
$(c_1, c_2) = (kG, s(kH))$ where $k \xleftarrow{R} \mathbb{Z}_q$
1. Calculate a (Pedersen) commitment $c = sG + sH$
2. Choose $r \xleftarrow{R} \mathbb{Z}_q$ and set $t = kG$, $a = kH$.
3. Compute $e = H(t, a, c_1, c_2, AUX)$
4. Set $z = k + es$
5. Send $(t, a, z, c, c_1, c_2)$ to the verifier.

**Verifier**
1. Compute $e = H(t, a, c_1, c_2, AUX)$
2. Check if $zG + zH == t + a + e*c$. If so, output $1$, otherwise output $0$.

This works since:

$zG + zH = (k + es)G + (k + es)H  = kG + esG + kH + esH = t + e(sG) + a + e(sH) = t + a + e(sG + sH)$