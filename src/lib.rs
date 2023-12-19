#![no_std]
use ark_ec::CurveGroup;
use ark_ff::{fields::PrimeField, UniformRand};
use ark_serialize::{CanonicalSerialize, SerializationError};
use ark_std::{marker::PhantomData, rand::Rng, vec::Vec};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

// a public commitment for a point in the curbe group's scalar field
pub type Commitment<C> = C;

// represents an el gamal ciphertext
pub struct Ciphertext<C: CurveGroup> {
    c1: C::Affine,
    c2: C::Affine,
}

#[derive(Debug)]
pub enum Error {
    SerializationError,
}

impl<C: CurveGroup> Ciphertext<C> {
    fn serialize_compressed(&self) -> Result<(Vec<u8>, Vec<u8>), SerializationError> {
        let mut c1_bytes = Vec::new();
        let mut c2_bytes = Vec::new();

        self.c1.serialize_compressed(&mut c1_bytes)?;
        self.c2.serialize_compressed(&mut c2_bytes)?;

        Ok((c1_bytes, c2_bytes))
    }
}

/// the NIZK PoK
pub struct PoK<C: CurveGroup> {
    /// the commitment to the random value (e.g. rG)
    pub t: C,
    /// the 'blinding' commitment to the random value (e.g. rH)
    pub a: C,
    /// the challenge (e.g. z = k + es)
    pub z: C::ScalarField,
}

/// public parameters for El Gamal encryption
#[derive(Clone, Debug)]
pub struct Params<C: CurveGroup> {
    pub g: C,
    pub h: C,
}

pub struct ElGamalSigmaProtocol<C> {
    _c: PhantomData<C>,
}

impl<C: CurveGroup> ElGamalSigmaProtocol<C> {
    /// Prove that a commitment is of the preimage of an El Gamal ciphertext
    /// without revealing the message
    ///
    pub fn prove<R: Rng + Sized>(
        s: C::ScalarField,
        params: Params<C>,
        mut rng: R,
    ) -> (Commitment<C>, Ciphertext<C>, PoK<C>) {
        // el gamal encryption
        let r = C::ScalarField::rand(&mut rng);
        let c1 = params.g * r;
        let c2 = params.h * (s * r);

        let ct: Ciphertext<C> = Ciphertext {
            c1: c1.into(),
            c2: c2.into(),
        };

        // the commitment
        let c: Commitment<C> = params.g * s + params.h * s;

        let k = C::ScalarField::rand(&mut rng);
        let t = params.g * k;
        let a = params.h * k;

        let mut t_bytes = Vec::new();
        let mut a_bytes = Vec::new();
        t.serialize_compressed(&mut t_bytes)
            .expect("group element should exist");
        a.serialize_compressed(&mut a_bytes)
            .expect("group element should exist");

        let mut inputs = Vec::new();
        inputs.push(t_bytes);
        inputs.push(a_bytes);
        let (c1_bytes, c2_bytes) = ct
            .serialize_compressed()
            .expect("group elements should exist");
        inputs.push(c1_bytes);
        inputs.push(c2_bytes);

        let challenge: C::ScalarField =
            C::ScalarField::from_be_bytes_mod_order(&shake128(inputs.as_ref()));
        let z = k + challenge * s;
        (c, ct, PoK { t, a, z })
    }

    /// verify a proof that a commitment is of the preimage of an el gamal ciphertext
    pub fn verify(
        commitment: Commitment<C>,
        ciphertext: Ciphertext<C>,
        proof: PoK<C>,
        params: Params<C>,
    ) -> bool {
        let mut t_bytes = Vec::new();
        let mut a_bytes = Vec::new();
        proof
            .t
            .serialize_compressed(&mut t_bytes)
            .expect("group element should exist");
        proof
            .a
            .serialize_compressed(&mut a_bytes)
            .expect("group element should exist");

        let mut inputs = Vec::new();
        inputs.push(t_bytes);
        inputs.push(a_bytes);
        let (c1_bytes, c2_bytes) = ciphertext
            .serialize_compressed()
            .expect("group element should exist");
        inputs.push(c1_bytes);
        inputs.push(c2_bytes);

        let challenge: C::ScalarField =
            C::ScalarField::from_be_bytes_mod_order(&shake128(inputs.as_ref()));

        let zg = params.g * proof.z;
        let zh = params.h * proof.z;

        zg + zh == proof.t + proof.a + commitment * challenge
    }
}

fn shake128(input: &[Vec<u8>]) -> [u8; 32] {
    let mut h = Shake128::default();

    for item in input.iter() {
        h.update(item);
    }

    let mut o = [0u8; 32];
    // get challenge from hasher
    h.finalize_xof().read(&mut o);
    o
}

#[cfg(test)]
mod test {

    use super::*;
    use ark_ec::Group;
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_std::{ops::Mul, test_rng};

    #[test]
    pub fn prove_and_verify() {
        let mut rng = test_rng();
        // the secret key
        let x = <JubJub as Group>::ScalarField::rand(&mut rng);
        let g: JubJub = JubJub::generator().into();
        // the public key
        let h: JubJub = g.mul(x).into();

        let params = Params { g, h };

        let (commitment, ciphertext, proof) =
            ElGamalSigmaProtocol::prove(x, params.clone(), test_rng());
        let result = ElGamalSigmaProtocol::verify(commitment, ciphertext, proof, params);
        assert_eq!(result, true);
    }

    #[test]
    pub fn verify_fails_with_invalid_proof() {
        let mut rng = test_rng();
        // the secret key
        let x = <JubJub as Group>::ScalarField::rand(&mut rng);
        let g: JubJub = JubJub::generator().into();
        // the public key
        let h: JubJub = g.mul(x).into();

        let j = <JubJub as Group>::ScalarField::rand(&mut rng);
        let bad_proof = PoK {
            t: g.mul(j).into(),
            a: g.mul(j).into(),
            z: j,
        };

        let params = Params { g, h };

        let (commitment, ciphertext, _proof) =
            ElGamalSigmaProtocol::prove(x, params.clone(), test_rng());
        let result = ElGamalSigmaProtocol::verify(commitment, ciphertext, bad_proof, params);
        assert_eq!(result, false);
    }

    #[test]
    pub fn verify_fails_with_invalid_commitment() {
        let mut rng = test_rng();
        // the secret key
        let x = <JubJub as Group>::ScalarField::rand(&mut rng);
        let g: JubJub = JubJub::generator().into();
        // the public key
        let h: JubJub = g.mul(x).into();

        let j = <JubJub as Group>::ScalarField::rand(&mut rng);
        let bad_commitment = g.mul(j).into();

        let params = Params { g, h };

        let (_commitment, ciphertext, proof) =
            ElGamalSigmaProtocol::prove(x, params.clone(), test_rng());
        let result = ElGamalSigmaProtocol::verify(bad_commitment, ciphertext, proof, params);
        assert_eq!(result, false);
    }
}
