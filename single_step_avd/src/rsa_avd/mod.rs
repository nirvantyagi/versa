use rand::Rng;
use ark_ff::{
    bytes::ToBytes,
    fields::PrimeField,
    ToConstraintField,
};

use crate::{Error, SingleStepAVD};

use rsa::{
    kvac::{RsaKVAC, RsaKVACParams, Commitment, MembershipWitness, UpdateProof},
    hash::{Hasher, hash_to_prime::{PocklingtonCertificate, PocklingtonPlan, ExtensionCertificate, PlannedExtension}},
    bignat::{BigNat, Order, nat_to_limbs, constraints::BigNatCircuitParams},
    poker::PoKERParams,
};

use std::{
    io::{Result as IoResult, Write},
    marker::PhantomData,
    hash::{Hash, Hasher as StdHasher},
    convert::TryInto,
};

pub mod store;
pub mod constraints;

pub struct RsaAVD<T: store::RSAAVDStorer> {
    store: T,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UpdateProofWrapper<P, H>
    where
        P: RsaKVACParams,
        H: Hasher,
{
    proof: UpdateProof<P, H>,
    _params: PhantomData<P>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DigestWrapper<P: RsaKVACParams, C: BigNatCircuitParams> {
    digest: Commitment<P>,
    _params: PhantomData<P>,
    _circuit_params: PhantomData<C>,

}

impl<P: RsaKVACParams, H: Hasher> Default for UpdateProofWrapper<P, H> {
    fn default() -> Self {
        let plan = PocklingtonPlan::new(P::PoKERParams::HASH_TO_PRIME_ENTROPY);
        let mut cert = PocklingtonCertificate::<H>::default();
        cert.base_plan = PlannedExtension {
            nonce_bits: plan.base_nonce_bits,
            random_bits: plan.base_random_bits,
        };
        for i in 0..plan.extensions.len() {
            cert.extensions.push(ExtensionCertificate{
                plan: plan.extensions[i].clone(),
                checking_base: BigNat::from(2),
                result: Default::default(),
                nonce: Default::default(),
            });
        }
        UpdateProofWrapper {
            proof: UpdateProof::<P, H>{
                v_a: Default::default(),
                v_b: Default::default(),
                v_1: Default::default(),
                v_2: Default::default(),
                r_a: Default::default(),
                r_b: Default::default(),
                l: BigNat::from(1),
                cert: cert,
            },
            _params: PhantomData,
        }
    }
}

impl<P: RsaKVACParams, C: BigNatCircuitParams> Default for DigestWrapper<P, C> {
    fn default() -> Self {
        Self {
            digest: Default::default(),
            _params: PhantomData,
            _circuit_params: PhantomData,
        }
    }
}

impl<P: RsaKVACParams, C: BigNatCircuitParams> Hash for DigestWrapper<P, C> {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        self.digest.c1.hash(state);
        self.digest.c2.hash(state);
    }
}

impl<P: RsaKVACParams, C: BigNatCircuitParams> ToBytes for DigestWrapper<P, C> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        let num_bytes_per_bignat = ((C::N_LIMBS * C::LIMB_WIDTH - 1) / 8) + 1;
        //Must match ToBytesGadget in BigNatVar
        let mut c0_bytes = self.digest.c1.n.to_digits::<u8>(Order::LsfBe);
        c0_bytes.resize(num_bytes_per_bignat, 0);
        c0_bytes.write(&mut writer)?;
        let mut c1_bytes = self.digest.c2.n.to_digits::<u8>(Order::LsfBe);
        c1_bytes.resize(num_bytes_per_bignat, 0);
        c1_bytes.write(&mut writer)
    }
}

impl<P: RsaKVACParams, C: BigNatCircuitParams, ConstraintF: PrimeField> ToConstraintField<ConstraintF> for DigestWrapper<P, C> {
    fn to_field_elements(&self) -> Option<Vec<ConstraintF>> {
        let mut v = Vec::new();
        v.extend_from_slice(&nat_to_limbs(&self.digest.c1.n, C::LIMB_WIDTH, C::N_LIMBS).unwrap());
        v.extend_from_slice(&nat_to_limbs(&self.digest.c2.n, C::LIMB_WIDTH, C::N_LIMBS).unwrap());
        Some(v)
    }
}

impl<T: store::RSAAVDStorer> SingleStepAVD for RsaAVD<T> {
    type Digest = DigestWrapper<T::P, T::C>;
    type PublicParameters = ();
    type LookupProof = MembershipWitness<T::P>;
    type UpdateProof = UpdateProofWrapper<T::P, T::CircuitH>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::PublicParameters, Error> {
        Ok(())
    }

    fn new<R: Rng>(_rng: &mut R, s: T) -> Result<Self, Error> {
        Ok(Self { store: s })
    }

    fn digest(&self) -> Result<Self::Digest, Error> {
        Ok(Self::wrap_digest(self.store.kvac_get_commitment()))
    }

    fn lookup(&mut self, key: &[u8; 32]) -> Result<(Option<(u64, [u8; 32])>, Self::Digest, Self::LookupProof), Error> {
        let (v, witness) = self.store.kvac_lookup(&to_bignat(key))?;
        let versioned_v = match v {
            Some(n) => Some((witness.u as u64, from_bignat(&n))),
            None => None,
        };
        Ok((versioned_v, self.digest()?, witness))
    }

    fn update(&mut self, key: &[u8; 32], value: &[u8; 32]) -> Result<(Self::Digest, Self::UpdateProof), Error> {
        let (d, proof) = self.store.kvac_update(to_bignat(key), to_bignat(value))?;
        Ok((Self::wrap_digest(d), Self::wrap_proof(proof)))

    }

    fn batch_update(&mut self, kvs: &Vec<([u8; 32], [u8; 32])>) -> Result<(Self::Digest, Self::UpdateProof), Error> {
        let (d, proof) = self.store.kvac_batch_update(
            &kvs.iter()
                .map(|(k, v)| (to_bignat(k), to_bignat(v)))
                .collect::<Vec<(BigNat, BigNat)>>()
        )?;
        Ok((Self::wrap_digest(d), Self::wrap_proof(proof)))
    }

    fn verify_update(_pp: &Self::PublicParameters, prev_digest: &Self::Digest, new_digest: &Self::Digest, proof: &Self::UpdateProof) -> Result<bool, Error> {
        RsaKVAC::<T>::verify_update_append_only(
            &prev_digest.digest,
            &new_digest.digest,
            &proof.proof,
        )
    }

    fn verify_lookup(_pp: &Self::PublicParameters, key: &[u8; 32], value: &Option<(u64, [u8; 32])>, digest: &Self::Digest, proof: &Self::LookupProof) -> Result<bool, Error> {
        let (version_matches, v) = match value {
            Some((version, v_arr)) => (*version == proof.u as u64, Some(to_bignat(v_arr))),
            None => (true, None),
        };
        let witness_verifies = RsaKVAC::<T>::verify_witness(
            &to_bignat(key),
            &v,
            &digest.digest,
            proof,
        )?;
        Ok(version_matches && witness_verifies)
    }

}

pub fn to_bignat(arr: &[u8; 32]) -> BigNat {
    BigNat::from_digits(&arr[..], Order::MsfBe)
}

pub fn from_bignat(n: &BigNat) -> [u8; 32] {
    let digits = n.to_digits::<u8>(Order::MsfBe);
    digits.try_into().unwrap()
}

impl<T: store::RSAAVDStorer> RsaAVD<T> {
    fn wrap_digest(d: Commitment<T::P>) -> DigestWrapper<T::P, T::C> {
        DigestWrapper { digest: d, _params: PhantomData, _circuit_params: PhantomData }
    }

    fn wrap_proof(proof: UpdateProof<T::P, T::CircuitH>) -> UpdateProofWrapper<T::P, T::CircuitH> {
        UpdateProofWrapper { proof: proof, _params: PhantomData }
    }
}
