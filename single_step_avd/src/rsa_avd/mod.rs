use rand::Rng;
use algebra::bytes::ToBytes;

use crate::{Error, SingleStepAVD};

use rsa::{
    kvac::{RsaKVAC, RsaKVACParams, Commitment, MembershipWitness, UpdateProof},
    hash::{Hasher, hash_to_prime::{PocklingtonCertificate, PocklingtonPlan, ExtensionCertificate}},
    bignat::{BigNat, Order, constraints::BigNatCircuitParams},
    poker::PoKERParams,
};

use std::{
    io::{Result as IoResult, Write},
    marker::PhantomData,
    hash::{Hash, Hasher as StdHasher},
    convert::TryInto,
};

pub struct RsaAVD<P, H, CircuitH, C>
    where
        P: RsaKVACParams,
        H: Hasher,
        CircuitH: Hasher,
        C: BigNatCircuitParams,
{
    kvac: RsaKVAC<P, H, CircuitH, C>
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
pub struct DigestWrapper<P: RsaKVACParams> {
    digest: Commitment<P>,
    _params: PhantomData<P>,

}

impl<P: RsaKVACParams, H: Hasher> Default for UpdateProofWrapper<P, H> {
    fn default() -> Self {
        let plan = PocklingtonPlan::new(P::PoKERParams::HASH_TO_PRIME_ENTROPY);
        let mut cert = PocklingtonCertificate::<H>::default();
        for i in 0..plan.extensions.len() {
            cert.extensions.push(ExtensionCertificate{
                plan: plan.extensions[i].clone(),
                checking_base: Default::default(),
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

impl<P: RsaKVACParams> Default for DigestWrapper<P> {
    fn default() -> Self {
        Self {
            digest: (Default::default(), Default::default()),
            _params: PhantomData,
        }
    }
}

impl<P: RsaKVACParams> Hash for DigestWrapper<P> {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        self.digest.0.hash(state);
        self.digest.1.hash(state);
    }
}

impl<P: RsaKVACParams> ToBytes for DigestWrapper<P> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.digest.0.write(&mut writer)?;
        self.digest.1.write(&mut writer)
    }
}

impl<P, H, CircuitH, C> SingleStepAVD for RsaAVD<P, H, CircuitH, C>

where
    P: RsaKVACParams,
    H: Hasher,
    CircuitH: Hasher,
    C: BigNatCircuitParams,
{
    type Digest = DigestWrapper<P>;
    type PublicParameters = ();
    type LookupProof = MembershipWitness<P>;
    type UpdateProof = UpdateProofWrapper<P, CircuitH>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::PublicParameters, Error> {
        Ok(())
    }

    fn new<R: Rng>(_rng: &mut R, _pp: &Self::PublicParameters) -> Result<Self, Error> {
        Ok(Self { kvac: RsaKVAC::new() })
    }

    fn digest(&self) -> Result<Self::Digest, Error> {
        Ok(Self::wrap_digest(self.kvac.commitment.clone()))
    }

    fn lookup(&mut self, key: &[u8; 32]) -> Result<(Option<(u64, [u8; 32])>, Self::Digest, Self::LookupProof), Error> {
        let (v, witness) = self.kvac.lookup(&to_bignat(key))?;
        let versioned_v = match v {
            Some(n) => Some((witness.u as u64, from_bignat(&n))),
            None => None,
        };
        Ok((versioned_v, self.digest()?, witness))
    }

    fn update(&mut self, key: &[u8; 32], value: &[u8; 32]) -> Result<(Self::Digest, Self::UpdateProof), Error> {
        let (d, proof) = self.kvac.update(to_bignat(key), to_bignat(value))?;
        Ok((Self::wrap_digest(d), Self::wrap_proof(proof)))

    }

    fn batch_update(&mut self, kvs: &Vec<([u8; 32], [u8; 32])>) -> Result<(Self::Digest, Self::UpdateProof), Error> {
        let (d, proof) = self.kvac.batch_update(
            &kvs.iter()
                .map(|(k, v)| (to_bignat(k), to_bignat(v)))
                .collect::<Vec<(BigNat, BigNat)>>()
        )?;
        Ok((Self::wrap_digest(d), Self::wrap_proof(proof)))
    }

    fn verify_update(_pp: &Self::PublicParameters, prev_digest: &Self::Digest, new_digest: &Self::Digest, proof: &Self::UpdateProof) -> Result<bool, Error> {
        RsaKVAC::<P, H, CircuitH, C>::verify_update_append_only(
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
        let witness_verifies = RsaKVAC::<P, H, CircuitH, C>::verify_witness(
            &to_bignat(key),
            &v,
            &digest.digest,
            proof,
        )?;
        Ok(version_matches && witness_verifies)
    }

}

fn to_bignat(arr: &[u8; 32]) -> BigNat {
    BigNat::from_digits(&arr[..], Order::MsfBe)
}

fn from_bignat(n: &BigNat) -> [u8; 32] {
    let digits = n.to_digits::<u8>(Order::MsfBe);
    digits.try_into().unwrap()
}

impl<P, H, CircuitH, C> RsaAVD<P, H, CircuitH, C>
    where
        P: RsaKVACParams,
        H: Hasher,
        CircuitH: Hasher,
        C: BigNatCircuitParams,
{
    fn wrap_digest(d: Commitment<P>) -> DigestWrapper<P> {
        DigestWrapper { digest: d, _params: PhantomData }
    }

    fn wrap_proof(proof: UpdateProof<P, CircuitH>) -> UpdateProofWrapper<P, CircuitH> {
        UpdateProofWrapper { proof: proof, _params: PhantomData }
    }
}
