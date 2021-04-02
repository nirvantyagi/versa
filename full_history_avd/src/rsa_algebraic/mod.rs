use rsa::{
    kvac::{
        RsaKVACParams, RsaKVAC, Commitment, MembershipWitness, UpdateProof,
    },
    poker::{
        PoKER,
        Statement as PoKERStatement,
        Witness as PoKERWitness,
    },
    hash::{Hasher},
    bignat::{BigNat, constraints::BigNatCircuitParams},
};
use single_step_avd::rsa_avd::{to_bignat, from_bignat};

use crate::{Error, FullHistoryAVD, get_checkpoint_epochs};
use rand::{Rng, CryptoRng};

pub type RsaParams<P> = <P as RsaKVACParams>::RsaGroupParams;
pub type PoKParams<P> = <P as RsaKVACParams>::PoKERParams;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RsaFullHistoryAVD<P: RsaKVACParams, H1: Hasher, H2: Hasher, C: BigNatCircuitParams> {
    kvac: RsaKVAC<P, H1, H2, C>,
    digests: Vec<Commitment<P>>,
    range_proofs: Vec<Vec<(UpdateProof<P, H2>, BigNat, BigNat)>>, // (proof, z_product, delta_sum)
}

pub struct AuditProof<P: RsaKVACParams, H2: Hasher> {
    range_proofs: Vec<UpdateProof<P, H2>>,
    checkpoint_digests: Vec<Commitment<P>>,
}


impl<P: RsaKVACParams, H1: Hasher, H2: Hasher, C: BigNatCircuitParams>
FullHistoryAVD for RsaFullHistoryAVD<P, H1, H2, C> {
    type Digest = Commitment<P>;
    type PublicParameters = ();
    type LookupProof = MembershipWitness<P>;
    type AuditProof = AuditProof<P, H2>;

    fn setup<R: Rng + CryptoRng>(_rng: &mut R) -> Result<Self::PublicParameters, Error> {
        Ok(())
    }

    fn new<R: Rng + CryptoRng>(_rng: &mut R, _pp: &Self::PublicParameters) -> Result<Self, Error> {
        let kvac = RsaKVAC::new();
        let digests = vec![kvac.commitment.clone()];
        Ok(Self {
            kvac,
            digests,
            range_proofs: vec![],
        })
    }

    fn digest(&self) -> Result<Self::Digest, Error> {
        Ok(self.digests.last().unwrap().clone())
    }

    fn lookup(&mut self, key: &[u8; 32]) -> Result<(Option<(u64, [u8; 32])>, Self::Digest, Self::LookupProof), Error> {
        let (v, witness) = self.kvac.lookup(&to_bignat(key))?;
        let versioned_v = match v {
            Some(n) => Some((witness.u as u64, from_bignat(&n))),
            None => None,
        };
        Ok((versioned_v, self.digest()?, witness))
    }

    fn update<R: Rng + CryptoRng>(&mut self, rng: &mut R, key: &[u8; 32], value: &[u8; 32]) -> Result<Self::Digest, Error> {
        self.batch_update(rng, &vec![(key.clone(), value.clone())])
    }

    fn batch_update<R: Rng + CryptoRng>(&mut self, _rng: &mut R, kvs: &Vec<([u8; 32], [u8; 32])>) -> Result<Self::Digest, Error> {
        let (d, proof, (z, delta)) = self.kvac._batch_update(
            &kvs.iter()
                .map(|(k, v)| (to_bignat(k), to_bignat(v)))
                .collect::<Vec<(BigNat, BigNat)>>()
        )?;
        self.digests.push(d.clone());

        //TODO: Only need to store z, delta for last two elements of each level
        // Compute range proofs
        let new_epoch = self.digests.len() - 1;
        let aggr_level = new_epoch.trailing_zeros() as usize;
        if aggr_level == self.range_proofs.len() {
            self.range_proofs.push(vec![]);
        }
        self.range_proofs[0].push((proof, z, delta));
        for level in 1..=aggr_level {  // Aggregate
            let start_epoch = new_epoch - (1 << level);
            let statement = PoKERStatement {
                u1: self.digests[start_epoch].c1.clone(),
                u2: self.digests[start_epoch].c2.clone(),
                w1: self.digests[new_epoch].c1.clone(),
                w2: self.digests[new_epoch].c2.clone(),
            };
            let level_len = self.range_proofs[level - 1].len();
            let (_, z1, delta1) = self.range_proofs[level - 1][level_len - 1].clone();
            let (_, z2, delta2) = self.range_proofs[level - 1][level_len - 2].clone();
            let witness = PoKERWitness {
                a: z1.clone() * z2.clone(),
                b: z1.clone() * delta2.clone() + z2.clone() * delta1.clone(),
            };
            let proof = PoKER::<PoKParams<P>, RsaParams<P>, H2, C>::prove(&statement, &witness)?;
            self.range_proofs[level].push((proof, witness.a, witness.b));
        }
        Ok(d)
    }

    fn verify_lookup(_pp: &Self::PublicParameters, key: &[u8; 32], value: &Option<(u64, [u8; 32])>, digest: &Self::Digest, proof: &Self::LookupProof) -> Result<bool, Error> {
        let (version_matches, v) = match value {
            Some((version, v_arr)) => (*version == proof.u as u64, Some(to_bignat(v_arr))),
            None => (true, None),
        };
        let witness_verifies = RsaKVAC::<P, H1, H2, C>::verify_witness(
            &to_bignat(key),
            &v,
            digest,
            proof,
        )?;
        Ok(version_matches && witness_verifies)
    }

    fn audit(&self, start_epoch: usize, end_epoch: usize) -> Result<(Self::Digest, Self::AuditProof), Error> {
        let (checkpoints, checkpoint_ranges) = get_checkpoint_epochs(start_epoch, end_epoch);
        let checkpoint_digests = checkpoints.iter()
            .map(|i| self.digests[*i].clone())
            .collect::<Vec<_>>();
        let range_proofs = checkpoints.iter().zip(&checkpoint_ranges)
            .map(|(ckpt, ckpt_level)| self.range_proofs[*ckpt_level][ckpt >> ckpt_level].clone().0)
            .collect::<Vec<_>>();
        Ok((
            self.digest()?,
            AuditProof {
                range_proofs,
                checkpoint_digests,
            },
        ))
    }

    fn verify_audit(_pp: &Self::PublicParameters, _start_epoch: usize, _end_epoch: usize, _digest: &Self::Digest, proof: &Self::AuditProof) -> Result<bool, Error> {
        Ok(proof.range_proofs.iter()
            .enumerate()
            .map(|(i, range_proof)|
                RsaKVAC::<P, H1, H2, C>::verify_update_append_only(
                    &proof.checkpoint_digests[i].clone(),
                    &proof.checkpoint_digests[i+1].clone(),
                    range_proof,
                )
            ).collect::<Result<Vec<_>, Error>>()?
            .iter().all(|b| *b)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381::{Fq};
    use rand::{rngs::StdRng, SeedableRng};
    use rsa::{
        poker::PoKERParams,
        hog::{RsaGroupParams},
        hash::{HasherFromDigest},
    };

    use std::time::Instant;


    // Parameters for RSA AVD
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestRsaParams;
    impl RsaGroupParams for TestRsaParams {
        const RAW_G: usize = 2;
        const RAW_M: &'static str = "2519590847565789349402718324004839857142928212620403202777713783604366202070\
                          7595556264018525880784406918290641249515082189298559149176184502808489120072\
                          8449926873928072877767359714183472702618963750149718246911650776133798590957\
                          0009733045974880842840179742910064245869181719511874612151517265463228221686\
                          9987549182422433637259085141865462043576798423387184774447920739934236584823\
                          8242811981638150106748104516603773060562016196762561338441436038339044149526\
                          3443219011465754445417842402092461651572335077870774981712577246796292638635\
                          6373289912154831438167899885040445364023527381951378636564391212010397122822\
                          120720357";
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct BigNatTestParams;
    impl BigNatCircuitParams for BigNatTestParams {
        const LIMB_WIDTH: usize = 32;
        const N_LIMBS: usize = 64;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestPokerParams;
    impl PoKERParams for TestPokerParams {
        const HASH_TO_PRIME_ENTROPY: usize = 128;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestKVACParams;
    impl RsaKVACParams for TestKVACParams {
        const KEY_LEN: usize = 256;
        const VALUE_LEN: usize = 256;
        const PRIME_LEN: usize = 264;
        type RsaGroupParams = TestRsaParams;
        type PoKERParams = TestPokerParams;
    }

    pub type H = HasherFromDigest<Fq, blake3::Hasher>;
    pub type TestRsaFHAVD = RsaFullHistoryAVD<TestKVACParams, H, H, BigNatTestParams>;

    #[test]
    fn rsa_update_and_verify_algebraic_full_history_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let start = Instant::now();
        let pp = TestRsaFHAVD::setup(&mut rng).unwrap();
        let mut avd  = TestRsaFHAVD::new(&mut rng, &pp).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t setup time: {} s", bench);

        fn u8_to_array(n: u8) -> [u8; 32] {
            let mut arr = [0_u8; 32];
            arr[31] = n;
            arr
        }

        let epoch1_update = &vec![
            (u8_to_array(1), u8_to_array(2)),
            (u8_to_array(11), u8_to_array(12)),
            (u8_to_array(21), u8_to_array(22)),
        ];
        let epoch2_update = &vec![
            (u8_to_array(1), u8_to_array(3)),
            (u8_to_array(11), u8_to_array(13)),
            (u8_to_array(21), u8_to_array(23)),
        ];
        let epoch3_update = &vec![
            (u8_to_array(1), u8_to_array(4)),
            (u8_to_array(11), u8_to_array(14)),
            (u8_to_array(21), u8_to_array(24)),
        ];
        let epoch4_update = &vec![
            (u8_to_array(1), u8_to_array(5)),
            (u8_to_array(11), u8_to_array(15)),
            (u8_to_array(31), u8_to_array(35)),
        ];
        let epoch5_update = &vec![
            (u8_to_array(1), u8_to_array(6)),
            (u8_to_array(11), u8_to_array(16)),
            (u8_to_array(31), u8_to_array(36)),
        ];

        let start = Instant::now();
        let d1 = avd.batch_update(&mut rng, &epoch1_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 1 proving time: {} s", bench);

        let (_, audit_proof) = avd.audit(0, 1).unwrap();
        let verify_audit = TestRsaFHAVD::verify_audit(&pp, 0, 1, &d1, &audit_proof).unwrap();
        assert!(verify_audit);

        let start = Instant::now();
        let _d2 = avd.batch_update(&mut rng, &epoch2_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 2 proving time: {} s", bench);

        let start = Instant::now();
        let _d3 = avd.batch_update(&mut rng, &epoch3_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 3 proving time: {} s", bench);

        let start = Instant::now();
        let _d4 = avd.batch_update(&mut rng, &epoch4_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 4 proving time: {} s", bench);

        let start = Instant::now();
        let d5 = avd.batch_update(&mut rng, &epoch5_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 5 proving time: {} s", bench);

        let (_, audit_proof) = avd.audit(1, 5).unwrap();
        let verify_audit = TestRsaFHAVD::verify_audit(&pp, 1, 5, &d5, &audit_proof).unwrap();
        assert!(verify_audit);
    }
}