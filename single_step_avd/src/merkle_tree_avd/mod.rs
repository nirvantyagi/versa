use rand::Rng;
use sha3::{digest::Digest, Sha3_256};
use zexe_cp::crh::FixedLengthCRH;

use std::{collections::HashMap, error::Error as ErrorTrait, fmt};

use crate::{Error, SingleStepAVD};
use crypto_primitives::sparse_merkle_tree::{
    MerkleDepth, MerkleIndex, MerkleTreeParameters, MerkleTreePath, SparseMerkleTree,
};

pub trait MerkleTreeAVDParameters {
    const MAX_UPDATE_BATCH_SIZE: u64;
    const MAX_OPEN_ADDRESSING_PROBES: u32;

    type MerkleTreeParameters: MerkleTreeParameters;

    fn is_valid(&self) -> Result<bool, Error> {
        Self::MerkleTreeParameters::is_valid()
    }
}

pub struct MerkleTreeAVD<P: MerkleTreeAVDParameters> {
    tree: SparseMerkleTree<P::MerkleTreeParameters>,
    key_d: HashMap<[u8; 32], (u32, u32, [u8; 32])>,
    // key -> probe, version, value
    index_d: HashMap<MerkleIndex, [u8; 32]>,
}

pub struct LookupProof<P: MerkleTreeAVDParameters> {
    paths: Vec<MerkleTreePath<P::MerkleTreeParameters>>,
    keys: Vec<[u8; 32]>,
    versions: Vec<u32>,
    values: Vec<[u8; 32]>,
}

pub struct UpdateProof<P: MerkleTreeAVDParameters> {
    paths: Vec<MerkleTreePath<P::MerkleTreeParameters>>,
    indices: Vec<MerkleIndex>,
    keys: Vec<[u8; 32]>,
    versions: Vec<u32>,
    prev_values: Vec<[u8; 32]>,
    new_values: Vec<[u8; 32]>,
}

impl<P: MerkleTreeAVDParameters> Clone for LookupProof<P> {
    fn clone(&self) -> Self {
        Self {
            paths: self.paths.clone(),
            keys: self.keys.clone(),
            versions: self.versions.clone(),
            values: self.values.clone(),
        }
    }
}

impl<P: MerkleTreeAVDParameters> Clone for UpdateProof<P> {
    fn clone(&self) -> Self {
        Self {
            paths: self.paths.clone(),
            indices: self.indices.clone(),
            keys: self.keys.clone(),
            versions: self.versions.clone(),
            prev_values: self.prev_values.clone(),
            new_values: self.new_values.clone(),
        }
    }
}

impl<P: MerkleTreeAVDParameters> SingleStepAVD for MerkleTreeAVD<P> {
    type Digest = <<P::MerkleTreeParameters as MerkleTreeParameters>::H as FixedLengthCRH>::Output;
    type PublicParameters = <<P::MerkleTreeParameters as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters;
    type LookupProof = LookupProof<P>;
    type UpdateProof = UpdateProof<P>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::PublicParameters, Error> {
        Ok(<<P::MerkleTreeParameters as MerkleTreeParameters>::H as FixedLengthCRH>::setup(rng)?)
    }

    fn new<R: Rng>(_rng: &mut R, pp: &Self::PublicParameters) -> Result<Self, Error> {
        let initial_leaf = concat_leaf_data(&Default::default(), 0, &Default::default());
        Ok(MerkleTreeAVD {
            tree: SparseMerkleTree::new(&initial_leaf, pp.clone())?,
            key_d: HashMap::new(),
            index_d: HashMap::new(),
        })
    }

    fn digest(&self) -> Result<Self::Digest, Error> {
        Ok(self.tree.root.clone())
    }

    fn lookup(
        &self,
        key: &[u8; 32],
    ) -> Result<(Option<(u32, [u8; 32])>, Self::Digest, Self::LookupProof), Error> {
        let (probe, lookup_value) = match self.key_d.get(key) {
            Some((probe, version, val)) => (*probe, Some((*version, val.clone()))),
            None => {
                // Find the first unpopulated index in probe sequence
                match (0..P::MAX_OPEN_ADDRESSING_PROBES).find(|i| {
                    self.index_d
                        .get(&hash_to_index(key, *i, P::MerkleTreeParameters::DEPTH))
                        == None
                }) {
                    Some(unpopulated_probe) => (unpopulated_probe, None),
                    None => return Err(Box::new(MerkleTreeAVDError::OpenAddressingOverflow(*key))),
                }
            }
        };
        let (mut paths, mut keys, mut versions, mut values) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for p in 0..probe {
            let i = hash_to_index(key, p, P::MerkleTreeParameters::DEPTH);
            let k = self.index_d.get(&i).unwrap().clone();
            let (_, version, val) = self.key_d.get(&k).unwrap().clone();
            let path = self.tree.lookup(i)?;
            paths.push(path);
            keys.push(k);
            versions.push(version);
            values.push(val);
        }
        paths.push(
            self.tree
                .lookup(hash_to_index(key, probe, P::MerkleTreeParameters::DEPTH))?,
        );
        Ok((
            lookup_value,
            self.tree.root.clone(),
            LookupProof {
                paths,
                keys,
                versions,
                values,
            },
        ))
    }

    fn update(
        &mut self,
        key: &[u8; 32],
        value: &[u8; 32],
    ) -> Result<(Self::Digest, Self::UpdateProof), Error> {
        let (probe, version, prev_value) = match self.key_d.get(key) {
            Some((probe, version, val)) => (*probe, *version, val.clone()),
            None => {
                // Find the first unpopulated index in probe sequence
                match (0..P::MAX_OPEN_ADDRESSING_PROBES).find(|i| {
                    self.index_d
                        .get(&hash_to_index(key, *i, P::MerkleTreeParameters::DEPTH))
                        == None
                }) {
                    Some(unpopulated_probe) => (unpopulated_probe, 0, Default::default()),
                    None => return Err(Box::new(MerkleTreeAVDError::OpenAddressingOverflow(*key))),
                }
            }
        };
        let i = hash_to_index(key, probe, P::MerkleTreeParameters::DEPTH);
        self.tree
            .update(i, &concat_leaf_data(key, version + 1, value))?;
        self.key_d
            .insert(key.clone(), (probe, version + 1, value.clone()));
        self.index_d.entry(i).or_insert_with(|| key.clone());

        Ok((
            self.tree.root.clone(),
            UpdateProof {
                paths: vec![self.tree.lookup(hash_to_index(
                    key,
                    probe,
                    P::MerkleTreeParameters::DEPTH,
                ))?],
                indices: vec![i],
                keys: vec![key.clone()],
                versions: vec![version],
                prev_values: vec![prev_value],
                new_values: vec![value.clone()],
            },
        ))
    }

    fn batch_update(
        &mut self,
        kvs: &Vec<([u8; 32], [u8; 32])>,
    ) -> Result<(Self::Digest, Self::UpdateProof), Error> {
        let update_proof = kvs
            .iter()
            .map(|(k, v)| self.update(k, v))
            .collect::<Result<Vec<(Self::Digest, Self::UpdateProof)>, Error>>()?
            .iter()
            .fold(
                UpdateProof {
                    paths: Vec::new(),
                    indices: Vec::new(),
                    keys: Vec::new(),
                    versions: Vec::new(),
                    prev_values: Vec::new(),
                    new_values: Vec::new(),
                },
                |mut acc_proof, single_proof| {
                    acc_proof.paths.push(single_proof.1.paths[0].clone());
                    acc_proof.indices.push(single_proof.1.indices[0]);
                    acc_proof.keys.push(single_proof.1.keys[0].clone());
                    acc_proof.versions.push(single_proof.1.versions[0]);
                    acc_proof
                        .prev_values
                        .push(single_proof.1.prev_values[0].clone());
                    acc_proof
                        .new_values
                        .push(single_proof.1.new_values[0].clone());
                    acc_proof
                },
            );
        Ok((self.tree.root.clone(), update_proof))
    }

    fn verify_lookup(
        pp: &Self::PublicParameters,
        key: &[u8; 32],
        value: &Option<(u32, [u8; 32])>,
        digest: &Self::Digest,
        proof: &Self::LookupProof,
    ) -> Result<bool, Error> {
        if proof.paths.len() == 0
            || proof.keys.len() != proof.paths.len() - 1
            || proof.versions.len() != proof.paths.len() - 1
            || proof.values.len() != proof.paths.len() - 1
        {
            return Err(Box::new(MerkleTreeAVDError::ProofFormat));
        }

        let skipped_probes_valid = (0..proof.paths.len() - 1)
            .map(|probe| {
                Ok((proof.versions[probe] > 0)
                    && proof.paths[probe].verify(
                        digest,
                        &concat_leaf_data(
                            &proof.keys[probe],
                            proof.versions[probe],
                            &proof.values[probe],
                        ),
                        hash_to_index(key, probe as u32, P::MerkleTreeParameters::DEPTH),
                        pp,
                    )?)
            })
            .collect::<Result<Vec<bool>, Error>>()?
            .iter()
            .all(|b| *b);
        let last_probe_valid = match value {
            Some((version, val)) => proof.paths.last().unwrap().verify(
                digest,
                &concat_leaf_data(key, *version, val),
                hash_to_index(
                    key,
                    (proof.paths.len() - 1) as u32,
                    P::MerkleTreeParameters::DEPTH,
                ),
                pp,
            )?,
            None => proof.paths.last().unwrap().verify(
                digest,
                &concat_leaf_data(&Default::default(), 0, &Default::default()),
                hash_to_index(
                    key,
                    (proof.paths.len() - 1) as u32,
                    P::MerkleTreeParameters::DEPTH,
                ),
                pp,
            )?,
        };
        Ok(skipped_probes_valid && last_probe_valid)
    }

    fn verify_update(
        pp: &Self::PublicParameters,
        prev_digest: &Self::Digest,
        new_digest: &Self::Digest,
        proof: &Self::UpdateProof,
    ) -> Result<bool, Error> {
        if proof.paths.len() == 0
            || proof.indices.len() != proof.paths.len()
            || proof.keys.len() != proof.paths.len()
            || proof.versions.len() != proof.paths.len()
            || proof.prev_values.len() != proof.paths.len()
            || proof.new_values.len() != proof.paths.len()
        {
            return Err(Box::new(MerkleTreeAVDError::ProofFormat));
        }

        let mut current_digest = prev_digest.clone();
        let update_paths_valid = (0..proof.paths.len())
            .map(|upd_i| {
                let prev_k = if proof.versions[upd_i] == 0 {
                    Default::default()
                } else {
                    proof.keys[upd_i]
                };
                let preupdate_path_valid = proof.paths[upd_i].verify(
                    &current_digest,
                    &concat_leaf_data(&prev_k, proof.versions[upd_i], &proof.prev_values[upd_i]),
                    proof.indices[upd_i],
                    pp,
                )?;
                current_digest = proof.paths[upd_i].compute_root(
                    &concat_leaf_data(
                        &proof.keys[upd_i],
                        proof.versions[upd_i] + 1,
                        &proof.new_values[upd_i],
                    ),
                    proof.indices[upd_i],
                    pp,
                )?;
                Ok(preupdate_path_valid)
            })
            .collect::<Result<Vec<bool>, Error>>()?
            .iter()
            .all(|b| *b);

        Ok(current_digest == *new_digest && update_paths_valid)
    }
}

fn concat_leaf_data(key: &[u8; 32], version: u32, value: &[u8; 32]) -> Vec<u8> {
    key.iter()
        .chain(&version.to_be_bytes())
        .chain(value)
        .cloned()
        .collect()
}

fn hash_to_index(key: &[u8; 32], probe: u32, depth: MerkleDepth) -> u64 {
    let mut y: [u8; 8] = Default::default();
    y.copy_from_slice(
        &Sha3_256::new()
            .chain(key)
            .chain(&probe.to_be_bytes())
            .finalize()
            .as_slice()[0..8],
    );
    u64::from_be_bytes(y) % (1_u64 << (depth as u64))
}

#[derive(Debug)]
pub enum MerkleTreeAVDError {
    OpenAddressingOverflow([u8; 32]),
    UpdateBatchSize(u64),
    ProofFormat,
}

impl ErrorTrait for MerkleTreeAVDError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
}

impl fmt::Display for MerkleTreeAVDError {
    fn fmt(self: &Self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            MerkleTreeAVDError::OpenAddressingOverflow(k) => {
                format!("all open addressing probes populated for key: {:?}", k)
            }
            MerkleTreeAVDError::UpdateBatchSize(s) => format!("surpassed max batch size: {}", s),
            MerkleTreeAVDError::ProofFormat => "invalid proof format".to_string(),
        };
        write!(f, "{}", msg)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use algebra::ed_on_bls12_381::EdwardsAffine as JubJub;
    use rand::{rngs::StdRng, SeedableRng};
    use zexe_cp::crh::{
        pedersen::{PedersenCRH, PedersenWindow},
        FixedLengthCRH,
    };

    #[derive(Clone)]
    pub struct Window4x256;

    impl PedersenWindow for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type H = PedersenCRH<JubJub, Window4x256>;

    #[derive(Clone)]
    pub struct MerkleTreeTestParameters;

    impl MerkleTreeParameters for MerkleTreeTestParameters {
        const DEPTH: MerkleDepth = 4;
        type H = H;
    }

    #[derive(Clone)]
    pub struct MerkleTreeAVDTestParameters;

    impl MerkleTreeAVDParameters for MerkleTreeAVDTestParameters {
        const MAX_UPDATE_BATCH_SIZE: u64 = 8;
        const MAX_OPEN_ADDRESSING_PROBES: u32 = 2;
        type MerkleTreeParameters = MerkleTreeTestParameters;
    }

    type TestMerkleTreeAVD = MerkleTreeAVD<MerkleTreeAVDTestParameters>;

    #[test]
    fn update_and_verify_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut avd = TestMerkleTreeAVD::new(&mut rng, &crh_parameters).unwrap();
        let digest_0 = avd.digest().unwrap();
        let (digest_1, proof) = avd.update(&[1_u8; 32], &[2_u8; 32]).unwrap();
        assert!(
            TestMerkleTreeAVD::verify_update(&crh_parameters, &digest_0, &digest_1, &proof,)
                .unwrap()
        );
    }

    #[test]
    fn invalid_update_proof_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut avd = TestMerkleTreeAVD::new(&mut rng, &crh_parameters).unwrap();
        let digest_0 = avd.digest().unwrap();
        let (digest_1, proof) = avd.update(&[1_u8; 32], &[2_u8; 32]).unwrap();
        assert!(
            !TestMerkleTreeAVD::verify_update(&crh_parameters, &digest_1, &digest_1, &proof,)
                .unwrap()
        );
        let mut proof_maul_key = proof.clone();
        proof_maul_key.keys[0] = [10_u8; 32];
        assert!(!TestMerkleTreeAVD::verify_update(
            &crh_parameters,
            &digest_0,
            &digest_1,
            &proof_maul_key,
        )
        .unwrap());
        let mut proof_maul_index = proof.clone();
        proof_maul_index.indices[0] = 12;
        assert!(!TestMerkleTreeAVD::verify_update(
            &crh_parameters,
            &digest_0,
            &digest_1,
            &proof_maul_index,
        )
        .unwrap());
        let mut proof_maul_version = proof.clone();
        proof_maul_version.versions[0] = 1;
        assert!(!TestMerkleTreeAVD::verify_update(
            &crh_parameters,
            &digest_0,
            &digest_1,
            &proof_maul_version,
        )
        .unwrap());
        let mut proof_maul_value = proof.clone();
        proof_maul_value.new_values[0] = [0_u8; 32];
        assert!(!TestMerkleTreeAVD::verify_update(
            &crh_parameters,
            &digest_0,
            &digest_1,
            &proof_maul_value,
        )
        .unwrap());
    }

    #[test]
    fn batch_update_and_verify_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut avd = TestMerkleTreeAVD::new(&mut rng, &crh_parameters).unwrap();
        let updates = vec![
            ([1_u8; 32], [2_u8; 32]),
            ([1_u8; 32], [3_u8; 32]),
            ([10_u8; 32], [11_u8; 32]),
        ];
        let digest_0 = avd.digest().unwrap();
        let (digest_1, proof) = avd.batch_update(&updates).unwrap();
        assert!(
            TestMerkleTreeAVD::verify_update(&crh_parameters, &digest_0, &digest_1, &proof,)
                .unwrap()
        );
    }

    #[test]
    fn lookup_member_and_verify_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut avd = TestMerkleTreeAVD::new(&mut rng, &crh_parameters).unwrap();
        assert!(avd.update(&[1_u8; 32], &[2_u8; 32]).is_ok());
        let (value, digest_1, proof) = avd.lookup(&[1_u8; 32]).unwrap();
        assert!(TestMerkleTreeAVD::verify_lookup(
            &crh_parameters,
            &[1_u8; 32],
            &value,
            &digest_1,
            &proof,
        )
        .unwrap());
        assert_eq!(value.unwrap(), (1, [2_u8; 32]));
    }

    #[test]
    fn lookup_nonmember_and_verify_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut avd = TestMerkleTreeAVD::new(&mut rng, &crh_parameters).unwrap();
        assert!(avd.update(&[1_u8; 32], &[2_u8; 32]).is_ok());
        let (value, digest_1, proof) = avd.lookup(&[10_u8; 32]).unwrap();
        assert!(TestMerkleTreeAVD::verify_lookup(
            &crh_parameters,
            &[10_u8; 32],
            &value,
            &digest_1,
            &proof,
        )
        .unwrap());
        assert!(value.is_none());
    }

    #[test]
    fn version_update_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut avd = TestMerkleTreeAVD::new(&mut rng, &crh_parameters).unwrap();
        assert!(avd.update(&[1_u8; 32], &[2_u8; 32]).is_ok());
        let (value_1, digest_1, proof_1) = avd.lookup(&[1_u8; 32]).unwrap();
        assert!(TestMerkleTreeAVD::verify_lookup(
            &crh_parameters,
            &[1_u8; 32],
            &value_1,
            &digest_1,
            &proof_1,
        )
        .unwrap());
        assert_eq!(value_1.unwrap(), (1, [2_u8; 32]));
        assert!(avd.update(&[1_u8; 32], &[3_u8; 32]).is_ok());
        let (value_2, digest_2, proof_2) = avd.lookup(&[1_u8; 32]).unwrap();
        assert!(TestMerkleTreeAVD::verify_lookup(
            &crh_parameters,
            &[1_u8; 32],
            &value_2,
            &digest_2,
            &proof_2,
        )
        .unwrap());
        assert_eq!(value_2.unwrap(), (2, [3_u8; 32]));
    }

    #[test]
    fn invalid_lookup_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut avd = TestMerkleTreeAVD::new(&mut rng, &crh_parameters).unwrap();
        assert!(avd.update(&[1_u8; 32], &[2_u8; 32]).is_ok());
        let (value, digest_1, proof) = avd.lookup(&[1_u8; 32]).unwrap();
        assert!(TestMerkleTreeAVD::verify_lookup(
            &crh_parameters,
            &[1_u8; 32],
            &value,
            &digest_1,
            &proof,
        )
        .unwrap());
        assert_eq!(value.unwrap(), (1, [2_u8; 32]));
        assert!(!TestMerkleTreeAVD::verify_lookup(
            &crh_parameters,
            &[1_u8; 32],
            &None,
            &digest_1,
            &proof,
        )
        .unwrap());
        assert!(!TestMerkleTreeAVD::verify_lookup(
            &crh_parameters,
            &[1_u8; 32],
            &Some((2, [2_u8; 32])),
            &digest_1,
            &proof,
        )
        .unwrap());
        assert!(!TestMerkleTreeAVD::verify_lookup(
            &crh_parameters,
            &[1_u8; 32],
            &Some((1, [12_u8; 32])),
            &digest_1,
            &proof,
        )
        .unwrap());
    }

    #[test]
    fn open_addressing_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut avd = TestMerkleTreeAVD::new(&mut rng, &crh_parameters).unwrap();
        let updates = vec![
            ([1_u8; 32], [2_u8; 32]),
            //([11_u8; 32], [12_u8; 32]),
            //([51_u8; 32], [52_u8; 32]),
            // (51, 0) and (51, 1) collide with (1, 0) and (11, 0)
        ];
        let mut result = avd.batch_update(&updates);
        assert!(result.is_ok());

        // Non-membership open addressing
        let (value_1, digest_1, proof_1) = avd.lookup(&[51_u8; 32]).unwrap();
        assert_eq!(proof_1.paths.len(), 2);
        assert!(TestMerkleTreeAVD::verify_lookup(
            &crh_parameters,
            &[51_u8; 32],
            &value_1,
            &digest_1,
            &proof_1,
        )
        .unwrap());
        assert!(value_1.is_none());

        // Membership open addressing
        result = avd.update(&[51_u8; 32], &[52_u8; 32]);
        assert!(result.is_ok());
        let (value_2, digest_2, proof_2) = avd.lookup(&[51_u8; 32]).unwrap();
        assert_eq!(proof_2.paths.len(), 2);
        assert!(TestMerkleTreeAVD::verify_lookup(
            &crh_parameters,
            &[51_u8; 32],
            &value_2,
            &digest_2,
            &proof_2,
        )
        .unwrap());
        assert_eq!(value_2.unwrap(), (1, [52_u8; 32]));

        // Adding (11, 1) does not overflow
        result = avd.update(&[11_u8; 32], &[12_u8; 32]);
        assert!(result.is_ok());
        let (value_3, digest_3, proof_3) = avd.lookup(&[11_u8; 32]).unwrap();
        assert_eq!(proof_3.paths.len(), 2);
        assert!(TestMerkleTreeAVD::verify_lookup(
            &crh_parameters,
            &[11_u8; 32],
            &value_3,
            &digest_3,
            &proof_3,
        )
        .unwrap());
        assert_eq!(value_3.unwrap(), (1, [12_u8; 32]));
    }

    #[test]
    fn open_addressing_overflow_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut avd = TestMerkleTreeAVD::new(&mut rng, &crh_parameters).unwrap();
        let updates = vec![
            ([1_u8; 32], [2_u8; 32]),
            ([11_u8; 32], [12_u8; 32]),
            //([51_u8; 32], [52_u8; 32]),
            // (51, 0) and (51, 1) collide with (1, 0) and (11, 0)
        ];
        let result = avd.batch_update(&updates);
        assert!(result.is_ok());

        // Overflow during lookup
        let lookup_overflow_result = avd.lookup(&[51_u8; 32]);
        assert!(lookup_overflow_result.is_err());

        // Overflow during update
        let update_overflow_result = avd.update(&[51_u8; 32], &[52_u8; 32]);
        assert!(update_overflow_result.is_err());
    }
}
