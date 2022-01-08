use std::{
    collections::HashMap,
};
use crate::Error;
use ark_ff::bytes::ToBytes;
use crypto_primitives::{
    sparse_merkle_tree::{
        store::SMTStorer,
        MerkleIndex,
        MerkleTreeParameters,
        MerkleTreePath,
        SparseMerkleTree,
    },
    hash::FixedLengthCRH,
};
use crate::history_tree::{
    store::HTStorer,
};

pub struct HTMemStore<T: SMTStorer, D: ToBytes + Eq + Clone> {
    pub tree: SparseMerkleTree<T>,
    digest_d: HashMap<MerkleIndex, D>,
    epoch: MerkleIndex,
}

impl<S: SMTStorer, D: ToBytes + Eq + Clone> HTStorer for HTMemStore<S, D> {
    type S = S;
    type D = D;

    fn get_root(&self) -> <<<<Self as HTStorer>::S as SMTStorer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output {
        return self.tree.store.get_root();
    }

    fn get_epoch(&self) -> MerkleIndex {
        return self.epoch.clone();
    }
    fn set_epoch(&mut self, index: MerkleIndex) -> Result<(), Error> {
        self.epoch = index;
        return Ok(());
    }

    fn get_digest_d(&self, key: &MerkleIndex) -> Option<&Self::D> {
        return self.digest_d.get(key);
    }
    fn insert_digest_d(&mut self, index: MerkleIndex, digest: Self::D) -> Option<Self::D> {
        return self.digest_d.insert(index, digest);
    }

    fn lookup_smt(&mut self, index: MerkleIndex) -> Result<MerkleTreePath<<<Self as HTStorer>::S as SMTStorer>::P>, Error> {
        return self.tree.lookup(index);
    }
    fn update_smt(&mut self, index: MerkleIndex, leaf_value: &[u8]) -> Result<(), Error> {
        return self.tree.update(index, leaf_value);
    }

}
