use crate::{
    bignat::BigNat,
    hog::{RsaHiddenOrderGroup, RsaGroupParams},
};

use std::fmt::{self, Debug, Display, Formatter};
use std::{
    error::Error as ErrorTrait,
    marker::PhantomData,
    cmp::{max, min, Ordering},
    collections::HashMap,
};

use crate::Error;


pub trait RsaKVACParams: Clone + Eq + Debug {
    const KEY_LEN: usize;
    const VALUE_LEN: usize;
    type RsaGroupParams: RsaGroupParams;
}

pub type RsaParams<P> = <P as RsaKVACParams>::RsaGroupParams;
pub type RsaQGroup<P> = RsaHiddenOrderGroup<RsaParams<P>>;
pub type Commitment<P> = (RsaQGroup<P>, RsaQGroup<P>);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MembershipWitness<P: RsaKVACParams> {
    _params: PhantomData<P>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UpdateProof<P: RsaKVACParams> {
    _params: PhantomData<P>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RsaKVAC<P: RsaKVACParams> {
    pub map: HashMap<BigNat, (BigNat, MembershipWitness<P>)>,
    pub commitment: Commitment<P>,
}

impl<P: RsaKVACParams> RsaKVAC<P> {
    pub fn new() -> Self {
        RsaKVAC {
            map: HashMap::new(),
            commitment: (
                RsaQGroup::<P>::from_nat(BigNat::from(1)),
                RsaQGroup::<P>::from_nat(RsaParams::<P>::G()),
            )
        }
    }

    pub fn lookup(&self, k: &BigNat) -> Result<(Option<BigNat>, MembershipWitness<P>), Error> {
        match self.map.get(k) {
            Some((value, witness)) => Ok((Some(value.clone()), witness.clone())),
            None => Ok((None, MembershipWitness{_params: PhantomData})), //TODO: non-membership proof
        }
    }

    pub fn update(&mut self, k: BigNat, v: BigNat) -> Result<(Commitment<P>, UpdateProof<P>), Error> {
        let (c1, c2) = &self.commitment;


        unimplemented!()
    }

}

