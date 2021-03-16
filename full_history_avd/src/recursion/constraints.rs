use single_step_avd::{
    SingleStepAVD,
    constraints::SingleStepAVDGadget,
};
use crypto_primitives::sparse_merkle_tree::{
    MerkleTreeParameters,
    constraints::MerkleTreePathVar,
};
use algebra::{
    biginteger::BigInteger,
    ToConstraintField,
    fields::{PrimeField, FpParameters},
    curves::{CycleEngine, PairingEngine},
};
use groth16::{Proof, VerifyingKey};
use r1cs_core::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError,
};
use r1cs_std::{
    prelude::*,
    uint64::UInt64,
    fields::fp::FpVar,
    ToConstraintFieldGadget,
};
use zexe_cp::{
    crh::{FixedLengthCRH, FixedLengthCRHGadget},
    nizk::{
        constraints::NIZKVerifierGadget,
        groth16::{
            constraints::{Groth16VerifierGadget, ProofVar, VerifyingKeyVar},
            Groth16,
        },
    },
};

use crate::{
    Error,
    history_tree::{
        SingleStepAVDWithHistory,
        SingleStepUpdateProof,
        constraints::SingleStepUpdateProofVar,
    },
};

use rand::rngs::mock::StepRng;
use std::{
    marker::PhantomData, ops::MulAssign, convert::TryFrom,
};
use bench_utils::{end_timer, start_timer};


pub struct InnerSingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, <Cycle::E2 as PairingEngine>::Fq>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, <Cycle::E2 as PairingEngine>::Fq>,
        Cycle: CycleEngine,
        E1Gadget: PairingVar<Cycle::E1, <Cycle::E1 as PairingEngine>::Fq>,
        E2Gadget: PairingVar<Cycle::E2, <Cycle::E2 as PairingEngine>::Fq>,
        <Cycle::E2 as PairingEngine>::G1Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
        <Cycle::E2 as PairingEngine>::G2Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
{
    is_genesis: bool,
    prev_recursive_proof: Proof<Cycle::E2>,
    vk: VerifyingKey<Cycle::E2>,
    proof: SingleStepUpdateProof<SSAVD, HTParams>,
    ssavd_pp: SSAVD::PublicParameters,
    history_tree_pp: <HTParams::H as FixedLengthCRH>::Parameters,
    _ssavd_gadget: PhantomData<SSAVDGadget>,
    _hash_gadget: PhantomData<HGadget>,
    _e1_gadget: PhantomData<E1Gadget>,
    _e2_gadget: PhantomData<E2Gadget>,
    _cycle: PhantomData<Cycle>,
}

pub struct InnerSingleStepProofVerifierInput<HTParams: MerkleTreeParameters> {
    pub(crate) new_digest: <HTParams::H as FixedLengthCRH>::Output,
    pub(crate) new_epoch: u64,
}

impl<HTParams: MerkleTreeParameters> Clone for InnerSingleStepProofVerifierInput<HTParams> {
    fn clone(&self) -> Self {
        Self {
            new_digest: self.new_digest.clone(),
            new_epoch: self.new_epoch,
        }
    }
}

//TODO: Include hash of witness vk as public input (https://www.michaelstraka.com/posts/recursivesnarks/)
impl<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget> ConstraintSynthesizer<<Cycle::E2 as PairingEngine>::Fq>
for InnerSingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget>
where
    SSAVD: SingleStepAVD,
    SSAVDGadget: SingleStepAVDGadget<SSAVD, <Cycle::E2 as PairingEngine>::Fq>,
    HTParams: MerkleTreeParameters,
    HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, <Cycle::E1 as PairingEngine>::Fr>,
    Cycle: CycleEngine,
    E1Gadget: PairingVar<Cycle::E1, <Cycle::E1 as PairingEngine>::Fq>,
    E2Gadget: PairingVar<Cycle::E2, <Cycle::E2 as PairingEngine>::Fq>,
    <Cycle::E2 as PairingEngine>::G1Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
    <Cycle::E2 as PairingEngine>::G2Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
    <HTParams::H as FixedLengthCRH>::Output: ToConstraintField<<Cycle::E1 as PairingEngine>::Fr>,
    <HGadget as FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, <Cycle::E2 as PairingEngine>::Fq>>::OutputVar: ToConstraintFieldGadget<<Cycle::E2 as PairingEngine>::Fq>,
{
    #[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<<Cycle::E2 as PairingEngine>::Fq>,
    ) -> Result<(), SynthesisError> {
        // Allocate constants
        let ssavd_pp_time = start_timer!(|| "Generating SSAVD parameters");
        let ssavd_pp = SSAVDGadget::PublicParametersVar::new_constant(
            r1cs_core::ns!(cs, "ssavd_pp"),
            &self.ssavd_pp,
        )?;
        end_timer!(ssavd_pp_time);
        let ht_pp_time = start_timer!(|| "Generating history tree parameters");
        let history_tree_pp = HGadget::ParametersVar::new_constant(
            r1cs_core::ns!(cs, "history_tree_pp"),
            &self.history_tree_pp,
        )?;
        end_timer!(ht_pp_time);
        let genesis_digest_time = start_timer!(|| "Generating genesis digest");
        let genesis_digest_val = SingleStepAVDWithHistory::<SSAVD, HTParams>::new(
            &mut StepRng::new(1, 1),
            &self.ssavd_pp,
            &self.history_tree_pp,
        ).unwrap().digest().digest;
        let genesis_digest = HGadget::OutputVar::new_constant(
            r1cs_core::ns!(cs, "genesis_digest"),
            &genesis_digest_val,
        )?;
        end_timer!(genesis_digest_time);

        // Allocate public inputs
        let public_input_time = start_timer!(|| "Allocating public inputs");
        let new_digest_time = start_timer!(|| "Generating new digest");
        let new_digest = HGadget::OutputVar::new_input(
            r1cs_core::ns!(cs, "new_digest"),
            || Ok(if self.is_genesis { &genesis_digest_val } else {&self.proof.new_digest} ),
        )?;
        end_timer!(new_digest_time);
        let new_epoch_time = start_timer!(|| "Generating new epoch");
        let new_epoch = UInt64::new_input(
            r1cs_core::ns!(cs, "new_epoch"),
            || Ok(if self.is_genesis { 0 } else { self.proof.prev_epoch + 1 }),
        )?;
        end_timer!(new_epoch_time);
        end_timer!(public_input_time);

        // Allocate witness inputs
        let witness_input_time = start_timer!(|| "Allocating witness inputs");
        let time = start_timer!(|| "Generating prev digest");
        let prev_digest = HGadget::OutputVar::new_witness(
            r1cs_core::ns!(cs, "prev_digest"),
            || Ok(&self.proof.prev_digest),
        )?;
        end_timer!(time);
        let time = start_timer!(|| "Generating SSAVD update proof");
        let ssavd_proof = SSAVDGadget::UpdateProofVar::new_witness(
            r1cs_core::ns!(cs, "ssavd_proof"),
            || Ok(&self.proof.ssavd_proof),
        )?;
        end_timer!(time);
        let time = start_timer!(|| "Generating history tree update proof");
        let history_tree_proof = <MerkleTreePathVar<HTParams, HGadget, _>>::new_witness(
            r1cs_core::ns!(cs, "history_tree_proof"),
            || Ok(&self.proof.history_tree_proof),
        )?;
        end_timer!(time);
        let prev_ssavd_digest = SSAVDGadget::DigestVar::new_witness(
            r1cs_core::ns!(cs, "prev_ssavd_digest"),
            || Ok(&self.proof.prev_ssavd_digest),
        )?;
        let new_ssavd_digest = SSAVDGadget::DigestVar::new_witness(
            r1cs_core::ns!(cs, "new_ssavd_digest"),
            || Ok(&self.proof.new_ssavd_digest),
        )?;
        let prev_epoch = UInt64::new_witness(
            r1cs_core::ns!(cs, "prev_epoch"),
            || Ok(&self.proof.prev_epoch),
        )?;
        let prev_recursive_proof = ProofVar::<Cycle::E2, E2Gadget>::new_witness(
            cs.clone(),
            || Ok(&self.prev_recursive_proof),
        )?;
        let vk = VerifyingKeyVar::<Cycle::E2, E2Gadget>::new_witness(
            r1cs_core::ns!(cs, "vk"),
            || Ok(&self.vk),
        )?;
        end_timer!(witness_input_time);

        // Check if genesis digest
        let time = start_timer!(|| "Generating constraints to check single step update");
        let is_genesis = new_digest.is_eq(&genesis_digest)?;
        new_epoch.conditional_enforce_equal(&UInt64::constant(0), &is_genesis)?;

        // Else check update proof and perform recursive check on previous epoch
        new_epoch.conditional_enforce_equal(
            &UInt64::addmany(&[prev_epoch.clone(), UInt64::constant(1)])?,
            &is_genesis.not(),
        )?;
        let proof_gadget = SingleStepUpdateProofVar::<SSAVD, SSAVDGadget, HTParams, HGadget, _>{
            ssavd_proof,
            history_tree_proof,
            prev_ssavd_digest,
            new_ssavd_digest,
            prev_digest: prev_digest.clone(),
            new_digest,
            prev_epoch: prev_epoch.clone(),
        };
        proof_gadget.conditional_check_single_step_with_history_update(
            &ssavd_pp,
            &history_tree_pp,
            &is_genesis.not(),
        )?;
        end_timer!(time);

        let time = start_timer!(|| "Generating constraints to check recursive proof");
        let mut inner_proof_input_as_e1_fr: Vec<FpVar<<Cycle::E1 as PairingEngine>::Fr>> = Vec::new();
        inner_proof_input_as_e1_fr.extend_from_slice(&prev_digest.to_constraint_field()?);
        for b in prev_epoch.to_bits_le() {
            inner_proof_input_as_e1_fr.push(<FpVar<_>>::from(b.clone()));
        }
        let inner_proof_input_as_e1_fr_bytes = inner_proof_input_as_e1_fr.iter()
            .map(|e1_fr| e1_fr.to_bytes())
            .collect::<Result<Vec<Vec<UInt8<_>>>, SynthesisError>>()?
            .iter().flatten().cloned().collect::<Vec<UInt8<_>>>();
        // Expand out E1::Fr byte encoding to E1::Fq byte encoding
        let e1_fq_max_encoding_size_in_bytes = usize::try_from(<<<Cycle::E1 as PairingEngine>::Fq as PrimeField>::Params as FpParameters>::CAPACITY / 8).unwrap();
        let e1_fq_size_in_bytes = <<<Cycle::E1 as PairingEngine>::Fq as PrimeField>::BigInt as BigInteger>::NUM_LIMBS * 8;
        let inner_proof_input_as_e1_fq_bytes = inner_proof_input_as_e1_fr_bytes
            .chunks(e1_fq_max_encoding_size_in_bytes)
            .map(|e1_fr_encoding_chunk| {
                //TODO: Might be an issue with little vs big endian encoding here
                let mut e1_fq_repr = vec![UInt8::constant(0); e1_fq_size_in_bytes];
                e1_fq_repr.iter_mut().zip(e1_fr_encoding_chunk)
                    .for_each(|(fq_byte_repr, fr_byte_repr)| *fq_byte_repr = fr_byte_repr.clone());
                e1_fq_repr
            })
            .collect::<Vec<Vec<UInt8<_>>>>();

        let outer_proof_verifies = <Groth16VerifierGadget<Cycle::E2, E2Gadget> as NIZKVerifierGadget<
            Groth16<
                Cycle::E2,
                OuterCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget>,
                OuterVerifierInput<HTParams, Cycle>,
            >,
            <Cycle::E2 as PairingEngine>::Fq,
        >>::verify(&vk, &inner_proof_input_as_e1_fq_bytes, &prev_recursive_proof)?;
        outer_proof_verifies.conditional_enforce_equal(&Boolean::TRUE, &is_genesis.not())?;
        end_timer!(time);

        println!(">>>>Checking constraints after generating them");
        match cs.is_satisfied() {
            Ok(b) => {
                if !b {
                    println!("=========================================================");
                    println!("Unsatisfied constraints:");
                    println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
                    println!("=========================================================");
                }
                //assert!(cs.is_satisfied().unwrap());
                println!("Constraints satisfied: {}", cs.is_satisfied().unwrap());
            },
            Err(_) => println!("Constraint system not assigned"),
        }

        Ok(())
    }
}

impl<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget> InnerSingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, <Cycle::E2 as PairingEngine>::Fq>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, <Cycle::E2 as PairingEngine>::Fq>,
        Cycle: CycleEngine,
        E1Gadget: PairingVar<Cycle::E1, <Cycle::E1 as PairingEngine>::Fq>,
        E2Gadget: PairingVar<Cycle::E2, <Cycle::E2 as PairingEngine>::Fq>,
        <Cycle::E2 as PairingEngine>::G1Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
        <Cycle::E2 as PairingEngine>::G2Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
{
    pub fn blank(
        ssavd_pp: &SSAVD::PublicParameters,
        history_tree_pp: &<HTParams::H as FixedLengthCRH>::Parameters,
        vk: VerifyingKey<Cycle::E2>,
    ) -> Self {
        Self {
            is_genesis: Default::default(),
            prev_recursive_proof: Default::default(),
            vk: vk,
            proof: SingleStepUpdateProof::<SSAVD, HTParams>::default(),
            ssavd_pp: ssavd_pp.clone(),
            history_tree_pp: history_tree_pp.clone(),
            _ssavd_gadget: PhantomData ,
            _hash_gadget: PhantomData,
            _e1_gadget: PhantomData,
            _e2_gadget: PhantomData,
            _cycle: PhantomData,
        }
    }

    pub fn new(
        is_genesis: bool,
        ssavd_pp: &SSAVD::PublicParameters,
        history_tree_pp: &<HTParams::H as FixedLengthCRH>::Parameters,
        proof: SingleStepUpdateProof<SSAVD, HTParams>,
        vk: VerifyingKey<Cycle::E2>,
        prev_recursive_proof: Proof<Cycle::E2>,
    ) -> Self {
        Self {
            is_genesis,
            prev_recursive_proof,
            vk: vk,
            proof: proof,
            ssavd_pp: ssavd_pp.clone(),
            history_tree_pp: history_tree_pp.clone(),
            _ssavd_gadget: PhantomData ,
            _hash_gadget: PhantomData,
            _e1_gadget: PhantomData,
            _e2_gadget: PhantomData,
            _cycle: PhantomData,
        }
    }

}

impl <HTParams, ConstraintF> ToConstraintField<ConstraintF> for InnerSingleStepProofVerifierInput<HTParams>
where
HTParams: MerkleTreeParameters,
ConstraintF: PrimeField,
<HTParams::H as FixedLengthCRH>::Output: ToConstraintField<ConstraintF>,
{
    fn to_field_elements(&self) -> Result<Vec<ConstraintF>, Error> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.new_digest.to_field_elements()?);
        let mut tmp = self.new_epoch;
        for _ in 0..64 {
            v.push(<ConstraintF>::from((tmp & 1 == 1) as u8));
            tmp >>= 1;
        }
        println!("Public input length: {}", v.len());
        let a = v.iter().map(|f| rsa::bignat::f_to_nat(f)).collect::<Vec<rsa::bignat::BigNat>>();
        println!("Public inputs: {:?}", a);
        Ok(v)
    }
}

pub struct OuterCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, <Cycle::E2 as PairingEngine>::Fq>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, <Cycle::E2 as PairingEngine>::Fq>,
        Cycle: CycleEngine,
        E1Gadget: PairingVar<Cycle::E1, <Cycle::E1 as PairingEngine>::Fq>,
        E2Gadget: PairingVar<Cycle::E2, <Cycle::E2 as PairingEngine>::Fq>,
        <Cycle::E2 as PairingEngine>::G1Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
        <Cycle::E2 as PairingEngine>::G2Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
{
    prev_inner_proof_input: InnerSingleStepProofVerifierInput<HTParams>,
    prev_inner_proof: Proof<Cycle::E1>,
    vk: VerifyingKey<Cycle::E1>,
    _inner_proof: PhantomData<InnerSingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget>>,
}

pub struct OuterVerifierInput<HTParams: MerkleTreeParameters, Cycle: CycleEngine>
where
    <Cycle::E2 as PairingEngine>::G1Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
    <Cycle::E2 as PairingEngine>::G2Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
{
    pub(crate) prev_inner_proof_input: InnerSingleStepProofVerifierInput<HTParams>,
    _cycle: PhantomData<Cycle>,
}

impl<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget> ConstraintSynthesizer<<Cycle::E1 as PairingEngine>::Fq>
for OuterCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, <Cycle::E2 as PairingEngine>::Fq>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, <Cycle::E1 as PairingEngine>::Fr>,
        Cycle: CycleEngine,
        E1Gadget: PairingVar<Cycle::E1, <Cycle::E1 as PairingEngine>::Fq>,
        E2Gadget: PairingVar<Cycle::E2, <Cycle::E2 as PairingEngine>::Fq>,
        <Cycle::E2 as PairingEngine>::G1Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
        <Cycle::E2 as PairingEngine>::G2Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
        <HTParams::H as FixedLengthCRH>::Output: ToConstraintField<<Cycle::E1 as PairingEngine>::Fr>,
        <HGadget as FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, <Cycle::E2 as PairingEngine>::Fq>>::OutputVar: ToConstraintFieldGadget<<Cycle::E2 as PairingEngine>::Fq>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<<<Cycle as CycleEngine>::E1 as PairingEngine>::Fq>) -> Result<(), SynthesisError> {
        let inner_proof_input_as_e1_fr: Vec<<Cycle::E1 as PairingEngine>::Fr> = self.prev_inner_proof_input.to_field_elements().unwrap();
        let inner_proof_input_as_e1_fr_bytes = inner_proof_input_as_e1_fr.iter()
            .map(|e1_fr| {
                e1_fr
                    .into_repr()
                    .as_ref()
                    .iter()
                    .map(|e1_fr_int| e1_fr_int.to_le_bytes().to_vec())
                    .collect::<Vec<Vec<u8>>>()
            })
            .collect::<Vec<Vec<Vec<u8>>>>().iter()
            .flatten().flatten().cloned().collect::<Vec<u8>>();
        let inner_proof_input_as_e1_fr_bytes_var = UInt8::<<Cycle::E1 as PairingEngine>::Fq>::new_input_vec(
            r1cs_core::ns!(cs, "e1_fr_bytes"),
            &inner_proof_input_as_e1_fr_bytes,
        )?;
        let e1_fr_size_in_bytes = <<<Cycle::E1 as PairingEngine>::Fr as PrimeField>::BigInt as BigInteger>::NUM_LIMBS * 8;
        let inner_proof_input_repacked_as_e1_fr = inner_proof_input_as_e1_fr_bytes_var
            .chunks(e1_fr_size_in_bytes)
            .map(|e1_fr_chunk| e1_fr_chunk.to_vec())
            .collect::<Vec<Vec<UInt8<_>>>>();

        let vk = VerifyingKeyVar::<Cycle::E1, E1Gadget>::new_constant(
            r1cs_core::ns!(cs, "vk"),
            &self.vk,
        )?;
        let prev_inner_proof = ProofVar::<Cycle::E1, E1Gadget>::new_witness(
            r1cs_core::ns!(cs, "inner_proof"),
            || Ok(&self.prev_inner_proof),
        )?;

        <Groth16VerifierGadget<Cycle::E1, E1Gadget> as NIZKVerifierGadget<
            Groth16<
                Cycle::E1,
                InnerSingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget>,
                InnerSingleStepProofVerifierInput<HTParams>,
            >,
            <Cycle::E1 as PairingEngine>::Fq,
        >>::verify(&vk, &inner_proof_input_repacked_as_e1_fr, &prev_inner_proof)?
            .enforce_equal(&Boolean::TRUE)?;
        Ok(())
    }
}

impl<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget> OuterCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, <Cycle::E2 as PairingEngine>::Fq>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, <Cycle::E1 as PairingEngine>::Fr>,
        Cycle: CycleEngine,
        E1Gadget: PairingVar<Cycle::E1, <Cycle::E1 as PairingEngine>::Fq>,
        E2Gadget: PairingVar<Cycle::E2, <Cycle::E2 as PairingEngine>::Fq>,
        <Cycle::E2 as PairingEngine>::G1Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
        <Cycle::E2 as PairingEngine>::G2Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
        <HGadget as FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, <Cycle::E2 as PairingEngine>::Fq>>::OutputVar: ToConstraintFieldGadget<<Cycle::E2 as PairingEngine>::Fq>,
{
    pub fn blank(
        vk: VerifyingKey<Cycle::E1>,
    ) -> Self {
       Self {
           prev_inner_proof_input: InnerSingleStepProofVerifierInput {
               new_digest: Default::default(),
               new_epoch: Default::default(),
           },
           prev_inner_proof: Default::default(),
           vk: vk,
           _inner_proof: PhantomData,
       }
    }

    pub fn new(
        prev_inner_proof: Proof<Cycle::E1>,
        prev_inner_proof_input: InnerSingleStepProofVerifierInput<HTParams>,
        vk: VerifyingKey<Cycle::E1>,
    ) -> Self {
        Self {
            prev_inner_proof_input: prev_inner_proof_input,
            prev_inner_proof: prev_inner_proof,
            vk: vk,
            _inner_proof: PhantomData,
        }
    }
}

impl <HTParams, Cycle> ToConstraintField<<Cycle::E1 as PairingEngine>::Fq> for OuterVerifierInput<HTParams, Cycle>
    where
        HTParams: MerkleTreeParameters,
        Cycle: CycleEngine,
        <Cycle::E2 as PairingEngine>::G1Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
        <Cycle::E2 as PairingEngine>::G2Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
        <HTParams::H as FixedLengthCRH>::Output: ToConstraintField<<Cycle::E1 as PairingEngine>::Fr>,
{
    fn to_field_elements(&self) -> Result<Vec<<Cycle::E1 as PairingEngine>::Fq>, Error> {
        let inner_proof_input_as_e1_fr: Vec<<Cycle::E1 as PairingEngine>::Fr> = self.prev_inner_proof_input.to_field_elements()?;
        let inner_proof_input_as_e1_fr_bytes = inner_proof_input_as_e1_fr.iter()
            .map(|e1_fr| {
                e1_fr.into_repr().as_ref().iter()
                    .map(|e1_fr_int| e1_fr_int.to_le_bytes().to_vec())
                    .collect::<Vec<Vec<u8>>>()
            })
            .collect::<Vec<Vec<Vec<u8>>>>()
            .iter().flatten().flatten().cloned().collect::<Vec<u8>>();
        inner_proof_input_as_e1_fr_bytes.to_field_elements()
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use algebra::{
        ed_on_mnt4_298::{EdwardsProjective, Fq},
        mnt4_298::{MNT4_298, Fq as MNT4Fq},
        mnt6_298::{MNT6_298, Fq as MNT6Fq},
        curves::{AffineCurve},
    };
    use r1cs_core::{ConstraintSystem, ConstraintLayer};
    use r1cs_std::{
        ed_on_mnt4_298::EdwardsVar,
        mnt4_298::PairingVar as MNT4PairingVar,
        mnt6_298::PairingVar as MNT6PairingVar,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use zexe_cp::{
        crh::pedersen::{constraints::CRHGadget, CRH, Window},
        nizk::{groth16::Groth16, NIZK},
    };
    use tracing_subscriber::layer::SubscriberExt;

    use single_step_avd::{
        merkle_tree_avd::{
            MerkleTreeAVDParameters,
            MerkleTreeAVD,
            constraints::MerkleTreeAVDGadget,
        },
        rsa_avd::{RsaAVD, constraints::RsaAVDGadget},
    };
    use crypto_primitives::sparse_merkle_tree::MerkleDepth;
    use crate::{
        history_tree::SingleStepAVDWithHistory,
    };
    use rsa::{
        bignat::constraints::BigNatCircuitParams,
        kvac::RsaKVACParams,
        poker::{PoKERParams},
        hog::{RsaGroupParams},
        hash::{
            HasherFromDigest, PoseidonHasher, constraints::PoseidonHasherGadget,
        },
    };

    use std::time::Instant;

    #[derive(Clone, Copy, Debug)]
    pub struct MNT298Cycle;

    impl CycleEngine for MNT298Cycle {
        type E1 = MNT4_298;
        type E2 = MNT6_298;
    }

    #[derive(Clone)]
    pub struct Window4x256;

    impl Window for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type H = CRH<EdwardsProjective, Window4x256>;
    type HG = CRHGadget<EdwardsProjective, EdwardsVar, Window4x256>;

    #[derive(Clone)]
    pub struct MerkleTreeTestParameters;

    impl MerkleTreeParameters for MerkleTreeTestParameters {
        const DEPTH: MerkleDepth = 4;
        type H = H;
    }

    #[derive(Clone)]
    pub struct MerkleTreeAVDTestParameters;

    impl MerkleTreeAVDParameters for MerkleTreeAVDTestParameters {
        const MAX_UPDATE_BATCH_SIZE: u64 = 3;
        const MAX_OPEN_ADDRESSING_PROBES: u8 = 2;
        type MerkleTreeParameters = MerkleTreeTestParameters;
    }

    type TestMerkleTreeAVD = MerkleTreeAVD<MerkleTreeAVDTestParameters>;
    type TestMerkleTreeAVDGadget = MerkleTreeAVDGadget<MerkleTreeAVDTestParameters, HG, Fq>;
    type TestAVDWithHistory = SingleStepAVDWithHistory<TestMerkleTreeAVD, MerkleTreeTestParameters>;

    type TestInnerCircuit = InnerSingleStepProofCircuit<TestMerkleTreeAVD, TestMerkleTreeAVDGadget, MerkleTreeTestParameters, HG, MNT298Cycle, MNT4PairingVar, MNT6PairingVar>;
    type TestInnerVerifierInput = InnerSingleStepProofVerifierInput<MerkleTreeTestParameters>;

    type TestOuterCircuit = OuterCircuit<TestMerkleTreeAVD, TestMerkleTreeAVDGadget, MerkleTreeTestParameters, HG, MNT298Cycle, MNT4PairingVar, MNT6PairingVar>;
    type TestOuterVerifierInput = OuterVerifierInput<MerkleTreeTestParameters, MNT298Cycle>;


    // Parameters for RSA AVD
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestRsa64Params;
    impl RsaGroupParams for TestRsa64Params {
        const RAW_G: usize = 2;
        const RAW_M: &'static str = "17839761582542106619";
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct BigNatTestParams;
    impl BigNatCircuitParams for BigNatTestParams {
        const LIMB_WIDTH: usize = 32;
        const N_LIMBS: usize = 2;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestPokerParams;
    impl PoKERParams for TestPokerParams {
        const HASH_TO_PRIME_ENTROPY: usize = 32;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestKVACParams;
    impl RsaKVACParams for TestKVACParams {
        const KEY_LEN: usize = 64;
        const VALUE_LEN: usize = 64;
        const PRIME_LEN: usize = 72;
        type RsaGroupParams = TestRsa64Params;
        type PoKERParams = TestPokerParams;
    }

    pub type PoseidonH = PoseidonHasher<Fq>;
    pub type PoseidonHG = PoseidonHasherGadget<Fq>;

    pub type TestRsaAVD = RsaAVD<
        TestKVACParams,
        HasherFromDigest<Fq, blake3::Hasher>,
        PoseidonH,
        BigNatTestParams,
    >;
    pub type TestRsaAVDGadget = RsaAVDGadget<
        Fq,
        TestKVACParams,
        HasherFromDigest<Fq, blake3::Hasher>,
        PoseidonH,
        PoseidonHG,
        BigNatTestParams,
    >;
    type TestRsaAVDWithHistory = SingleStepAVDWithHistory<TestRsaAVD, MerkleTreeTestParameters>;

    type TestRsaInnerCircuit = InnerSingleStepProofCircuit<TestRsaAVD, TestRsaAVDGadget, MerkleTreeTestParameters, HG, MNT298Cycle, MNT4PairingVar, MNT6PairingVar>;
    type TestRsaOuterCircuit = OuterCircuit<TestRsaAVD, TestRsaAVDGadget, MerkleTreeTestParameters, HG, MNT298Cycle, MNT4PairingVar, MNT6PairingVar>;

    #[test]
    #[ignore] // Expensive test, run with ``cargo test mt_update_and_verify_inner_circuit_test --release -- --ignored --nocapture``
    fn mt_update_and_verify_inner_circuit_test() {
        println!("Test with tree height: {}, and number of updates: {}...",
                 MerkleTreeTestParameters::DEPTH,
                 MerkleTreeAVDTestParameters::MAX_UPDATE_BATCH_SIZE,
        );
        let mut rng = StdRng::seed_from_u64(0_u64);
        let (ssavd_pp, crh_pp) = TestAVDWithHistory::setup(&mut rng).unwrap();
        let mut avd = TestAVDWithHistory::new(&mut rng, &ssavd_pp, &crh_pp).unwrap();

        // Setup inner proof circuit
        println!("Setting up inner proof...");
        let start = Instant::now();
        let inner_blank_circuit = TestInnerCircuit::blank(
            &ssavd_pp,
            &crh_pp,
            VerifyingKey {
                alpha_g1: Default::default(),
                beta_g2: Default::default(),
                gamma_g2: Default::default(),
                delta_g2: Default::default(),
                gamma_abc_g1: vec![Default::default(); 73] // 8 for digest, 64 for epoch
            },
        );
        let inner_parameters =
            Groth16::<MNT4_298, TestInnerCircuit, TestInnerVerifierInput>::setup(inner_blank_circuit, &mut rng).unwrap();
        println!("Inner preparedVK len: {}", inner_parameters.1.gamma_abc_g1.len());
        let bench = start.elapsed().as_secs();
        println!("\t setup time: {} s", bench);

        // Setup outer proof circuit
        println!("Setting up outer proof...");
        let start = Instant::now();
        let outer_blank_circuit = TestOuterCircuit::blank(
            inner_parameters.0.vk.clone(),
        );
        let outer_parameters =
            Groth16::<MNT6_298, TestOuterCircuit, TestOuterVerifierInput>::setup(outer_blank_circuit, &mut rng).unwrap();
        println!("Outer preparedVK len: {}", outer_parameters.1.gamma_abc_g1.len());
        let bench = start.elapsed().as_secs();
        println!("\t setup time: {} s", bench);


        // Construct genesis proof
        let genesis_digest = avd.digest().digest;
        let verifier_input_genesis = TestInnerVerifierInput{
            new_digest: genesis_digest.clone(),
            new_epoch: 0,
        };

        println!("Generating inner proof for genesis epoch...");
        let start = Instant::now();
        let g = <MNT6_298 as PairingEngine>::G1Affine::prime_subgroup_generator();
        let g2 = <MNT6_298 as PairingEngine>::G2Affine::prime_subgroup_generator();
        let inner_genesis_proof = Groth16::<MNT4_298, TestInnerCircuit, TestInnerVerifierInput>::prove(
            &inner_parameters.0,
            TestInnerCircuit::new(
                true,
                &ssavd_pp,
                &crh_pp,
                Default::default(),
                outer_parameters.0.vk.clone(),
                Proof {
                    a: g.clone(),
                    b: g2,
                    c: g.clone(),
                },
            ),
            &mut rng,
        ).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t proving time: {} s", bench);

        // Verify inner proof for genesis epoch
        let result = Groth16::<MNT4_298, TestInnerCircuit, TestInnerVerifierInput>::verify(
            &inner_parameters.1,
            &verifier_input_genesis,
            &inner_genesis_proof,
        ).unwrap();
        assert!(result);
        let result2 = Groth16::<MNT4_298, TestInnerCircuit, TestInnerVerifierInput>::verify(
            &inner_parameters.1,
            &TestInnerVerifierInput{new_digest: genesis_digest.clone(), new_epoch: 1 },
            &inner_genesis_proof,
        ).unwrap();
        assert!(!result2);

        // Construct outer genesis proof
        println!("Generating outer genesis proof...");
        let start = Instant::now();
        let outer_genesis_proof = Groth16::<MNT6_298, TestOuterCircuit, TestOuterVerifierInput>::prove(
            &outer_parameters.0,
            TestOuterCircuit::new(
                inner_genesis_proof.clone(),
                verifier_input_genesis.clone(),
                inner_parameters.0.vk.clone(),
            ),
            &mut rng,
        ).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t proving time: {} s", bench);

        // Verify outer genesis proof
        let outer_genesis_verifier_input = TestOuterVerifierInput{
            prev_inner_proof_input: verifier_input_genesis.clone(),
            _cycle: PhantomData,
        };
        let result = Groth16::<MNT6_298, TestOuterCircuit, TestOuterVerifierInput>::verify(
            &outer_parameters.1,
            &outer_genesis_verifier_input,
            &outer_genesis_proof,
        ).unwrap();
        assert!(result);
        let result2 = Groth16::<MNT6_298, TestOuterCircuit, TestOuterVerifierInput>::verify(
            &outer_parameters.1,
            &TestOuterVerifierInput{
                prev_inner_proof_input: TestInnerVerifierInput{ new_digest: Default::default(), new_epoch: 0 },
                _cycle: PhantomData,
           },
            &outer_genesis_proof,
        ).unwrap();
        assert!(!result2);

        // Update AVD
        let proof = avd.batch_update(
            &vec![
                ([1_u8; 32], [2_u8; 32]),
                ([11_u8; 32], [12_u8; 32]),
                ([21_u8; 32], [22_u8; 32]),
            ]).unwrap();


        // Generate inner proof for new update
        let verifier_input_epoch_1 = TestInnerVerifierInput{
            new_digest: proof.new_digest.clone(),
            new_epoch: 1,
        };
        println!("Generating inner proof for epoch 1...");
        let start = Instant::now();
        let inner_epoch_1_proof = Groth16::<MNT4_298, TestInnerCircuit, TestInnerVerifierInput>::prove(
            &inner_parameters.0,
            TestInnerCircuit::new(
                false,
                &ssavd_pp,
                &crh_pp,
                proof,
                outer_parameters.0.vk.clone(),
                outer_genesis_proof.clone(),
            ),
            &mut rng,
        ).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t proving time: {} s", bench);

        // Verify inner proof for epoch 1
        let result = Groth16::<MNT4_298, TestInnerCircuit, TestInnerVerifierInput>::verify(
            &inner_parameters.1,
            &verifier_input_epoch_1,
            &inner_epoch_1_proof,
        ).unwrap();
        assert!(result);
        let result2 = Groth16::<MNT4_298, TestInnerCircuit, TestInnerVerifierInput>::verify(
            &inner_parameters.1,
            &TestInnerVerifierInput{new_digest: Default::default(), new_epoch: 1 },
            &inner_epoch_1_proof,
        ).unwrap();
        assert!(!result2);
        let result3 = Groth16::<MNT4_298, TestInnerCircuit, TestInnerVerifierInput>::verify(
            &inner_parameters.1,
            &TestInnerVerifierInput{new_digest: verifier_input_epoch_1.new_digest.clone(), new_epoch: 0 },
            &inner_epoch_1_proof,
        ).unwrap();
        assert!(!result3);


        // Construct outer proof for epoch 1
        println!("Generating outer proof for epoch 1...");
        let start = Instant::now();
        let outer_epoch_1_proof = Groth16::<MNT6_298, TestOuterCircuit, TestOuterVerifierInput>::prove(
            &outer_parameters.0,
            TestOuterCircuit::new(
                inner_epoch_1_proof.clone(),
                verifier_input_epoch_1.clone(),
                inner_parameters.0.vk.clone(),
            ),
            &mut rng,
        ).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t proving time: {} s", bench);

        // Verify outer proof for epoch 1
        let outer_epoch_1_verifier_input = TestOuterVerifierInput{
            prev_inner_proof_input: verifier_input_epoch_1.clone(),
            _cycle: PhantomData,
        };
        let result = Groth16::<MNT6_298, TestOuterCircuit, TestOuterVerifierInput>::verify(
            &outer_parameters.1,
            &outer_epoch_1_verifier_input,
            &outer_epoch_1_proof,
        ).unwrap();
        assert!(result);


        // Update AVD
        let proof = avd.batch_update(
            &vec![
                ([1_u8; 32], [3_u8; 32]),
                ([11_u8; 32], [13_u8; 32]),
                ([21_u8; 32], [23_u8; 32]),
            ]).unwrap();


        // Generate inner proof for new update
        let verifier_input_epoch_2 = TestInnerVerifierInput{
            new_digest: proof.new_digest.clone(),
            new_epoch: 2,
        };
        println!("Generating inner proof for epoch 2...");
        let start = Instant::now();
        let inner_epoch_2_proof = Groth16::<MNT4_298, TestInnerCircuit, TestInnerVerifierInput>::prove(
            &inner_parameters.0,
            TestInnerCircuit::new(
                false,
                &ssavd_pp,
                &crh_pp,
                proof,
                outer_parameters.0.vk.clone(),
                outer_epoch_1_proof.clone(),
            ),
            &mut rng,
        ).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t proving time: {} s", bench);

        // Verify inner proof for epoch 2
        let result = Groth16::<MNT4_298, TestInnerCircuit, TestInnerVerifierInput>::verify(
            &inner_parameters.1,
            &verifier_input_epoch_2,
            &inner_epoch_2_proof,
        ).unwrap();
        assert!(result);

        // Count constraints
        let blank_circuit_constraint_counter = TestInnerCircuit::blank(
            &ssavd_pp,
            &crh_pp,
            outer_parameters.0.vk.clone(),
        );
        let cs = ConstraintSystem::<Fq>::new_ref();
        blank_circuit_constraint_counter.generate_constraints(cs.clone()).unwrap();
        println!("\t number of constraints for inner circuit: {}", cs.num_constraints());
        let blank_circuit_constraint_counter = TestOuterCircuit::blank(inner_parameters.0.vk.clone());
        let cs = ConstraintSystem::<MNT4Fq>::new_ref();
        blank_circuit_constraint_counter.generate_constraints(cs.clone()).unwrap();
        println!("\t number of constraints for outer circuit: {}", cs.num_constraints());
    }


    #[test]
    #[ignore] // Expensive test, run with ``cargo test rsa_update_and_verify_inner_circuit_test --release -- --ignored --nocapture``
    fn rsa_update_and_verify_inner_circuit_test() {
        fn u8_to_array(n: u8) -> [u8; 32] {
            let mut arr = [0_u8; 32];
            arr[31] = n;
            arr
        }
        let mut rng = StdRng::seed_from_u64(0_u64);
        let (ssavd_pp, crh_pp) = TestRsaAVDWithHistory::setup(&mut rng).unwrap();
        let mut avd = TestRsaAVDWithHistory::new(&mut rng, &ssavd_pp, &crh_pp).unwrap();

        // Setup inner proof circuit
        println!("Setting up inner proof...");
        let start = Instant::now();
        let inner_blank_circuit = TestRsaInnerCircuit::blank(
            &ssavd_pp,
            &crh_pp,
            VerifyingKey {
                alpha_g1: Default::default(),
                beta_g2: Default::default(),
                gamma_g2: Default::default(),
                delta_g2: Default::default(),
                gamma_abc_g1: vec![Default::default(); 73] // 8 for digest, 64 for epoch
            },
        );
        let inner_parameters =
            Groth16::<MNT4_298, TestRsaInnerCircuit, TestInnerVerifierInput>::setup(inner_blank_circuit, &mut rng).unwrap();
        println!("Inner preparedVK len: {}", inner_parameters.1.gamma_abc_g1.len());
        let bench = start.elapsed().as_secs();
        println!("\t setup time: {} s", bench);

        // Setup outer proof circuit
        println!("Setting up outer proof...");
        let start = Instant::now();
        let outer_blank_circuit = TestRsaOuterCircuit::blank(
            inner_parameters.0.vk.clone(),
        );
        let outer_parameters =
            Groth16::<MNT6_298, TestRsaOuterCircuit, TestOuterVerifierInput>::setup(outer_blank_circuit, &mut rng).unwrap();
        println!("Outer preparedVK len: {}", outer_parameters.1.gamma_abc_g1.len());
        let bench = start.elapsed().as_secs();
        println!("\t setup time: {} s", bench);


        // Construct genesis proof
        let genesis_digest = avd.digest().digest;
        println!("Genesis digest in test: {:?}", &genesis_digest);
        let verifier_input_genesis = TestInnerVerifierInput{
            new_digest: genesis_digest.clone(),
            new_epoch: 0,
        };

        println!("Generating inner proof for genesis epoch...");


        let mut layer = ConstraintLayer::default();
        layer.mode = r1cs_core::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let cs = ConstraintSystem::<MNT6Fq>::new_ref();
            let g = <MNT6_298 as PairingEngine>::G1Affine::prime_subgroup_generator();
            let g2 = <MNT6_298 as PairingEngine>::G2Affine::prime_subgroup_generator();
            TestRsaInnerCircuit::new(
                true,
                &ssavd_pp,
                &crh_pp,
                Default::default(),
                outer_parameters.0.vk.clone(),
                Proof {
                    a: g.clone(),
                    b: g2,
                    c: g.clone(),
                },
            ).generate_constraints(cs.clone()).unwrap();
            println!(">>>>Constraint check before proving");
            if !cs.is_satisfied().unwrap() {
                println!("=========================================================");
                println!("Unsatisfied constraints:");
                println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
                println!("=========================================================");
            }
            assert!(cs.is_satisfied().unwrap());
        });


        let start = Instant::now();
        let g = <MNT6_298 as PairingEngine>::G1Affine::prime_subgroup_generator();
        let g2 = <MNT6_298 as PairingEngine>::G2Affine::prime_subgroup_generator();
        let inner_genesis_proof = Groth16::<MNT4_298, TestRsaInnerCircuit, TestInnerVerifierInput>::prove(
            &inner_parameters.0,
            TestRsaInnerCircuit::new(
                true,
                &ssavd_pp,
                &crh_pp,
                Default::default(),
                outer_parameters.0.vk.clone(),
                Proof {
                    a: g.clone(),
                    b: g2,
                    c: g.clone(),
                },
            ),
            &mut rng,
        ).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t proving time: {} s", bench);

        // Verify inner proof for genesis epoch
        let result = Groth16::<MNT4_298, TestRsaInnerCircuit, TestInnerVerifierInput>::verify(
            &inner_parameters.1,
            &verifier_input_genesis,
            &inner_genesis_proof,
        ).unwrap();
        assert!(result);
        println!("Verification of inner genesis proof: {}", result);
        let result2 = Groth16::<MNT4_298, TestRsaInnerCircuit, TestInnerVerifierInput>::verify(
            &inner_parameters.1,
            &TestInnerVerifierInput{new_digest: genesis_digest.clone(), new_epoch: 1 },
            &inner_genesis_proof,
        ).unwrap();
        assert!(!result2);

        // Construct outer genesis proof
        println!("Generating outer genesis proof...");
        let start = Instant::now();
        let outer_genesis_proof = Groth16::<MNT6_298, TestRsaOuterCircuit, TestOuterVerifierInput>::prove(
            &outer_parameters.0,
            TestRsaOuterCircuit::new(
                inner_genesis_proof.clone(),
                verifier_input_genesis.clone(),
                inner_parameters.0.vk.clone(),
            ),
            &mut rng,
        ).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t proving time: {} s", bench);

        // Verify outer genesis proof
        let outer_genesis_verifier_input = TestOuterVerifierInput{
            prev_inner_proof_input: verifier_input_genesis.clone(),
            _cycle: PhantomData,
        };
        let result = Groth16::<MNT6_298, TestRsaOuterCircuit, TestOuterVerifierInput>::verify(
            &outer_parameters.1,
            &outer_genesis_verifier_input,
            &outer_genesis_proof,
        ).unwrap();
        //assert!(result);
        println!("Verification of outer genesis proof: {}", result);
        let result2 = Groth16::<MNT6_298, TestRsaOuterCircuit, TestOuterVerifierInput>::verify(
            &outer_parameters.1,
            &TestOuterVerifierInput{
                prev_inner_proof_input: TestInnerVerifierInput{ new_digest: Default::default(), new_epoch: 0 },
                _cycle: PhantomData,
            },
            &outer_genesis_proof,
        ).unwrap();
        assert!(!result2);

        // Update AVD
        let proof = avd.batch_update(
            &vec![
                (u8_to_array(1), u8_to_array(2)),
                (u8_to_array(11), u8_to_array(12)),
                (u8_to_array(21), u8_to_array(22)),
            ]).unwrap();


        // Generate inner proof for new update
        let verifier_input_epoch_1 = TestInnerVerifierInput{
            new_digest: proof.new_digest.clone(),
            new_epoch: 1,
        };
        println!("Generating inner proof for epoch 1...");
        let start = Instant::now();
        let inner_epoch_1_proof = Groth16::<MNT4_298, TestRsaInnerCircuit, TestInnerVerifierInput>::prove(
            &inner_parameters.0,
            TestRsaInnerCircuit::new(
                false,
                &ssavd_pp,
                &crh_pp,
                proof,
                outer_parameters.0.vk.clone(),
                outer_genesis_proof.clone(),
            ),
            &mut rng,
        ).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t proving time: {} s", bench);

        // Verify inner proof for epoch 1
        let result = Groth16::<MNT4_298, TestRsaInnerCircuit, TestInnerVerifierInput>::verify(
            &inner_parameters.1,
            &verifier_input_epoch_1,
            &inner_epoch_1_proof,
        ).unwrap();
        //assert!(result);
        println!("Verification of inner epoch 1 proof: {}", result);
        let result2 = Groth16::<MNT4_298, TestRsaInnerCircuit, TestInnerVerifierInput>::verify(
            &inner_parameters.1,
            &TestInnerVerifierInput{new_digest: Default::default(), new_epoch: 1 },
            &inner_epoch_1_proof,
        ).unwrap();
        assert!(!result2);
        let result3 = Groth16::<MNT4_298, TestRsaInnerCircuit, TestInnerVerifierInput>::verify(
            &inner_parameters.1,
            &TestInnerVerifierInput{new_digest: verifier_input_epoch_1.new_digest.clone(), new_epoch: 0 },
            &inner_epoch_1_proof,
        ).unwrap();
        assert!(!result3);


        // Construct outer proof for epoch 1
        println!("Generating outer proof for epoch 1...");
        let start = Instant::now();
        let outer_epoch_1_proof = Groth16::<MNT6_298, TestRsaOuterCircuit, TestOuterVerifierInput>::prove(
            &outer_parameters.0,
            TestRsaOuterCircuit::new(
                inner_epoch_1_proof.clone(),
                verifier_input_epoch_1.clone(),
                inner_parameters.0.vk.clone(),
            ),
            &mut rng,
        ).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t proving time: {} s", bench);

        // Verify outer proof for epoch 1
        let outer_epoch_1_verifier_input = TestOuterVerifierInput{
            prev_inner_proof_input: verifier_input_epoch_1.clone(),
            _cycle: PhantomData,
        };
        let result = Groth16::<MNT6_298, TestRsaOuterCircuit, TestOuterVerifierInput>::verify(
            &outer_parameters.1,
            &outer_epoch_1_verifier_input,
            &outer_epoch_1_proof,
        ).unwrap();
        //assert!(result);
        println!("Verification of outer epoch 1 proof: {}", result);


        // Update AVD
        let proof = avd.batch_update(
            &vec![
                (u8_to_array(1), u8_to_array(3)),
                (u8_to_array(11), u8_to_array(13)),
                (u8_to_array(21), u8_to_array(23)),
            ]).unwrap();


        // Generate inner proof for new update
        let verifier_input_epoch_2 = TestInnerVerifierInput{
            new_digest: proof.new_digest.clone(),
            new_epoch: 2,
        };
        println!("Generating inner proof for epoch 2...");
        let start = Instant::now();
        let inner_epoch_2_proof = Groth16::<MNT4_298, TestRsaInnerCircuit, TestInnerVerifierInput>::prove(
            &inner_parameters.0,
            TestRsaInnerCircuit::new(
                false,
                &ssavd_pp,
                &crh_pp,
                proof,
                outer_parameters.0.vk.clone(),
                outer_epoch_1_proof.clone(),
            ),
            &mut rng,
        ).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t proving time: {} s", bench);

        // Verify inner proof for epoch 2
        let result = Groth16::<MNT4_298, TestRsaInnerCircuit, TestInnerVerifierInput>::verify(
            &inner_parameters.1,
            &verifier_input_epoch_2,
            &inner_epoch_2_proof,
        ).unwrap();
        //assert!(result);
        println!("Verification of inner epoch 2 proof: {}", result);

        // Count constraints
        let blank_circuit_constraint_counter = TestRsaInnerCircuit::blank(
            &ssavd_pp,
            &crh_pp,
            outer_parameters.0.vk.clone(),
        );
        let cs = ConstraintSystem::<Fq>::new_ref();
        blank_circuit_constraint_counter.generate_constraints(cs.clone()).unwrap();
        println!("\t number of constraints for inner circuit: {}", cs.num_constraints());
        let blank_circuit_constraint_counter = TestRsaOuterCircuit::blank(inner_parameters.0.vk.clone());
        let cs = ConstraintSystem::<MNT4Fq>::new_ref();
        blank_circuit_constraint_counter.generate_constraints(cs.clone()).unwrap();
        println!("\t number of constraints for outer circuit: {}", cs.num_constraints());
    }


}
