use algebra::{
    curves::{AffineCurve, PairingEngine},
    fields::Field,
    groups::Group,
    to_bytes,
};
use groth16::{VerifyingKey};
use ff_fft::polynomial::DensePolynomial as UnivariatePolynomial;

use std::ops::AddAssign;

use rand::Rng;
use num_traits::identities::{One, Zero};

use dh_commitments::{
    afgho16::{AFGHOCommitmentG1, AFGHOCommitmentG2},
    identity::{HomomorphicPlaceholderValue, IdentityCommitment, IdentityOutput},
};
use inner_products::{
    ExtensionFieldElement, InnerProduct, MultiexponentiationInnerProduct, PairingInnerProduct,
    ScalarInnerProduct,
};
use ip_proofs::{
    tipa::{
        structured_scalar_message::{structured_scalar_power, TIPAWithSSM, TIPAWithSSMProof},
        TIPAProof, VerifierSRS, SRS, TIPA,
    },
};

use super::*;
use crate::{
    Error,
    history_tree::hash_to_final_digest,
};

type PairingInnerProductAB<P, D> = TIPA<
    PairingInnerProduct<P>,
    AFGHOCommitmentG1<P>,
    AFGHOCommitmentG2<P>,
    IdentityCommitment<ExtensionFieldElement<P>, <P as PairingEngine>::Fr>,
    P,
    D,
>;

type PairingInnerProductABProof<P, D> = TIPAProof<
    PairingInnerProduct<P>,
    AFGHOCommitmentG1<P>,
    AFGHOCommitmentG2<P>,
    IdentityCommitment<ExtensionFieldElement<P>, <P as PairingEngine>::Fr>,
    P,
    D,
>;

type MultiExpInnerProductC<P, D> = TIPAWithSSM<
    MultiexponentiationInnerProduct<<P as PairingEngine>::G1Projective>,
    AFGHOCommitmentG1<P>,
    IdentityCommitment<<P as PairingEngine>::G1Projective, <P as PairingEngine>::Fr>,
    P,
    D,
>;

type MultiExpInnerProductCProof<P, D> = TIPAWithSSMProof<
    MultiexponentiationInnerProduct<<P as PairingEngine>::G1Projective>,
    AFGHOCommitmentG1<P>,
    IdentityCommitment<<P as PairingEngine>::G1Projective, <P as PairingEngine>::Fr>,
    P,
    D,
>;

// Simple implementation of KZG polynomial commitment scheme
pub struct KZG<P: PairingEngine> {
    _pairing: PhantomData<P>,
}

impl<P: PairingEngine> KZG<P> {
    pub fn commit(
        powers: &[P::G1Projective],
        coeffs: &[P::Fr],
    ) -> Result<P::G1Projective, Error> {
        assert!(powers.len() == coeffs.len());
        MultiexponentiationInnerProduct::<<P as PairingEngine>::G1Projective>::inner_product(
            powers,
            &coeffs,
        )
    }

    pub fn open(
        powers: &[P::G1Projective],
        coeffs: &[P::Fr],
        point: &P::Fr,
    ) -> Result<P::G1Projective, Error> {
        assert!(powers.len() == coeffs.len());
        let polynomial = UnivariatePolynomial::from_coefficients_slice(coeffs);

        // Trick to calculate (p(x) - p(z)) / (x - z) as p(x) / (x - z) ignoring remainder p(z)
        let quotient_polynomial = &polynomial
            / &UnivariatePolynomial::from_coefficients_vec(vec![-point.clone(), P::Fr::one()]);
        let mut quotient_coeffs = quotient_polynomial.coeffs.to_vec();
        quotient_coeffs.resize(powers.len(), <P::Fr>::zero());
        MultiexponentiationInnerProduct::<<P as PairingEngine>::G1Projective>::inner_product(
            powers,
            &quotient_coeffs,
        )
    }

    pub fn verify(
        v_srs: &VerifierSRS<P>,
        com: &P::G1Projective,
        point: &P::Fr,
        eval: &P::Fr,
        proof: &P::G1Projective,
    ) -> Result<bool, Error> {
        Ok(P::pairing(
            com.clone() - &<P::G1Projective as Group>::mul(&v_srs.g, eval),
            v_srs.h.clone(),
        ) == P::pairing(
            proof.clone(),
            v_srs.h_alpha.clone() - &<P::G2Projective as Group>::mul(&v_srs.h, point),
        ))
    }
}


pub struct AggregateDigestProof<SSAVD, HTParams, P, FastH>
    where
        SSAVD: SingleStepAVD,
        HTParams: MerkleTreeParameters,
        P: PairingEngine,
        FastH: HashDigest,
{
    com_a: ExtensionFieldElement<P>,
    com_b: ExtensionFieldElement<P>,
    com_c: ExtensionFieldElement<P>,
    com_d: Vec<P::G1Projective>,
    ip_ab: ExtensionFieldElement<P>,
    agg_c: P::G1Projective,
    agg_d: Vec<P::Fr>,
    tipa_proof_ab: PairingInnerProductABProof<P, FastH>,
    tipa_proof_c: MultiExpInnerProductCProof<P, FastH>,
    tipa_proof_d: Vec<P::G1Projective>,
    pub trailing_digest: <<HTParams as MerkleTreeParameters>::H as FixedLengthCRH>::Output,
    pub trailing_digest_opening: (u64, SSAVD::Digest, <HTParams::H as FixedLengthCRH>::Output),
}


impl<SSAVD, HTParams, P, FastH> Clone for AggregateDigestProof<SSAVD, HTParams, P, FastH>
    where
        SSAVD: SingleStepAVD,
        HTParams: MerkleTreeParameters,
        P: PairingEngine,
        FastH: HashDigest,
{
    fn clone(&self) -> Self {
        Self {
            com_a: self.com_a.clone(),
            com_b: self.com_b.clone(),
            com_c: self.com_c.clone(),
            com_d: self.com_d.clone(),
            ip_ab: self.ip_ab.clone(),
            agg_c: self.agg_c.clone(),
            agg_d: self.agg_d.clone(),
            tipa_proof_ab: self.tipa_proof_ab.clone(),
            tipa_proof_c: self.tipa_proof_c.clone(),
            tipa_proof_d: self.tipa_proof_d.clone(),
            trailing_digest: self.trailing_digest.clone(),
            trailing_digest_opening: self.trailing_digest_opening.clone(),
        }
    }
}

impl<Params, SSAVD, SSAVDGadget, HTParams, HGadget, Pairing, FastH>
AggregatedFullHistoryAVD<Params, SSAVD, SSAVDGadget, HTParams, HGadget, Pairing, FastH>
    where
        Params: AggregatedFullHistoryAVDParameters,
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, Pairing::Fr>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, Pairing::Fr>,
        Pairing: PairingEngine,
        FastH: HashDigest,
        <HTParams::H as FixedLengthCRH>::Output: ToConstraintField<Pairing::Fr>,
{
    pub(crate) fn setup_inner_product<R: Rng>(rng: &mut R, size: usize) -> Result<SRS<Pairing>, Error>
    {
        let (srs, _) = PairingInnerProductAB::<Pairing, FastH>::setup(rng, size)?;
        Ok(srs)
    }

    //TODO: Make stateless instead of dependent on `self` - easier for benchmarking
    pub(crate) fn aggregate_proofs(
        &self,
        start_i: usize,
        end_i: usize,
    ) -> Result<AggregateDigestProof<SSAVD, HTParams, Pairing, FastH>, Error> {
        let size = end_i - start_i;
        assert!(size.is_power_of_two() && size < (1_usize << Params::MAX_EPOCH_LOG_2));
        assert!(end_i <= self.digest().unwrap().epoch as usize);
        // Truncate SRS
        let ip_srs = SRS{
            g_alpha_powers: self.ip_pp.g_alpha_powers[0..(2*size - 1)].to_vec(),
            h_beta_powers: self.ip_pp.h_beta_powers[0..(2*size - 1)].to_vec(),
            g_beta: self.ip_pp.g_beta.clone(),
            h_alpha: self.ip_pp.h_alpha.clone(),
        };
        let kzg_srs = &ip_srs.g_alpha_powers[0..size];

        let proofs = &self.proofs[start_i..end_i];
        let a = proofs
            .iter()
            .map(|proof| proof.a.into_projective())
            .collect::<Vec<Pairing::G1Projective>>();
        let b = proofs
            .iter()
            .map(|proof| proof.b.into_projective())
            .collect::<Vec<Pairing::G2Projective>>();
        let c = proofs
            .iter()
            .map(|proof| proof.c.into_projective())
            .collect::<Vec<Pairing::G1Projective>>();

        //TODO: Keep as iters instead of collecting to vector
        let digest_size = self.digests[start_i].to_field_elements()?.len();
        let digests_as_field = self.digests[start_i..end_i].iter().map(|d| d.to_field_elements()).collect::<Result<Vec<Vec<Pairing::Fr>>, Error>>()?;
        let digest_cross_slices = (0..digest_size).map(|i| {
            digests_as_field.iter().map(|d| d[i].clone()).collect::<Vec<Pairing::Fr>>()
        }).collect::<Vec<_>>();

        let trailing_digest = self.digests[end_i].clone();
        let trailing_digest_opening = (
            end_i as u64,
            self.digest_openings[end_i].0.clone(),
            self.digest_openings[end_i].1.clone(),
        );


        let (full_ck_1, full_ck_2) = self.ip_pp.get_commitment_keys();
        let ck_1 = &full_ck_1[0..size];
        let ck_2 = &full_ck_2[0..size];

        let com_a = PairingInnerProduct::<Pairing>::inner_product(&a, ck_1)?;
        let com_b = PairingInnerProduct::<Pairing>::inner_product(ck_2, &b)?;
        let com_c = PairingInnerProduct::<Pairing>::inner_product(&c, ck_1)?;
        let com_d = digest_cross_slices.iter().map(|d| {
            KZG::<Pairing>::commit(kzg_srs, d)
        }).collect::<Result<Vec<_>, Error>>()?;

        // Random linear combination of proofs
        let mut counter_nonce: usize = 0;
        let r = loop {
            let mut hash_input = Vec::new();
            hash_input.extend_from_slice(&counter_nonce.to_be_bytes()[..]);
            //TODO: Should use CanonicalSerialize instead of ToBytes
            hash_input.extend_from_slice(&to_bytes![com_a, com_b, com_c, com_d]?);
            if let Some(r) = <Pairing::Fr>::from_random_bytes(&FastH::digest(&hash_input)) {
                break r;
            };
            counter_nonce += 1;
        };

        let r_vec = structured_scalar_power(proofs.len(), &r);
        let a_r = a
            .iter()
            .zip(&r_vec)
            .map(|(a, r)| a.mul(r))
            .collect::<Vec<Pairing::G1Projective>>();
        let ip_ab = PairingInnerProduct::<Pairing>::inner_product(&a_r, &b)?;
        let agg_c = MultiexponentiationInnerProduct::<Pairing::G1Projective>::inner_product(&c, &r_vec)?;
        let agg_d = digest_cross_slices.iter().map(|d| {
            ScalarInnerProduct::<Pairing::Fr>::inner_product(d, &r_vec)
        }).collect::<Result<Vec<_>, Error>>()?;

        let ck_1_r = ck_1
            .iter()
            .zip(&r_vec)
            .map(|(ck, r)| ck.mul(&r.inverse().unwrap()))
            .collect::<Vec<Pairing::G2Projective>>();

        assert_eq!(
            com_a,
            PairingInnerProduct::<Pairing>::inner_product(&a_r, &ck_1_r)?
        );

        //TODO: Optimization: Currently duplicating proving effort of ck, r_vec, and recursive challenges
        let tipa_proof_ab = PairingInnerProductAB::<Pairing, FastH>::prove_with_srs_shift(
            &ip_srs,
            (&a_r, &b),
            (&ck_1_r, ck_2, &HomomorphicPlaceholderValue),
            &r,
        )?;

        let tipa_proof_c = MultiExpInnerProductC::<Pairing, FastH>::prove_with_structured_scalar_message(
            &ip_srs,
            (&c, &r_vec),
            (ck_1, &HomomorphicPlaceholderValue),
        )?;

        let tipa_proof_d = digest_cross_slices.iter().map(|d| {
            KZG::<Pairing>::open(&kzg_srs, d, &r)
        }).collect::<Result<Vec<_>, Error>>()?;

        Ok(AggregateDigestProof {
            com_a,
            com_b,
            com_c,
            com_d,
            ip_ab,
            agg_c,
            agg_d,
            tipa_proof_ab,
            tipa_proof_c,
            tipa_proof_d,
            trailing_digest,
            trailing_digest_opening,
        })
    }

    pub(crate) fn verify_aggregate_proof(
        history_tree_pp: &<HTParams::H as FixedLengthCRH>::Parameters,
        ip_verifier_srs: &VerifierSRS<Pairing>,
        vk: &VerifyingKey<Pairing>,
        leading_digest: &<<HTParams as MerkleTreeParameters>::H as FixedLengthCRH>::Output,
        proof: &AggregateDigestProof<SSAVD, HTParams, Pairing, FastH>,
        num_aggregated: u64,
    ) -> Result<bool, Error> {
        // Random linear combination of proofs
        let mut counter_nonce: usize = 0;
        let r = loop {
            let mut hash_input = Vec::new();
            hash_input.extend_from_slice(&counter_nonce.to_be_bytes()[..]);
            //TODO: Should use CanonicalSerialize instead of ToBytes
            hash_input.extend_from_slice(&to_bytes![proof.com_a, proof.com_b, proof.com_c, proof.com_d]?);
            if let Some(r) = <Pairing::Fr>::from_random_bytes(&FastH::digest(&hash_input)) {
                break r;
            };
            counter_nonce += 1;
        };

        // Check TIPA proofs
        let tipa_proof_ab_valid = PairingInnerProductAB::<Pairing, FastH>::verify_with_srs_shift(
            ip_verifier_srs,
            &HomomorphicPlaceholderValue,
            (
                &proof.com_a,
                &proof.com_b,
                &IdentityOutput(vec![proof.ip_ab.clone()]),
            ),
            &proof.tipa_proof_ab,
            &r,
        )?;
        let tipa_proof_c_valid = MultiExpInnerProductC::<Pairing, FastH>::verify_with_structured_scalar_message(
            ip_verifier_srs,
            &HomomorphicPlaceholderValue,
            (&proof.com_c, &IdentityOutput(vec![proof.agg_c.clone()])),
            &r,
            &proof.tipa_proof_c,
        )?;
        let tipa_proof_d_valid = proof.tipa_proof_d.iter().enumerate().map(|(i, p)| {
            KZG::<Pairing>::verify(
                ip_verifier_srs,
                &proof.com_d[i],
                &r,
                &proof.agg_d[i],
                p,
            )
        })
            .collect::<Result<Vec<bool>, Error>>()?
            .iter()
            .all(|b| *b);


        // Check aggregate pairing product equation

        let r_sum =
            (r.pow(&[num_aggregated]) - &<Pairing::Fr>::one()) / &(r.clone() - &<Pairing::Fr>::one());
        let p1 = Pairing::pairing(vk.alpha_g1.into_projective().mul(&r_sum), vk.beta_g2);

        let digest_size = proof.agg_d.len();
        assert_eq!(vk.gamma_abc_g1.len(), 1 + 2 * digest_size);
        let mut g_ic = vk.gamma_abc_g1[0].into_projective().mul(&r_sum);
        for i in 0..digest_size {
            g_ic.add_assign(&vk.gamma_abc_g1[i + 1].into_projective().mul(&proof.agg_d[i]));
            g_ic.add_assign(&vk.gamma_abc_g1[digest_size + i + 1].into_projective().mul(
                &(((proof.agg_d[i] - &leading_digest.to_field_elements()?[i]) / &r) + &(r.pow(&[num_aggregated - 1]) * &proof.trailing_digest.to_field_elements()?[i]))
            ));
        }

        let p2 = Pairing::pairing(g_ic, vk.gamma_g2);
        let p3 = Pairing::pairing(proof.agg_c, vk.delta_g2);

        let ppe_valid = proof.ip_ab.0 == (p1 * &p2) * &p3;

        // Check opening of trailing digest
        let trailing_digest_valid =
            proof.trailing_digest ==
                hash_to_final_digest::<SSAVD, HTParams::H>(
                    history_tree_pp,
                    &proof.trailing_digest_opening.1,
                    &proof.trailing_digest_opening.2,
                    &proof.trailing_digest_opening.0,
                )?;

        Ok(tipa_proof_ab_valid && tipa_proof_c_valid && tipa_proof_d_valid && ppe_valid && trailing_digest_valid)
    }
}
