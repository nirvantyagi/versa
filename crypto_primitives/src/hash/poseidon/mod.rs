/*
This implementation of Poseidon is taken almost entirely from arkworks:
https://github.com/arkworks-rs/marlin/blob/constraints/src/fiat_shamir/poseidon/mod.rs
 */

use ark_ff::{fields::{PrimeField, FpParameters}, ToConstraintField};
use rand::{Rng, rngs::StdRng, SeedableRng};
use crate::{
    hash::{FixedLengthCRH, HashError},
    Error,
};

/// constraints for Poseidon
pub mod constraints;

/// the trait for algebraic sponge
pub trait AlgebraicSponge<CF: PrimeField>: Clone {
    /// initialize the sponge
    fn new() -> Self;
    /// take in field elements
    fn absorb(&mut self, elems: &[CF]);
    /// take out field elements
    fn squeeze(&mut self, num: usize) -> Vec<CF>;
}

#[derive(Clone)]
enum PoseidonSpongeState {
    Absorbing { next_absorb_index: usize },
    Squeezing { next_squeeze_index: usize },
}

#[derive(Clone)]
/// the sponge for Poseidon
pub struct PoseidonSponge<F: PrimeField> {
    /// number of rounds in a full-round operation
    pub full_rounds: u32,
    /// number of rounds in a partial-round operation
    pub partial_rounds: u32,
    /// Exponent used in S-boxes
    pub alpha: u64,
    /// Additive Round keys. These are added before each MDS matrix application to make it an affine shift.
    /// They are indexed by ark[round_num][state_element_index]
    pub ark: Vec<Vec<F>>,
    /// Maximally Distance Separating Matrix.
    pub mds: Vec<Vec<F>>,

    /// the sponge's state
    pub state: Vec<F>,
    /// the rate
    pub rate: usize,
    /// the capacity
    pub capacity: usize,
    /// the mode
    mode: PoseidonSpongeState,
}

impl<F: PrimeField> PoseidonSponge<F> {
    fn apply_s_box(&self, state: &mut [F], is_full_round: bool) {
        // Full rounds apply the S Box (x^alpha) to every element of state
        if is_full_round {
            for elem in state {
                *elem = elem.pow(&[self.alpha]);
            }
        }
        // Partial rounds apply the S Box (x^alpha) to just the final element of state
        else {
            state[state.len() - 1] = state[state.len() - 1].pow(&[self.alpha]);
        }
    }

    fn apply_ark(&self, state: &mut [F], round_number: usize) {
        for (i, state_elem) in state.iter_mut().enumerate() {
            state_elem.add_assign(&self.ark[round_number][i]);
        }
    }

    fn apply_mds(&self, state: &mut [F]) {
        let mut new_state = Vec::new();
        for i in 0..state.len() {
            let mut cur = F::zero();
            for (j, state_elem) in state.iter().enumerate() {
                let term = state_elem.mul(&self.mds[i][j]);
                cur.add_assign(&term);
            }
            new_state.push(cur);
        }
        state.clone_from_slice(&new_state[..state.len()])
    }

    fn permute(&mut self) {
        let full_rounds_over_2 = self.full_rounds / 2;
        let mut state = self.state.clone();
        for i in 0..full_rounds_over_2 {
            self.apply_ark(&mut state, i as usize);
            self.apply_s_box(&mut state, true);
            self.apply_mds(&mut state);
        }

        for i in full_rounds_over_2..(full_rounds_over_2 + self.partial_rounds) {
            self.apply_ark(&mut state, i as usize);
            self.apply_s_box(&mut state, false);
            self.apply_mds(&mut state);
        }

        for i in
        (full_rounds_over_2 + self.partial_rounds)..(self.partial_rounds + self.full_rounds)
        {
            self.apply_ark(&mut state, i as usize);
            self.apply_s_box(&mut state, true);
            self.apply_mds(&mut state);
        }
        self.state = state;
    }

    // Absorbs everything in elements, this does not end in an absorbtion.
    fn absorb_internal(&mut self, rate_start_index: usize, elements: &[F]) {
        // if we can finish in this call
        if rate_start_index + elements.len() <= self.rate {
            for (i, element) in elements.iter().enumerate() {
                self.state[i + rate_start_index] += element;
            }
            self.mode = PoseidonSpongeState::Absorbing {
                next_absorb_index: rate_start_index + elements.len(),
            };

            return;
        }
        // otherwise absorb (rate - rate_start_index) elements
        let num_elements_absorbed = self.rate - rate_start_index;
        for (i, element) in elements.iter().enumerate().take(num_elements_absorbed) {
            self.state[i + rate_start_index] += element;
        }
        self.permute();
        // Tail recurse, with the input elements being truncated by num elements absorbed
        self.absorb_internal(0, &elements[num_elements_absorbed..]);
    }

    // Squeeze |output| many elements. This does not end in a squeeze
    fn squeeze_internal(&mut self, rate_start_index: usize, output: &mut [F]) {
        // if we can finish in this call
        if rate_start_index + output.len() <= self.rate {
            output
                .clone_from_slice(&self.state[rate_start_index..(output.len() + rate_start_index)]);
            self.mode = PoseidonSpongeState::Squeezing {
                next_squeeze_index: rate_start_index + output.len(),
            };
            return;
        }
        // otherwise squeeze (rate - rate_start_index) elements
        let num_elements_squeezed = self.rate - rate_start_index;
        output[..num_elements_squeezed].clone_from_slice(
            &self.state[rate_start_index..(num_elements_squeezed + rate_start_index)],
        );

        // Unless we are done with squeezing in this call, permute.
        if output.len() != self.rate {
            self.permute();
        }
        // Tail recurse, with the correct change to indices in output happening due to changing the slice
        self.squeeze_internal(0, &mut output[num_elements_squeezed..]);
    }
}

impl<F: PrimeField> AlgebraicSponge<F> for PoseidonSponge<F> {
    fn new() -> Self {
        let full_rounds = 8;
        let partial_rounds = 31;
        let alpha = 17;

        //TODO: Switch to non-near MDS which can be generated https://gist.github.com/ValarDragon/1831132789765d4469899ccbdc8ed2b7#file-generate_mds-sage-L116
        let mds = vec![
            vec![F::one(), F::zero(), F::one()],
            vec![F::one(), F::one(), F::zero()],
            vec![F::zero(), F::one(), F::one()],
        ];

        let mut ark = Vec::new();
        let mut ark_rng = StdRng::seed_from_u64(0u64);

        for _ in 0..(full_rounds + partial_rounds) {
            let mut res = Vec::new();

            for _ in 0..3 {
                res.push(F::rand(&mut ark_rng));
            }
            ark.push(res);
        }

        let rate = 2;
        let capacity = 1;
        let state = vec![F::zero(); rate + capacity];
        let mode = PoseidonSpongeState::Absorbing {
            next_absorb_index: 0,
        };

        PoseidonSponge {
            full_rounds,
            partial_rounds,
            alpha,
            ark,
            mds,

            state,
            rate,
            capacity,
            mode,
        }
    }

    fn absorb(&mut self, elems: &[F]) {
        if elems.is_empty() {
            return;
        }

        match self.mode {
            PoseidonSpongeState::Absorbing { next_absorb_index } => {
                let mut absorb_index = next_absorb_index;
                if absorb_index == self.rate {
                    self.permute();
                    absorb_index = 0;
                }
                self.absorb_internal(absorb_index, elems);
            }
            PoseidonSpongeState::Squeezing {
                next_squeeze_index: _,
            } => {
                self.permute();
                self.absorb_internal(0, elems);
            }
        };
    }

    fn squeeze(&mut self, num: usize) -> Vec<F> {
        let mut squeezed_elems = vec![F::zero(); num];
        match self.mode {
            PoseidonSpongeState::Absorbing {
                next_absorb_index: _,
            } => {
                self.permute();
                self.squeeze_internal(0, &mut squeezed_elems);
            }
            PoseidonSpongeState::Squeezing { next_squeeze_index } => {
                let mut squeeze_index = next_squeeze_index;
                if squeeze_index == self.rate {
                    self.permute();
                    squeeze_index = 0;
                }
                self.squeeze_internal(squeeze_index, &mut squeezed_elems);
            }
        };
        squeezed_elems
    }
}

impl<F: PrimeField> FixedLengthCRH for PoseidonSponge<F> {
    const INPUT_SIZE_BITS: usize = <F::Params as FpParameters>::CAPACITY as usize;
    type Output = F;
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        if input.len() > Self::INPUT_SIZE_BITS / 8 {
            return Err(Box::new(HashError::InputSizeError(input.len())));
        }
        Self::evaluate_variable_length(parameters, input)
    }

    fn evaluate_variable_length(_parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        let mut sponge = PoseidonSponge::<F>::new();
        sponge.absorb(&input.to_field_elements().unwrap());
        Ok(sponge.squeeze(1)[0].clone())
    }

    fn merge(_parameters: &Self::Parameters, left: &Self::Output, right: &Self::Output) -> Result<Self::Output, Error> {
        let mut sponge = PoseidonSponge::<F>::new();
        sponge.absorb(&[left.clone(), right.clone()]);
        Ok(sponge.squeeze(1)[0].clone())
    }
}