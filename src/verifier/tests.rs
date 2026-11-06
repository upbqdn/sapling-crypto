use super::SaplingVerificationContextInner;
use crate::{
    constants::SPENDING_KEY_GENERATOR,
    value::{CommitmentSum, NoteValue, ValueCommitTrapdoor, ValueCommitment},
};
use core::cell::Cell;
use group::Curve;
use redjubjub::{SpendAuth, VerificationKey};

#[test]
fn retained_spend_keys_preserve_coordinates_and_small_order_policy() {
    let order_two = jubjub::AffinePoint::from_bytes((-jubjub::Fq::one()).to_bytes()).unwrap();
    let order_four = jubjub::AffinePoint::from_bytes([0; 32]).unwrap();
    let generator = jubjub::ExtendedPoint::from(SPENDING_KEY_GENERATOR);
    let cv = ValueCommitment::derive(
        NoteValue::ZERO,
        ValueCommitTrapdoor::from_bytes([7; 32]).unwrap(),
    );
    let proof = groth16::Proof::<bls12_381::Bls12> {
        a: bls12_381::G1Affine::generator(),
        b: bls12_381::G2Affine::generator(),
        c: bls12_381::G1Affine::generator(),
    };
    for torsion in [jubjub::AffinePoint::identity(), order_two, order_four] {
        for point in [jubjub::ExtendedPoint::from(torsion), generator + torsion] {
            let expected = point.to_affine();
            let key = VerificationKey::<SpendAuth>::try_from(expected.to_bytes()).unwrap();
            let signature_checked = Cell::new(false);
            let proof_checked = Cell::new(false);
            let valid = SaplingVerificationContextInner::new().check_spend(
                &cv,
                bls12_381::Scalar::zero(),
                &[0; 32],
                &key,
                proof.clone(),
                &mut (),
                |_, _| {
                    signature_checked.set(true);
                    true
                },
                |_, _, inputs| {
                    proof_checked.set(true);
                    assert_eq!(inputs[0], expected.get_u());
                    assert_eq!(inputs[1], expected.get_v());
                    true
                },
            );
            let expected_valid = !bool::from(expected.is_small_order());
            assert_eq!(valid, expected_valid);
            assert_eq!(signature_checked.get(), expected_valid);
            assert_eq!(proof_checked.get(), expected_valid);
        }
    }
}

#[test]
fn retained_binding_keys_match_encoding_roundtrip() {
    for value in [i64::MIN, -1, 0, 1, i64::MAX] {
        let commitment = ValueCommitment::derive(
            NoteValue::from_raw(17),
            ValueCommitTrapdoor::from_bytes([7; 32]).unwrap(),
        );
        let sum = CommitmentSum::zero() + &commitment;
        let key = sum.into_bvk(value);
        let bytes: [u8; 32] = key.into();
        let decoded = redjubjub::VerificationKey::try_from(bytes).unwrap();
        assert_eq!(key, decoded);
    }
}
