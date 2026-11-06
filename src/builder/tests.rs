use super::{bundle, BundleType};
use crate::{
    note_encryption::Zip212Enforcement,
    prover::mock::{MockOutputProver, MockSpendProver},
    Anchor,
};
use rand::{rngs::StdRng, SeedableRng};

#[test]
fn empty_bundles_skip_binding_keys_and_value_conversion() {
    struct NoValueConversion;
    impl TryFrom<i64> for NoValueConversion {
        type Error = core::convert::Infallible;
        fn try_from(_: i64) -> Result<Self, Self::Error> {
            panic!("an absent bundle has no value to convert")
        }
    }
    for bundle_type in [BundleType::Coinbase, BundleType::DEFAULT] {
        let result = bundle::<MockSpendProver, MockOutputProver, _, NoValueConversion>(
            &mut StdRng::seed_from_u64(0),
            bundle_type,
            Zip212Enforcement::On,
            Anchor::empty_tree(),
            vec![],
            vec![],
            &[],
        );
        assert!(result.unwrap().is_none());
    }
}
