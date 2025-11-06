pub mod attestation;
pub mod assertion;

pub use attestation::{get_attestation_options, post_attestation_result};
pub use assertion::{get_assertion_options, post_assertion_result};