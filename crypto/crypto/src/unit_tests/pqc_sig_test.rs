use crate as diem_crypto;
use crate::{
    pqc_sig::{PQCPrivateKey, PQCPublicKey, PQCSignature},
    test_utils::{random_serializable_struct, uniform_keypair_strategy},
    traits::*,
};
use oqs::*;
use std::convert::TryFrom;

#[test]
fn test_pqc_sig() {
    let sigalg = sig::Sig::new(sig::Algorithm::default()).unwrap();
    let (sig_pk, sig_sk) = sigalg.keypair().unwrap();
    let private_key = PQCPrivateKey::try_from(&sig_sk).unwrap();
    let public_key = PQCPublicKey::try_from(&sig_pk).unwrap();
    let message = b"This is a message.";
    let signature = private_key.sign_arbitrary_message(message);
    assert!(signature.verify_arbitrary_msg(message, &public_key).is_ok());
}