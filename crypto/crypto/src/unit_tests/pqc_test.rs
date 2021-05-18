use crate as diem_crypto;
use crate::{
    pqc_sig::{PQCPrivateKey, PQCPublicKey, PQCSignature, curr_alg, keypair},
    pqc_kem::{PrivateKey, PublicKey, keypair},
    test_utils::{random_serializable_struct, uniform_keypair_strategy},
    traits::*,
};
use oqs::*;
use std::convert::TryFrom;

#[test]
fn test_pqc_sig() {
    let sigalg = sig::Sig::new(curr_alg()).unwrap();
    let (sig_pk, sig_sk) = sigalg.keypair().unwrap();
    let private_key = PQCPrivateKey::try_from(&sig_sk).unwrap();
    let public_key = PQCPublicKey::try_from(&sig_pk).unwrap();
    let message = b"This is a message.";
    let signature = private_key.sign_arbitrary_message(message);
    assert!(signature.verify_arbitrary_msg(message, &public_key).is_ok());
}

fn test_pqc() {
    // Keys used for KEMs and long-term secrets
    let (kem_sk, kem_pk) = pqc_kem::keypair();
    let (a_sig_sk, a_sig_pk) = pqc_sig::keypair();
    let (b_sig_sk, b_sig_pk) = pqc_sig::keypair();
    
    // Assumption: A has (a_sig_sk, a_sig_pk, b_sig_pk)
    // Assumption: B has (b_sig_sk, b_sig_pk, a_sig_pk)
    
    // A -> B: kem_pk, signature
    let signature = a_sig_sk.sign_arbitrary_message(&(kem_pk.to_bytes()));

    // B -> A: kem_ct, signature
    signature.verify_arbitrary_msg(&(kem_pk.to_bytes()), &a_sig_pk);
    let (kem_ct, b_kem_ss) = kem_pk.encapsulate();
    let signature = b_sig_sk.sign_arbitrary_message(&kem_ct);

    // A verifies, decapsulates, now both have kem_ss
    signature.verify_arbitrary_msg(&kem_ct, &b_sig_pk);
    let a_kem_ss = kem_sk.decapsulate(&kem_ct);
    assert_eq!(a_kem_ss, b_kem_ss);

    Ok(())
}