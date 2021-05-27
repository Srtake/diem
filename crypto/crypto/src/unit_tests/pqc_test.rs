use crate as diem_crypto;
use crate::{
    pqc_sig::{PQCPrivateKey, PQCPublicKey, PQCSignature, curr_alg, keypair as sig_keypair},
    pqc_kem::{PrivateKey, PublicKey, keypair as kem_keypair, CiphertextVecToArray},
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

#[test]
fn test_pqc() {
    // Keys used for KEMs and long-term secrets
    let (kem_sk, kem_pk) = kem_keypair();
    let (a_sig_sk, a_sig_pk) = sig_keypair();
    let (b_sig_sk, b_sig_pk) = sig_keypair();
    println!("[test_pqc] kem_pk = {}", hex::encode(kem_pk.to_bytes()));
    println!("[test_pqc] a_sig_pk = {}", hex::encode(a_sig_pk.to_bytes()));
    println!("[test_pqc] b_sig_pk = {}", hex::encode(b_sig_pk.to_bytes()));
    
    // Assumption: A has (a_sig_sk, a_sig_pk, b_sig_pk)
    // Assumption: B has (b_sig_sk, b_sig_pk, a_sig_pk)
    
    // A -> B: kem_pk, signature
    let signature = a_sig_sk.sign_arbitrary_message(&(kem_pk.to_bytes()));
    println!("[test_pqc] A -> B signature = {}", hex::encode(signature.to_bytes()));

    // B -> A: kem_ct, signature
    signature.verify_arbitrary_msg(&(kem_pk.to_bytes()), &a_sig_pk);
    let (kem_ct, b_kem_ss) = kem_pk.encapsulate();
    let signature = b_sig_sk.sign_arbitrary_message(&(CiphertextVecToArray(kem_ct.clone().into_vec())));
    println!("[test_pqc] B -> A signature = {}", hex::encode(signature.to_bytes()));
    println!("[test_pqc] kem_ct = {}", hex::encode(CiphertextVecToArray(kem_ct.clone().into_vec())));
    println!("[test_pqc] b_kem_ss = {}", hex::encode(SharedSecretVecToArray(b_kem_ss.clone().into_vec())));

    // A verifies, decapsulates, now both have kem_ss
    signature.verify_arbitrary_msg(&(CiphertextVecToArray(kem_ct.clone().into_vec())), &b_sig_pk);
    let a_kem_ss = kem_sk.decapsulate(&kem_ct);
    println!("[test_pqc] a_kem_ss = {}", hex::encode(SharedSecretVecToArray(a_kem_ss.clone().into_vec())));
    assert_eq!(a_kem_ss, b_kem_ss);
}