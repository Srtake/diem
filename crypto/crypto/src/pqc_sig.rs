//! This module provides an API for the Post-Quantum Cryptography algorithms
//! implemented in Open Quantum Safe library liboqs.

use crate::{
    hash::{CryptoHash, CryptoHasher},
    traits::*,
};
use anyhow::{anyhow, Result};
use core::convert::TryFrom;
use diem_crypto_derive::{DeserializeKey, SerializeKey, SilentDebug, SilentDisplay};
use mirai_annotations::*;
use serde::Serialize;
use std::{cmp::Ordering, fmt};
use std::ops::Deref;
use itertools::Itertools;

// #![allow(clippy::integer_arithmetic)]

pub use oqs;

const CURR_ALGORITHM: oqs::sig::Algorithm = oqs::sig::Algorithm::Dilithium2;
const SECRET_KEY_LENGTH: usize = 2528;
const PUBLIC_KEY_LENGTH: usize = 1312;
const SIGNATURE_LENGTH: usize = 2420;

fn secretKeyVecToArray(v: Vec<u8>) -> [u8; SECRET_KEY_LENGTH] {
    let mut arr = [0u8; SECRET_KEY_LENGTH];
    arr.iter_mut().set_from(v.iter().cloned());
    arr
}

fn publicKeyVecToArray(v: Vec<u8>) -> [u8; PUBLIC_KEY_LENGTH] {
    let mut arr = [0u8; PUBLIC_KEY_LENGTH];
    arr.iter_mut().set_from(v.iter().cloned());
    arr
}

fn signatureVecToArray(v: Vec<u8>) -> [u8; SIGNATURE_LENGTH] {
    let mut arr = [0u8; SIGNATURE_LENGTH];
    arr.iter_mut().set_from(v.iter().cloned());
    arr
}

/// Signature scheme struct of liboqs
pub struct LiboqsSig {
    alg: oqs::sig::Algorithm,
    sig: oqs::sig::Sig,
}

impl core::convert::TryFrom<oqs::sig::Algorithm> for LiboqsSig {
    type Error = CryptoMaterialError;
    fn try_from(alg: oqs::sig::Algorithm) -> Result<LiboqsSig, CryptoMaterialError> {
        match LiboqsSig::new(alg) {
            Ok(sig) => Ok(sig),
            Err(_) => Err(CryptoMaterialError::DeserializationError)
        }
    }
}

impl Clone for LiboqsSig {
    fn clone(&self) -> LiboqsSig {
        LiboqsSig::new(CURR_ALGORITHM).unwrap()
    }
}

impl LiboqsSig {
    /// Create a new Liboqs object
    pub fn new(alg: oqs::sig::Algorithm) -> Result<Self> {
        oqs::init();
        let sig = oqs::sig::Sig::try_from(alg).unwrap();
        Ok(Self { alg, sig })
    }
}

/// An PQC private key
#[derive(DeserializeKey, SerializeKey, SilentDebug, SilentDisplay)]
pub struct PQCPrivateKey {
    LENGTH: usize,
    SIG: LiboqsSig,
    KEY: oqs::sig::SecretKey
}

impl Clone for PQCPrivateKey {
    fn clone(&self) -> PQCPrivateKey {
        let serialized: &[u8] = &(self.to_bytes());
        PQCPrivateKey::try_from(serialized).unwrap()
    }
}

/// An PQC Public key
#[derive(DeserializeKey, Clone, SerializeKey)]
pub struct PQCPublicKey {
    LENGTH: usize,
    SIG: LiboqsSig,
    KEY: oqs::sig::PublicKey
}

/// #[cfg(not(mirai))]
struct ValidatedPublicKeyTag {}

/// An PQC signature
#[derive(DeserializeKey, Clone, SerializeKey)]
pub struct PQCSignature {
    LENGTH: usize,
    SIG: LiboqsSig,
    SIGNATURE: oqs::sig::Signature
}

impl PQCPrivateKey {
    /// Construct a private key
    pub fn new(bytes_param: &[u8]) -> Result<Self, CryptoMaterialError>{
        let sig = LiboqsSig::try_from(CURR_ALGORITHM).unwrap();
        Ok(PQCPrivateKey {
            LENGTH: sig.sig.length_secret_key(),
            SIG: sig.clone(),
            /// KEY: oqs::sig::SecretKey {
            ///     bytes: sig.sig.secret_key_from_bytes(bytes_param).unwrap().deref().to_vec()
            /// }
            KEY: sig.sig.secret_key_from_bytes(bytes_param).unwrap().to_owned()
        })
    }

    /// Construct a private key from a OQS SecretKey type
    pub fn new_from_oqs(sk: &oqs::sig::SecretKey) -> Result<Self, CryptoMaterialError> {
        let sig = LiboqsSig::try_from(CURR_ALGORITHM).unwrap();
        Ok(PQCPrivateKey {
            LENGTH: sig.sig.length_secret_key(),
            SIG: sig.clone(),
            KEY: (*sk).clone()
        })
    }

    /// Serialize an PQCPrivateKey
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        secretKeyVecToArray(self.KEY.clone().into_vec())
    }

    /// Deserialize an PQCPrivate without any value check
    fn from_bytes_unchecked(bytes: &[u8]) -> Result<PQCPrivateKey, CryptoMaterialError> {
        let sig = LiboqsSig::try_from(CURR_ALGORITHM).unwrap();
        match PQCPrivateKey::new(bytes) {
            Ok(private_key) => Ok(private_key),
            Err(_) => Err(CryptoMaterialError::DeserializationError)
        }
    }

    /// Private sign function
    fn sign_arbitrary_message(&self, message: &[u8]) -> PQCSignature {
        let secret_key: &oqs::sig::SecretKey = &self.KEY;
        let sig = self.SIG.sig.sign(&*message, oqs::sig::SecretKeyRef::from(secret_key)).unwrap();
        println!("Signature: {}", hex::encode(sig.clone().into_vec()));
        PQCSignature {
            LENGTH: sig.clone().into_vec().len(),
            SIG: self.SIG.clone(),
            SIGNATURE: sig.clone()
        }
    }
}

impl TryFrom<&oqs::sig::SecretKey> for PQCPrivateKey {
    type Error = CryptoMaterialError;

    fn try_from(sk: &oqs::sig::SecretKey) -> Result<PQCPrivateKey, CryptoMaterialError> {
        let key = PQCPrivateKey::new_from_oqs(sk).unwrap();
        println!("Private key: {}", hex::encode(key.clone().KEY.into_vec()));
        Ok(key)
    }
}

impl TryFrom<&[u8]> for PQCPrivateKey {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> Result<PQCPrivateKey, CryptoMaterialError> {
        PQCPrivateKey::new(bytes)
    }
}

impl PQCPublicKey {
    /// Construct a PQCPublicKey.
    pub fn new(bytes_param: &[u8]) -> Result<Self, CryptoMaterialError> {
        let sig = LiboqsSig::try_from(CURR_ALGORITHM).unwrap();
        Ok(PQCPublicKey {
            LENGTH: sig.sig.length_public_key(),
            SIG: sig.clone(),
            /// KEY: oqs::sig::PublicKey {
            ///     bytes: sig.sig.public_key_from_bytes(bytes_param).unwrap().deref().to_vec()
            /// }
            KEY: sig.sig.public_key_from_bytes(bytes_param).unwrap().to_owned()
        })
    }

    /// Construct a PQCPublicKey from OQS PublicKey type
    pub fn new_from_oqs(pk: &oqs::sig::PublicKey) -> Result<Self, CryptoMaterialError> {
        let sig = LiboqsSig::try_from(CURR_ALGORITHM).unwrap();
        Ok(PQCPublicKey {
            LENGTH: sig.sig.length_public_key(),
            SIG: sig.clone(),
            KEY: (*pk).clone()
        })
    }

    /// Serialize a PQCPublicKey.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        publicKeyVecToArray(self.KEY.clone().into_vec())
    }

    /// Deserialize a PQCPublicKey without any value check
    pub(crate) fn from_bytes_unchecked(bytes: &[u8]) -> Result<PQCPublicKey, CryptoMaterialError> {
        let sig = LiboqsSig::try_from(CURR_ALGORITHM);
        match PQCPublicKey::new(bytes) {
            Ok(public_key) => Ok(public_key),
            Err(_) => Err(CryptoMaterialError::DeserializationError)
        }
    }

    // In ed25519.rs: from_x25519_public_bytes() implementation
}

impl TryFrom<&oqs::sig::PublicKey> for PQCPublicKey {
    type Error = CryptoMaterialError;

    fn try_from(pk: &oqs::sig::PublicKey) -> Result<PQCPublicKey, CryptoMaterialError> {
        let key = PQCPublicKey::new_from_oqs(pk).unwrap();
        println!("Public key: {}", hex::encode(key.clone().KEY.into_vec()));
        Ok(key)
    }
}

impl TryFrom<&[u8]> for PQCPublicKey {
    type Error = CryptoMaterialError;
    
    fn try_from(bytes: &[u8]) -> Result<PQCPublicKey, CryptoMaterialError> {
        match PQCPublicKey::new(bytes) {
            Ok(public_key) => Ok(public_key),
            Err(_) => Err(CryptoMaterialError::DeserializationError),
        }
    }
}

impl PQCSignature {
    /// Construct a PQCSignature object
    pub fn new(bytes_param: &[u8]) -> Result<Self, CryptoMaterialError> {
        let sig = LiboqsSig::try_from(CURR_ALGORITHM).unwrap();
        Ok(PQCSignature {
            LENGTH: sig.sig.length_signature(),
            SIG: sig.clone(),
            /// SIGNATURE: oqs::sig::Signature {
            ///     bytes: sig.sig.signature_from_bytes(bytes_param).unwrap().deref().to_vec()
            /// }
            SIGNATURE: sig.sig.signature_from_bytes(bytes_param).unwrap().to_owned()
        })
    }

    /// Construct a PQCSignature object from OQS Signature type
    pub fn new_from_oqs(sig: &oqs::sig::Signature) -> Result<Self, CryptoMaterialError> {
        let oqs_sig = LiboqsSig::try_from(CURR_ALGORITHM).unwrap();
        Ok(PQCSignature {
            LENGTH: oqs_sig.sig.length_signature(),
            SIG: oqs_sig.clone(),
            SIGNATURE: (*sig).clone()
        })
    }

    /// Liboqs signature object to bytes (u8 array)
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        signatureVecToArray(self.SIGNATURE.clone().into_vec())
    }

    /// Create Liboqs signature object from bytes (u8 array)
    pub(crate) fn from_bytes_unchecked(bytes: &[u8]) -> Result<PQCSignature, CryptoMaterialError> {
        let sig = LiboqsSig::try_from(CURR_ALGORITHM);
        match PQCSignature::try_from(bytes) {
            Ok(signature) => Ok(signature),
            Err(_) => Err(CryptoMaterialError::DeserializationError)
        }
    }

    // Return an all-zero signature (for test only)
    // pub fn dummy_signature() -> Self {
    //     Self::from_bytes_unchecked(&[0u8; self.LENGTH])
    // }
    
    /// Check operation. Doing nothing right now. (TODO)
    pub fn check_malleability(bytes: &[u8]) -> Result<(), CryptoMaterialError> {
        /// if bytes.len() != self.LENGTH {
        ///     return Err(CryptoMaterialError::WrongLengthError);
        /// }
        Ok(())
    }
}

/// PrivateKey Traits
impl PrivateKey for PQCPrivateKey {
    type PublicKeyMaterial = PQCPublicKey;
}

impl SigningKey for PQCPrivateKey {
    type VerifyingKeyMaterial = PQCPublicKey;
    type SignatureMaterial = PQCSignature;

    fn sign<T: CryptoHash + Serialize>(&self, message: &T) -> PQCSignature {
        let mut bytes = <T::Hasher as CryptoHasher>::seed().to_vec();
        bcs::serialize_into(&mut bytes, &message)
            .map_err(|_| CryptoMaterialError::SerializationError)
            .expect("Serialization of signable material should not fail.");
        PQCPrivateKey::sign_arbitrary_message(&self, bytes.as_ref())
    }

    #[cfg(any(test, feature = "fuzzing"))]
    fn sign_arbitrary_message(&self, message: &[u8]) -> PQCSignature {
        PQCPrivateKey::sign_arbitrary_message(self, message)
    }
}

impl Uniform for PQCPrivateKey {
    fn generate<R>(rng: &mut R) -> Self
    where
        R: ::rand::RngCore + ::rand::CryptoRng,
    {
        /// 由于Diem规定的trait只允许这个函数传入一个rng参数
        /// 所以这里直接传入默认的算法标记
        /// 之后对这一点进行修改，使整个模块维护一个全局的当前算法标记和签名对象
        let sig = LiboqsSig::try_from(oqs::sig::Algorithm::default());
        /// const length = sig.length_secret_key();
        /// 这里需要后续修改。把32换成符合要求的*常量*
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        PQCPrivateKey::new(&bytes).unwrap()
    }
}

impl PartialEq<Self> for PQCPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for PQCPrivateKey {}

impl Length for PQCPrivateKey {
    fn length(&self) -> usize {
        self.LENGTH
    }
}

impl ValidCryptoMaterial for PQCPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

impl Genesis for PQCPrivateKey {
    fn genesis() -> Self {
        let sig = LiboqsSig::try_from(oqs::sig::Algorithm::default()).unwrap();
        /// const length = sig.length_secret_key;
        let mut buf = [0u8; 32];
        buf[sig.sig.length_secret_key() - 1] = 1;
        Self::try_from(buf.as_ref()).unwrap()
    }
}

/// PublicKey Traits

/// impl From<&[u8]> for PQCPublicKey {
///     fn from(bytes: &[u8]) -> Self {
///         PQCPublicKey::try_from(bytes).unwrap()
///     }
/// }

/// 根据私钥生成公钥，在Ed25519的实现里实现了这个trait
/// 但liboqs的实现中是使用keypair一次性生成公私钥
impl From<&PQCPrivateKey> for PQCPublicKey {
    fn from(private_key: &PQCPrivateKey) -> Self {
        let sig = LiboqsSig::try_from(oqs::sig::Algorithm::default());
        /// const length = sig.length_public_key;
        let bytes = [0u8; PUBLIC_KEY_LENGTH];
        let public: PQCPublicKey = PQCPublicKey::new(&bytes).unwrap();
        public
    }
}

impl PublicKey for PQCPublicKey {
    type PrivateKeyMaterial = PQCPrivateKey;
}

impl std::hash::Hash for PQCPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_pubkey = self.to_bytes();
        state.write(&encoded_pubkey);
    }
}

impl PartialEq for PQCPublicKey {
    fn eq(&self, other: &PQCPublicKey) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for PQCPublicKey {}

impl VerifyingKey for PQCPublicKey {
    type SigningKeyMaterial = PQCPrivateKey;
    type SignatureMaterial = PQCSignature;
}

impl fmt::Display for PQCPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.KEY.clone().into_vec()))
    }
}

impl fmt::Debug for PQCPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PQCPublicKey({})", self)
    }
}

impl Length for PQCPublicKey {
    fn length(&self) -> usize {
        self.LENGTH
    }
}

impl ValidCryptoMaterial for PQCPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

/// Signature traits
impl Signature for PQCSignature {
    type VerifyingKeyMaterial = PQCPublicKey;
    type SigningKeyMaterial = PQCPrivateKey;

    fn verify<T: CryptoHash + Serialize>(
        &self,
        message: &T,
        public_key: &PQCPublicKey
    ) -> Result<()> {
        /// precondition!(has_tag!(public_key, ValidatedPublicKeyTag))
        let mut bytes = <T::Hasher as CryptoHasher>::seed().to_vec();
        bcs::serialize_into(&mut bytes, &message)
            .map_err(|_| CryptoMaterialError::SerializationError)?;
        Self::verify_arbitrary_msg(self, &bytes, public_key)
    }

    fn verify_arbitrary_msg(&self, message: &[u8], public_key: &PQCPublicKey) -> Result<()> {
        /// precondition!(has_tag!(public_key, ValidatedPublicKeyTag));
        PQCSignature::check_malleability(&self.to_bytes())?;
        public_key.SIG.sig.verify(
            &*message,
            oqs::sig::SignatureRef::from(&self.SIGNATURE), 
            oqs::sig::PublicKeyRef::from(&(*public_key).KEY)
        )
            .map_err(|e| anyhow!("{}", e))
            .and(Ok(()))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    /// Batch signature
    /// 批量签名，暂时不实现
    fn batch_verify<T: CryptoHash + Serialize>(
        message: &T,
        keys_and_signatures: Vec<(Self::VerifyingKeyMaterial, Self)>,
    ) -> Result<()> {
        /// TODO
        Ok(())
    }
}

impl Length for PQCSignature {
    fn length(&self) -> usize {
        self.LENGTH
    }
}

impl ValidCryptoMaterial for PQCSignature {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

impl std::hash::Hash for PQCSignature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_signature = self.to_bytes();
        state.write(&encoded_signature);
    }
}

impl TryFrom<&oqs::sig::Signature> for PQCSignature {
    type Error = CryptoMaterialError;

    fn try_from(sig: &oqs::sig::Signature) -> Result<PQCSignature, CryptoMaterialError> {
        PQCSignature::new_from_oqs(sig)
    }
}

impl TryFrom<&[u8]> for PQCSignature {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> Result<PQCSignature, CryptoMaterialError> {
        PQCSignature::check_malleability(bytes)?;
        PQCSignature::from_bytes_unchecked(bytes)
    }
}

impl PartialEq for PQCSignature {
    fn eq(&self, other: &PQCSignature) -> bool {
        self.to_bytes()[..] == other.to_bytes()[..]
    }
}

impl Eq for PQCSignature {}

impl fmt::Display for PQCSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.to_bytes()[..]))
    }
}

impl fmt::Debug for PQCSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PQCSignature({})", self)
    }
}