//! This module provides an API for the Post-Quantum Cryptography key encapsulate algorithms
//! implemented in Open Quantum Safe library liboqs.

use crate::{
    traits::{self, CryptoMaterialError, ValidCryptoMaterial, ValidCryptoMaterialStringExt},
    x25519,
};
use diem_crypto_derive::{DeserializeKey, SerializeKey, SilentDebug, SilentDisplay};
use rand::{CryptoRng, RngCore};
use std::convert::{TryFrom, TryInto};
use itertools::Itertools;
use thiserror::Error;

pub use oqs;

const CURR_ALGORITHM: oqs::kem::Algorithm = oqs::kem::Algorithm::Kyber512;
pub const SECRET_KEY_LENGTH: usize = 1632;
pub const PUBLIC_KEY_LENGTH: usize = 800;
pub const CIPHERTEXT_LENGTH: usize = 768;
pub const SHARED_SECRET_LENGTH: usize = 32;

pub fn secretKeyVecToArray(v: Vec<u8>) -> [u8; SECRET_KEY_LENGTH] {
    let mut arr = [0u8; SECRET_KEY_LENGTH];
    arr.iter_mut().set_from(v.iter().cloned());
    arr
}

pub fn publicKeyVecToArray(v: Vec<u8>) -> [u8; PUBLIC_KEY_LENGTH] {
    let mut arr = [0u8; PUBLIC_KEY_LENGTH];
    arr.iter_mut().set_from(v.iter().cloned());
    arr
}

pub fn CiphertextVecToArray(v: Vec<u8>) -> [u8; CIPHERTEXT_LENGTH] {
    let mut arr = [0u8; CIPHERTEXT_LENGTH];
    arr.iter_mut().set_from(v.iter().cloned());
    arr
}

pub fn SharedSecretVecToArray(v: Vec<u8>) -> [u8; SHARED_SECRET_LENGTH] {
    let mut arr = [0u8; SHARED_SECRET_LENGTH];
    arr.iter_mut().set_from(v.iter().cloned());
    arr
}

#[derive(Debug, Error)]
pub enum PQCKemError {
    #[error("Length of ciphertext array is not correct.")]
    CiphertextLengthNotCorrect,
}


/// Return current used algorithm
pub fn curr_alg() -> oqs::kem::Algorithm {
    CURR_ALGORITHM
}

/// Key encapsulation scheme struct of liboqs
pub struct LiboqsKem {
    alg: oqs::kem::Algorithm,
    kem: oqs::kem::Kem,
}

impl core::convert::TryFrom<oqs::kem::Algorithm> for LiboqsKem {
    type Error = CryptoMaterialError;
    fn try_from(alg: oqs::kem::Algorithm) -> Result<LiboqsKem, CryptoMaterialError> {
        match LiboqsKem::new(alg) {
            Ok(kem) => Ok(kem),
            Err(_) => Err(CryptoMaterialError::DeserializationError)
        }
    }
}

impl Clone for LiboqsKem {
    fn clone(&self) -> LiboqsKem {
        LiboqsKem::new(CURR_ALGORITHM).unwrap()
    }
}

impl LiboqsKem {
    /// Create a new Liboqs key encapsulation object
    pub fn new(alg: oqs::kem::Algorithm) -> Result<Self, CryptoMaterialError> {
        oqs::init();
        let kem = oqs::kem::Kem::try_from(alg).unwrap();
        Ok(Self { alg, kem })
    }
}

/// This type should be used to deserialize a received private key
#[derive(Clone, DeserializeKey, SilentDisplay, SilentDebug, SerializeKey)]
pub struct PrivateKey {
    LENGTH: usize,
    KEM: LiboqsKem,
    KEY: oqs::kem::SecretKey
}

/// This type should be used to deserialize a received public key
#[derive(Clone, SerializeKey, DeserializeKey)]
pub struct PublicKey {
    LENGTH: usize,
    KEM: LiboqsKem,
    KEY: oqs::kem::PublicKey
}

//
// Handy implementations
// =====================
//

impl PrivateKey {
    /// Construct a private key
    pub fn new(bytes_param: &[u8]) -> Result<Self, CryptoMaterialError> {
        let kem = LiboqsKem::try_from(CURR_ALGORITHM).unwrap();
        Ok(PrivateKey {
            LENGTH: kem.kem.length_secret_key(),
            KEM: kem.clone(),
            KEY: kem.kem.secret_key_from_bytes(bytes_param).unwrap().to_owned()
        })
    }

    /// Construct a private key from an OQS SecretKey type
    pub fn new_from_oqs(sk: &oqs::kem::SecretKey) -> Result<Self, CryptoMaterialError> {
        let kem = LiboqsKem::try_from(CURR_ALGORITHM).unwrap();
        Ok(PrivateKey {
            LENGTH: kem.kem.length_secret_key(),
            KEM: kem.clone(),
            KEY: (*sk).clone()
        })
    }

    /// Serialize an PrivateKey
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        secretKeyVecToArray(self.KEY.clone().into_vec())
    }

    /// Deserialize an Private without any value check
    fn from_bytes_unchecked(bytes: &[u8]) -> Result<PrivateKey, CryptoMaterialError> {
        let kem = LiboqsKem::try_from(CURR_ALGORITHM).unwrap();
        match PrivateKey::new(bytes) {
            Ok(private_key) => Ok(private_key),
            Err(_) => Err(CryptoMaterialError::DeserializationError)
        }
    }

    /// Decapsulate provided ciphertext to get the shared secret
    pub fn decapsulate(&self, ct: &oqs::kem::Ciphertext) -> oqs::kem::SharedSecret {
        let secret_key: &oqs::kem::SecretKey = &self.KEY;
        let kem = self.KEM.kem.decapsulate(
            oqs::kem::SecretKeyRef::from(secret_key),
            oqs::kem::CiphertextRef::from(ct)
        ).unwrap();
        kem.clone()
    }

    /// Decapsulate provided raw ciphertext to get the shared secret
    pub fn decapsulate_from_raw(&self, ct: &[u8]) -> oqs::kem::SharedSecret {
        let ct = self.KEM.kem.ciphertext_from_bytes(ct)
            .ok_or(PQCKemError::CiphertextLengthNotCorrect)
            .unwrap();
        self.decapsulate(&ct.to_owned().clone())
    }
}

impl PublicKey {
    /// Construct a PublicKey
    pub fn new(bytes_param: &[u8]) -> Result<Self, CryptoMaterialError> {
        let kem = LiboqsKem::try_from(CURR_ALGORITHM).unwrap();
        Ok(PublicKey {
            LENGTH: kem.kem.length_public_key(),
            KEM: kem.clone(),
            KEY: kem.kem.public_key_from_bytes(bytes_param).unwrap().to_owned()
        })
    }

    /// Construct a PublicKey from OQS PublicKey type
    pub fn new_from_oqs(pk: &oqs::kem::PublicKey) -> Result<Self, CryptoMaterialError> {
        let kem = LiboqsKem::try_from(CURR_ALGORITHM).unwrap();
        Ok(PublicKey {
            LENGTH: kem.kem.length_public_key(),
            KEM: kem.clone(),
            KEY: (*pk).clone()
        })
    }

    /// Serialize a PublicKey
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        publicKeyVecToArray(self.KEY.clone().into_vec())
    }

    /// Deserialize a PublicKey without any value check
    pub(crate) fn from_bytes_unchecked(bytes: &[u8]) -> Result<PublicKey, CryptoMaterialError> {
        let kem = LiboqsKem::try_from(CURR_ALGORITHM);
        match PublicKey::new(bytes) {
            Ok(public_key) => Ok(public_key),
            Err(_) => Err(CryptoMaterialError::DeserializationError)
        }
    }

    /// Encapsulate using the public key to get ciphertext (sent to remote end) and shared secret (stored locally)
    pub fn encapsulate(&self) -> (oqs::kem::Ciphertext, oqs::kem::SharedSecret) {
        let public_key: &oqs::kem::PublicKey = &self.KEY;
        let (ct, ss) = self.KEM.kem.encapsulate(oqs::kem::PublicKeyRef::from(public_key)).unwrap();
        (
            ct.clone(),
            ss.clone()
        )
    }
}

//
// Traits implementations
// ======================
//

// private key part

impl std::convert::From<[u8; SECRET_KEY_LENGTH]> for PrivateKey {
    fn from(private_key_bytes: [u8; SECRET_KEY_LENGTH]) -> Self {
        PrivateKey::new(&private_key_bytes).unwrap()
    }
}

impl std::convert::TryFrom<&[u8]> for PrivateKey {
    type Error = traits::CryptoMaterialError;

    fn try_from(private_key_bytes: &[u8]) -> Result<Self, Self::Error> {
        let private_key_bytes: [u8; SECRET_KEY_LENGTH] = private_key_bytes
            .try_into()
            .map_err(|_| traits::CryptoMaterialError::DeserializationError)?;
        Ok(PrivateKey::new(&private_key_bytes).unwrap())
    }
}

impl traits::PrivateKey for PrivateKey {
    type PublicKeyMaterial = PublicKey;
}

impl traits::Uniform for PrivateKey {
    fn generate<R>(rng: &mut R) -> Self
    where
        R: ::rand::RngCore + ::rand::CryptoRng,
    {
        let kem = LiboqsKem::try_from(CURR_ALGORITHM);
        let mut bytes = [0u8; SECRET_KEY_LENGTH];
        rng.fill_bytes(&mut bytes);
        PrivateKey::new(&bytes).unwrap()
    }
}

impl ValidCryptoMaterial for PrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &PrivateKey) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

// public key part

impl std::convert::From<[u8; PUBLIC_KEY_LENGTH]> for PublicKey {
    fn from(public_key_bytes: [u8; PUBLIC_KEY_LENGTH]) -> Self {
        PublicKey::new(&public_key_bytes).unwrap()
    }    
}

impl std::convert::TryFrom<&[u8]> for PublicKey {
    type Error = traits::CryptoMaterialError;

    fn try_from(public_key_bytes: &[u8]) -> Result<Self, Self::Error> {
        let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = public_key_bytes
            .try_into()
            .map_err(|_| traits::CryptoMaterialError::WrongLengthError)?;
        Ok(PublicKey::new(&public_key_bytes).unwrap())
    }
}

/// 根据私钥生成公钥，在Ed25519的实现里实现了这个trait
/// 但liboqs的实现中是使用keypair一次性生成公私钥
impl From<&PrivateKey> for PublicKey {
    fn from(private_key: &PrivateKey) -> Self {
        let sig = LiboqsKem::try_from(CURR_ALGORITHM);
        let bytes = [0u8; PUBLIC_KEY_LENGTH];
        let public: PublicKey = PublicKey::new(&bytes).unwrap();
        public
    }
}

impl traits::PublicKey for PublicKey {
    type PrivateKeyMaterial = PrivateKey;
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for PublicKey {}

impl std::hash::Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_pubkey = self.to_bytes();
        state.write(&encoded_pubkey);
    }
}

impl traits::ValidCryptoMaterial for PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.KEY.clone().into_vec()))
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", self)
    }
}

/// Generate a keypair
pub fn keypair() -> (PrivateKey, PublicKey) {
    let kemalg = oqs::kem::Kem::new(curr_alg()).unwrap();
    let (pk, sk) = kemalg.keypair().unwrap();
    (PrivateKey::new_from_oqs(&sk).unwrap(), PublicKey::new_from_oqs(&pk).unwrap())
}