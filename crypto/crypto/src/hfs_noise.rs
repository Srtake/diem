//! This file implements Hybrid Forward Secrecy version of Noise IK protocol.
//! The specification of HFS Noise protocol framework can see [here](https://github.com/noiseprotocol/noise_hfs_spec/blob/master/output/noise_hfs.pdf).

// #![allow(clippy::integer_arithmetic)]

use crate::{hash::HashValue, hkdf::Hkdf, traits::Uniform as _, x25519, pqc_kem};
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, AeadInPlace, NewAead, Payload},
    Aes256Gcm,
};
use sha2::Digest;
use std::{
    convert::TryFrom as _,
    io::{Cursor, Read as _, Write as _},
};
use thiserror::Error;
use oqs;

//
// Useful constants
// ----------------
//

/// A noise message cannot be larger than 65535 bytes as per the specification.
pub const MAX_SIZE_NOISE_MSG: usize = 65535;

/// The authentication tag length of AES-GCM.
pub const AES_GCM_TAGLEN: usize = 16;

/// The only Noise handshake protocol that we implement in this file.
const PROTOCOL_NAME: &[u8] = b"Noise_IKhfs_25519_PQC_AESGCM_SHA256\0\0\0\0";

/// The nonce size we use for AES-GCM.
const AES_NONCE_SIZE: usize = 12;

/// A handy const fn to get the expanded size of a plaintext after encryption
pub const fn encrypted_len(plaintext_len: usize) -> usize {
    plaintext_len + AES_GCM_TAGLEN
}

/// A handy const fn to get the size of a plaintext from a ciphertext size
pub const fn decrypted_len(ciphertext_len: usize) -> usize {
    ciphertext_len - AES_GCM_TAGLEN
}

/// A handy const fn to get the size of the first handshake message
pub const fn handshake_init_msg_len(payload_len: usize) -> usize {
    // e
    let e_len = x25519::PUBLIC_KEY_SIZE;
    // encrypted s
    let enc_s_len = encrypted_len(x25519::PUBLIC_KEY_SIZE);
    // encrypted e1
    let enc_e1_len = encrypted_len(pqc_kem::PUBLIC_KEY_LENGTH);
    // encrypted payload
    let enc_payload_len = encrypted_len(payload_len);
    //
    e_len + enc_s_len + enc_e1_len + enc_payload_len
}

/// A handy const fn to get the size of the second handshake message
pub const fn handshake_resp_msg_len(payload_len: usize) -> usize {
    // e
    let e_len = x25519::PUBLIC_KEY_SIZE;
    // encrypted ekem1
    let enc_ekem1_len = encrypted_len(pqc_kem::CIPHERTEXT_LENGTH);
    // encrypted payload
    let enc_payload_len = encrypted_len(payload_len);
    //
    e_len + enc_ekem1_len + enc_payload_len
}

/// This implementation relies on the fact that the hash function used has a 256-bit output
#[rustfmt::skip]
const _: [(); 32] = [(); HashValue::LENGTH];

//
// Errors
// ------
//

/// A NoiseError enum represents the different types of error that noise can return to users of the crate
#[derive(Debug, Error)]
pub enum HfsNoiseError {
    /// the received message is too short to contain the expected data
    #[error("noise: the received message is too short to contain the expected data")]
    MsgTooShort,

    /// HKDF has failed (in practice there is no reason for HKDF to fail)
    #[error("noise: HKDF has failed")]
    Hkdf,

    /// encryption has failed (in practice there is no reason for encryption to fail)
    #[error("noise: encryption has failed")]
    Encrypt,

    /// could not decrypte the received data (most likely the data was tampered with)
    #[error("noise: could not decrypt the received data")]
    Decrypt,

    /// the public key received is of the wrong format
    #[error("noise: the public key received is of the wrong format")]
    WrongPublicKeyReceived,
    
    /// session was closed due to decrypt error
    #[error("noise: session was closed due to decrypt error")]
    SessionClosed,

    /// the payload that we are trying to send is too large
    #[error("noise: the payload that we are trying to send is too large")]
    PayloadTooLarge,

    /// the message we received is too large
    #[error("noise: the message we received is too large")]
    ReceivedMsgTooLarge,

    /// the response buffer passed as argument is too small
    #[error("noise: the response buffer passed as argument is too small")]
    ResponseBufferTooSmall,

    /// the nonce exceeds the maximum u64 value (in practice this should not happen)
    #[error("noise: the nonce exceeds the maximum u64 value")]
    NonceOverflow,
}

//
// helpers
// -------
//

fn hash(data: &[u8]) -> Vec<u8> {
    sha2::Sha256::digest(data).to_vec()
}

fn hkdf(ck: &[u8], dh_output: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), HfsNoiseError> {
    let dh_output = dh_output.unwrap_or_else(|| &[]);
    let hkdf_output = if dh_output.is_empty() {
        Hkdf::<sha2::Sha256>::extract_then_expand_no_ikm(Some(ck), None, 64)
    } else {
        Hkdf::<sha2::Sha256>::extract_then_expand(Some(ck), dh_output, None, 64)
    };

    let hkdf_output = hkdf_output.map_err(|_| HfsNoiseError::Hkdf)?;
    let (k1, k2) = hkdf_output.split_at(32);
    Ok((k1.to_vec(), k2.to_vec()))
}

fn mix_hash(h: &mut Vec<u8>, data: &[u8]) {
    h.extend_from_slice(data);
    *h = hash(h);
}

fn mix_key(ck: &mut Vec<u8>, dh_output: &[u8]) -> Result<Vec<u8>, HfsNoiseError> {
    let (new_ck, k) = hkdf(ck, Some(dh_output))?;
    *ck = new_ck;
    Ok(k)
}

//
// Noise implementation
// --------------------
//

/// A key holder structure used for both initiators and responders.
#[derive(Debug)]
pub struct HfsNoiseConfig {
    private_key: x25519::PrivateKey,
    public_key: x25519::PublicKey,
}

/// Refer to the Noise protocol framework specification in order to understand these fields.
#[cfg_attr(test, derive(Clone))]
pub struct HfsInitiatorHandshakeState {
    /// rolling hash
    h: Vec<u8>,
    /// chaining key
    ck: Vec<u8>,
    /// x25519 ephemeral key
    e: x25519::PrivateKey,
    /// pqc ephemeral key
    e1: pqc_kem::PrivateKey,
    /// remote static key used
    rs: x25519::PublicKey,
}

/// Refer to the Noise protocol framework specification in order to understand these fields.
#[cfg_attr(test, derive(Clone))]
pub struct HfsResponderHandshakeState {
    /// rolling hash
    h: Vec<u8>,
    /// chaining key
    ck: Vec<u8>,
    /// remote static key received
    rs: x25519::PublicKey,
    /// remote x25519 ephemeral key received
    re: x25519::PublicKey,
    /// remote pqc ephemeral key received
    re1: pqc_kem::PublicKey,
}

impl HfsNoiseConfig {
    /// A peer must create a HfsNoiseConfig through this function before being able to connect with other peers
    pub fn new(private_key: x25519::PrivateKey) -> Self {
        // we could take a public key as argument, and it would be faster, but this is cleaner
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }

    /// Handy getter to access the configuration's public key
    pub fn public_key(&self) -> x25519::PublicKey {
        self.public_key
    }

    //
    // Initiator
    // ---------

    /// An initiator can use this function to initiate a handshake with a known responder.
    pub fn initiate_connection(
        &self,
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
        prologue: &[u8],
        remote_public: x25519::PublicKey,
        payload: Option<&[u8]>,
        response_buffer: &mut [u8],
    ) -> Result<HfsInitiatorHandshakeState, HfsNoiseError> {
        // checks
        let payload_len = payload.map(<[u8]>::len).unwrap_or(0);
        let buffer_size_required = handshake_init_msg_len(payload_len);
        if buffer_size_required > MAX_SIZE_NOISE_MSG {
            return Err(HfsNoiseError::PayloadTooLarge);
        }
        if response_buffer.len() < buffer_size_required {
            return Err(HfsNoiseError::ResponseBufferTooSmall);
        }
        // initalize
        let mut h = PROTOCOL_NAME.to_vec();
        let mut ck = PROTOCOL_NAME.to_vec();
        let rs = remote_public; // for naming consistency with the specification
        mix_hash(&mut h, &prologue);
        mix_hash(&mut h, rs.as_slice());

        // -> e
        let e = x25519::PrivateKey::generate(rng);
        let e_pub = e.public_key();

        mix_hash(&mut h, e_pub.as_slice());
        let mut response_buffer = Cursor::new(response_buffer);
        response_buffer
            .write(e_pub.as_slice())
            .map_err(|_| HfsNoiseError::ResponseBufferTooSmall)?;
        
        // -> es
        let dh_output = e.diffie_hellman(&rs);
        let k = mix_key(&mut ck, &dh_output)?;
        println!("[Initiator] -> es finished, key = {:?}", k);

        // -> e1
        let aead = Aes256Gcm::new(GenericArray::from_slice(&k));
        let (e1, e1_pub) = pqc_kem::keypair();

        let msg_and_ad = Payload {
            msg: &e1_pub.to_bytes(),
            aad: &h,
        };
        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let encrypted_e1 = aead.encrypt(nonce, msg_and_ad)
            .map_err(|_| HfsNoiseError::Encrypt)?;
        println!("[Initiator] encryption of e1 finished. ciphertext = {:?}, h = {:?}", encrypted_e1, h);
        
        mix_hash(&mut h, &encrypted_e1);
        response_buffer.write(&e1_pub.to_bytes())
            .map_err(|_| HfsNoiseError::ResponseBufferTooSmall)?;
        
        // -> s
        let aead = Aes256Gcm::new(GenericArray::from_slice(&k));

        let msg_and_ad = Payload {
            msg: self.public_key.as_slice(),
            aad: &h,
        };
        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let encrypted_static = aead 
            .encrypt(nonce, msg_and_ad)
            .map_err(|_| HfsNoiseError::Encrypt)?;
        
        mix_hash(&mut h, &encrypted_static);
        response_buffer
            .write(&encrypted_static)
            .map_err(|_| HfsNoiseError::ResponseBufferTooSmall)?;
        
        // -> ss
        let dh_output = self.private_key.diffie_hellman(&rs);
        let k = mix_key(&mut ck, &dh_output)?;

        // -> payload
        let aead = Aes256Gcm::new(GenericArray::from_slice(&k));
        let msg_and_ad = Payload {
            msg: payload.unwrap_or_else(|| &[]),
            aad: &h
        };
        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let encrypted_payload = aead
            .encrypt(nonce, msg_and_ad)
            .map_err(|_| HfsNoiseError::Encrypt)?;
        
        mix_hash(&mut h, &encrypted_payload);

        response_buffer
            .write(&encrypted_payload)
            .map_err(|_| HfsNoiseError::ResponseBufferTooSmall)?;
        
        // return
        let handshake_state = HfsInitiatorHandshakeState { h, ck, e, e1, rs };
        Ok(handshake_state)
    }

    /// A client can call this to finalize a connection, after receiving an answer from a server
    pub fn finalize_connection(
        &self,
        handshake_state: HfsInitiatorHandshakeState,
        received_message: &[u8],
    ) -> Result<(Vec<u8>, HfsNoiseSession), HfsNoiseError> {
        // checks
        if received_message.len() > MAX_SIZE_NOISE_MSG {
            return Err(HfsNoiseError::ReceivedMsgTooLarge);
        }
        // retrieve handshake state
        let HfsInitiatorHandshakeState {
            mut h,
            mut ck,
            e,
            e1,
            rs,
        } = handshake_state;

        // <- e
        let mut re = [0u8; x25519::PUBLIC_KEY_SIZE];
        let mut cursor = Cursor::new(received_message);
        cursor
            .read_exact(&mut re)
            .map_err(|_| HfsNoiseError::MsgTooShort)?;
        mix_hash(&mut h, &re);
        let re = x25519::PublicKey::from(re);

        // <- ee
        let dh_output = e.diffie_hellman(&re);
        let k = mix_key(&mut ck, &dh_output)?;

        // <- ekem1
        let aead = Aes256Gcm::new(GenericArray::from_slice(&k));
        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let mut received_encrypted_rekem1 = [0u8; pqc_kem::PUBLIC_KEY_LENGTH];
        cursor.read_exact(&mut received_encrypted_rekem1)
            .map_err(|_| HfsNoiseError::MsgTooShort)?;
        let ct_and_ad = Payload {
            msg: &received_encrypted_rekem1,
            aad: &h,
        };
        let received_rekem1 = aead
            .decrypt(nonce, ct_and_ad)
            .map_err(|_| HfsNoiseError::Decrypt)?;
        mix_hash(&mut h, &received_encrypted_rekem1);
        let rekem1 = pqc_kem::SharedSecretVecToArray(
            e1.decapsulate_from_raw(&pqc_kem::CiphertextVecToArray(received_rekem1)).clone().into_vec());
        let k = mix_key(&mut ck, &rekem1)?;

        // <- se
        let dh_output = self.private_key.diffie_hellman(&re);
        let k = mix_key(&mut ck, &dh_output)?;

        // <- payload
        let offset = cursor.position() as usize;
        let received_encrypted_payload = &cursor.into_inner()[offset..];

        let aead = Aes256Gcm::new(GenericArray::from_slice(&k));

        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let ct_and_ad = Payload {
            msg: received_encrypted_payload,
            aad: &h,
        };
        let received_payload = aead
            .decrypt(nonce, ct_and_ad)
            .map_err(|_| HfsNoiseError::Decrypt)?;
        
        // split
        let (k1, k2) = hkdf(&ck, None)?;
        let session = HfsNoiseSession::new(k1, k2, rs);

        //
        Ok((received_payload, session))
    }

    //
    // Responder
    // ---------
    // There are two ways to use this API:
    // - either use `parse_client_init_message()` followed by `respond_to_client()`
    // - or use the all-in-one `respond_to_client_and_finalize()`
    //
    // the reason for the first deconstructed API is that we might want to do
    // some validation of the received initiator's public key which might
    //

    /// A responder can accept a connection by first parsing an initiator message.
    /// The function respond_to_client is usually called after this to respond to the initiator
    pub fn parse_client_init_message(
        &self,
        prologue: &[u8],
        received_message: &[u8],
    ) -> Result<
        (
            x25519::PublicKey,            // initiator's public key
            HfsResponderHandshakeState,   // state to be used in respond_to_client
            Vec<u8>,                      // payload received
        ),
        HfsNoiseError,
    > {
        // checks
        if received_message.len() > MAX_SIZE_NOISE_MSG {
            return Err(HfsNoiseError::ReceivedMsgTooLarge);
        }
        // initialize
        let mut h = PROTOCOL_NAME.to_vec();
        let mut ck = PROTOCOL_NAME.to_vec();
        mix_hash(&mut h, prologue);
        mix_hash(&mut h, self.public_key.as_slice());

        // buffer message received
        let mut cursor = Cursor::new(received_message);

        // <- e
        let mut re = [0u8; x25519::PUBLIC_KEY_SIZE];
        cursor.read_exact(&mut re)
            .map_err(|_| HfsNoiseError::MsgTooShort)?;
        mix_hash(&mut h, &re);
        let re = x25519::PublicKey::from(re);
        println!("<- e finished.");

        // <- es
        let dh_output = self.private_key.diffie_hellman(&re);
        let k = mix_key(&mut ck, &dh_output)?;
        println!("<- es finished, key = {:?}", k);

        // <- e1
        let aead = Aes256Gcm::new(GenericArray::from_slice(&k));
        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let mut encrypted_remote_e1 = [0u8; pqc_kem::PUBLIC_KEY_LENGTH + AES_GCM_TAGLEN];
        cursor.read_exact(&mut encrypted_remote_e1)
            .map_err(|_| HfsNoiseError::MsgTooShort)?;
        println!("receive ciphertext = {:?}, h = {:?}", encrypted_remote_e1, h);
        let ct_and_ad = Payload {
            msg: &encrypted_remote_e1,
            aad: &h
        };
        let re1 = aead.decrypt(nonce, ct_and_ad)
            .map_err(|_| HfsNoiseError::Decrypt)?;
        let re1 = pqc_kem::PublicKey::try_from(re1.as_slice())
            .map_err(|_| HfsNoiseError::WrongPublicKeyReceived)?;
        mix_hash(&mut h, &encrypted_remote_e1);
        println!("<- e1 finished.");

        // <- s
        let mut encrypted_remote_static = [0u8; x25519::PUBLIC_KEY_SIZE + AES_GCM_TAGLEN];
        cursor
            .read_exact(&mut encrypted_remote_static)
            .map_err(|_| HfsNoiseError::MsgTooShort)?;
        
        let aead = Aes256Gcm::new(GenericArray::from_slice(&k));

        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let ct_and_ad = Payload {
            msg: &encrypted_remote_static,
            aad: &h,
        };
        let rs = aead.decrypt(nonce, ct_and_ad)
            .map_err(|_| HfsNoiseError::Decrypt)?;
        let rs = x25519::PublicKey::try_from(rs.as_slice())
            .map_err(|_| HfsNoiseError::WrongPublicKeyReceived)?;
        mix_hash(&mut h, &encrypted_remote_static);
        println!("<- s finished.");

        // <- ss
        let dh_output = self.private_key.diffie_hellman(&rs);
        let k = mix_key(&mut ck, &dh_output)?;

        // <- payload
        let offset = cursor.position() as usize;
        let received_encrypted_payload = &cursor.into_inner()[offset..];

        let aead = Aes256Gcm::new(GenericArray::from_slice(&k));
        
        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let ct_and_ad = Payload {
            msg: received_encrypted_payload,
            aad: &h,
        };
        let received_payload = aead.decrypt(nonce, ct_and_ad)
            .map_err(|_| HfsNoiseError::Decrypt)?;
        mix_hash(&mut h, received_encrypted_payload);
        println!("<- payload finished.");

        // return 
        let handshake_state = HfsResponderHandshakeState { h, ck, rs, re, re1 };
        Ok((rs, handshake_state, received_payload))
    }

    /// A responder can respond to an initiator by calling this function with the state obtained,
    /// after calling parse_client_init_message
    pub fn respond_to_client(
        &self,
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
        handshake_state: HfsResponderHandshakeState,
        payload: Option<&[u8]>,
        response_buffer: &mut [u8],
    ) -> Result<HfsNoiseSession, HfsNoiseError> {
        // checks
        let payload_len = payload.map(<[u8]>::len).unwrap_or(0);
        let buffer_size_required = handshake_resp_msg_len(payload_len);
        if buffer_size_required > MAX_SIZE_NOISE_MSG {
            return Err(HfsNoiseError::PayloadTooLarge);
        }
        if response_buffer.len() < buffer_size_required {
            return Err(HfsNoiseError::ResponseBufferTooSmall);
        }

        // retrieve handshake state
        let HfsResponderHandshakeState {
            mut h,
            mut ck,
            rs,
            re,
            re1
        } = handshake_state;

        // -> e
        let e = x25519::PrivateKey::generate(rng);
        let e_pub = e.public_key();

        mix_hash(&mut h, e_pub.as_slice());
        let mut response_buffer = Cursor::new(response_buffer);
        response_buffer.write(e_pub.as_slice())
            .map_err(|_| HfsNoiseError::ResponseBufferTooSmall)?;

        // -> ee
        let dh_output = e.diffie_hellman(&re);
        let k = mix_key(&mut ck, &dh_output)?;

        // -> ekem1
        let (ekem1, shared_secret) = re1.encapsulate();
        let aead = Aes256Gcm::new(GenericArray::from_slice(&k));
        let ekem1 = pqc_kem::CiphertextVecToArray(ekem1.clone().into_vec());
        let shared_secret = pqc_kem::SharedSecretVecToArray(shared_secret.clone().into_vec());
        let msg_and_ad = Payload {
            msg: &ekem1,
            aad: &h,
        };
        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let encrypted_ekem1 = aead.encrypt(nonce, msg_and_ad)
            .map_err(|_| HfsNoiseError::Encrypt)?;
        mix_hash(&mut h, &encrypted_ekem1);
        response_buffer.write(&encrypted_ekem1)
            .map_err(|_| HfsNoiseError::Encrypt)?;
        let k = mix_key(&mut ck, &shared_secret);

        // -> se
        let dh_output = e.diffie_hellman(&rs);
        let k = mix_key(&mut ck, &dh_output)?;

        // -> payload
        let aead = Aes256Gcm::new(GenericArray::from_slice(&k));
        let msg_and_ad = Payload {
            msg: payload.unwrap_or_else(|| &[]),
            aad: &h,
        };
        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let encrypted_payload = aead.encrypt(nonce, msg_and_ad)
            .map_err(|_| HfsNoiseError::Encrypt)?;
        mix_hash(&mut h, &encrypted_payload);
        response_buffer.write(&encrypted_payload)
            .map_err(|_| HfsNoiseError::ResponseBufferTooSmall)?;
        
        // split
        let (k1, k2) = hkdf(&ck, None)?;
        let session = HfsNoiseSession::new(k2, k1, rs);

        //
        Ok(session)
    }

    /// This function is a one-call that replaces calling the two functions parse_client_init_message
    /// and respond_to_client consecutively
    pub fn respond_to_client_and_finalize(
        &self,
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
        prologue: &[u8],
        received_message: &[u8],
        payload: Option<&[u8]>,
        response_buffer: &mut [u8],
    ) -> Result<
        (
            Vec<u8>,           // the payload the initiator sent
            HfsNoiseSession,   // The created session
        ),
        HfsNoiseError,
    > {
        let (_, handshake_state, received_payload) = 
            self.parse_client_init_message(prologue, received_message)?;
        let session = self.respond_to_client(rng, handshake_state, payload, response_buffer)?;
        Ok((received_payload, session))
    }
}

//
// Post-Handshake
// --------------

/// A NoiseSession is produced after a successful Noise handshake, and can be used to encrypt and decrypt messages to the other peer.
#[cfg_attr(test, derive(Clone))]
pub struct HfsNoiseSession {
    /// a session can be marked as invalid if it has seen a decryption failure
    valid: bool,
    /// the public key of the other peer
    remote_public_key: x25519::PublicKey,
    /// key used to encrypt messages to the other peer
    write_key: Vec<u8>,
    /// associated nonce (in practice the maximum u64 value cannot be reached)
    write_nonce: u64,
    /// key used to decrypt messages received from the other peer
    read_key: Vec<u8>,
    /// associated nonce (in practice the maximum u64 value cannot be reached)
    read_nonce: u64,
}

impl HfsNoiseSession {
    fn new(write_key: Vec<u8>, read_key: Vec<u8>, remote_public_key: x25519::PublicKey) -> Self {
        Self {
            valid: true,
            remote_public_key,
            write_key,
            write_nonce: 0,
            read_key,
            read_nonce: 0,
        }
    }

    /// create a dummy session with 0 keys
    #[cfg(any(test, feature = "fuzzing"))]
    pub fn new_for_testing() -> Self {
        Self::new(
            vec![0u8; 32],
            vec![0u8; 32],
            [0u8; x25519::PUBLIC_KEY_SIZE].into(),
        )
    }

    /// obtain remote static public key
    pub fn get_remote_static(&self) -> x25519::PublicKey {
        self.remote_public_key
    }

    /// encrypts a message for the other peers (post-handshake)
    /// the function encrypts in place, and returns the authentication tag as result
    pub fn write_message_in_place(&mut self, message: &mut [u8]) -> Result<Vec<u8>, HfsNoiseError> {
        // checks
        if !self.valid {
            return Err(HfsNoiseError::SessionClosed);
        }
        if message.len() > MAX_SIZE_NOISE_MSG - AES_GCM_TAGLEN {
            return Err(HfsNoiseError::PayloadTooLarge);
        }

        // encrypt in place
        let aead = Aes256Gcm::new(GenericArray::from_slice(&self.write_key));
        let mut nonce = [0u8; 4].to_vec();
        nonce.extend_from_slice(&self.write_nonce.to_be_bytes());
        let nonce = GenericArray::from_slice(&nonce);

        let authentication_tag = aead.encrypt_in_place_detached(nonce, b"", message)
            .map_err(|_| HfsNoiseError::Encrypt)?;
        
        // increment nonce
        self.write_nonce = self.write_nonce.checked_add(1)
            .ok_or(HfsNoiseError::NonceOverflow)?;
        
        // return a subslice without the authentication tag
        Ok(authentication_tag.to_vec())
    }

    /// decrypts a message from the other peer (post-handshake)
    /// the function decrypts in place, and returns a subslice without the auth tag
    pub fn read_message_in_place<'a>(
        &mut self,
        message: &'a mut [u8],
    ) -> Result<&'a [u8], HfsNoiseError> {
        // checks
        if !self.valid {
            return Err(HfsNoiseError::SessionClosed);
        }
        if message.len() > MAX_SIZE_NOISE_MSG {
            self.valid = false;
            return Err(HfsNoiseError::ReceivedMsgTooLarge);
        }
        if message.len() < AES_GCM_TAGLEN {
            self.valid = false;
            return Err(HfsNoiseError::ResponseBufferTooSmall);
        }

        // decrypt in place
        let aead = Aes256Gcm::new(GenericArray::from_slice(&self.read_key));

        let mut nonce = [0u8; 4].to_vec();
        nonce.extend_from_slice(&self.read_nonce.to_be_bytes());
        let nonce = GenericArray::from_slice(&nonce);

        let (buffer, authentication_tag) = message.split_at_mut(message.len() - AES_GCM_TAGLEN);
        let authentication_tag = GenericArray::from_slice(authentication_tag);
        aead.decrypt_in_place_detached(nonce, b"", buffer, authentication_tag)
            .map_err(|_| {
                self.valid = false;
                HfsNoiseError::Decrypt
            })?;
        
        // increment nonce
        self.read_nonce = self.read_nonce.checked_add(1)
            .ok_or(HfsNoiseError::NonceOverflow)?;
        
        // return a subslice of the buffer representing the decrypted plaintext
        Ok(buffer)
    }
}

impl std::fmt::Debug for HfsNoiseSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HfsNoiseSession[...]")
    }
}