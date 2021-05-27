//! This file implements a pure post-quantum version of NoiseIK (we call it Noise_IK_PQCRYPTO_AESGCM_SHA256).
//! This means that only the parts that we care about (the IK handshake) are implemented,
//! and crypto algorithms used in this implementation are ALL post-quantum key encapsulation mechanisms (KEM).
#![allow(clippy::integer_arithmetic)]

use crate::{hash::HashValue, hkdf::Hkdf, pqc_kem, traits::Uniform as _};
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

//
// Useful constants
// ----------------
//

/// A noise message cannot be larger than 65535 bytes as per the specification.
/// Note that key materials in some algorithms may exceed this limit.
pub const MAX_SIZE_NOISE_MSG: usize = 65535;

/// The authentication tag length of AES-GCM.
pub const AES_GCM_TAGLEN: usize = 16;

/// The only Noise handshake protocol that we implement in this file.
const PROTOCOL_NAME: &[u8] = b"Noise_IK_PQCRYPTO_AESGCM_SHA256\0\0\0\0";

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
    let e_len = pqc_kem::PUBLIC_KEY_LENGTH;
    // encrypted s
    let enc_s_len = encrypted_len(pqc_kem::PUBLIC_KEY_LENGTH);
    // encrypted payload
    let enc_payload_len = encrypted_len(payload_len);
    //
    e_len + enc_s_len + enc_payload_len
}

/// A handy const fn to get the size of the second handshake message
pub const fn handshake_resp_msg_len(payload_len: usize) -> usize {
    // e
    let e_len = pqc_kem::PUBLIC_KEY_LENGTH;
    // encrypted payload
    let enc_payload_len = encrypted_len(payload_len);
    //
    e_len + enc_payload_len
}

/// This implementation relies on the fact that the hash function used has a 256-bit output
#[rustfmt::skip]
const _: [(); 32] = [(); HashValue::LENGTH];

//
// Errors
// ------
//

// A NoiseError enum represents the different types of error that noise can return to users of the crate
#[derive(Debug, Error)]
pub enum PQNoiseError {
    /// the received message is too short to contain the expected data
    #[error("noise: the received message is too short to contain the expected data")]
    MsgTooShort,

    /// HKDF has failed (in practice there is no reason for HKDF to fail)
    #[error("noise: HKDF has failed")]
    Hkdf,

    /// encapsulation has failed
    #[error("noise: encapsulation has failed")]
    Encapsulation,

    /// decapsulation has failed
    #[error("noise: decapsulation has failed")]
    Decapsulation,

    /// encryption has failed (in practice there is no reason for encryption to fail)
    #[error("noise: encryption has failed")]
    Encrypt,

    /// could not decrypt the received data (most likely the data was tampered with)
    #[error("noise: could not decrypt the received data")]
    Decrypt,

    /// the public key received is of the wrong format
    #[error("noise: the public key received is of the wrong format")]
    WrongPublicKeyReceived,

    /// session was close due to decrypt error
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

fn hkdf(ck: &[u8], dh_output: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), PQNoiseError> {
    let dh_output = dh_output.unwrap_or_else(|| &[]);
    let hkdf_output = if dh_output.is_empty() {
        Hkdf::<sha2::Sha256>::extract_then_expand_no_ikm(Some(ck), None, 64)
    } else {
        Hkdf::<sha2::Sha256>::extract_then_expand(Some(ck), dh_output, None, 64)
    };

    let hkdf_output = hkdf_output.map_err(|_| PQNoiseError::Hkdf)?;
    let (k1, k2) = hkdf_output.split_at(32);
    Ok((k1.to_vec(), k2.to_vec()))
}

fn mix_hash(h: &mut Vec<u8>, data: &[u8]) {
    h.extend_from_slice(data);
    *h = hash(h);
}

fn mix_key(ck: &mut Vec<u8>, dh_output: &[u8]) -> Result<Vec<u8>, PQNoiseError> {
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
pub struct PQNoiseConfig {
    private_key: pqc_kem::PrivateKey,
    public_key: pqc_kem::PublicKey,
}

/// Refer to the Noise protocol framework specification in order to understand these fields.
#[cfg_attr(test, derive(Clone))]
pub struct PQInitiatorHandshakeState {
    /// rolling hash
    h: Vec<u8>,
    /// chaining key
    ck: Vec<u8>,
    /// ephemeral key
    e: pqc_kem::PrivateKey,
    /// remote static key used
    rs: pqc_kem::PublicKey,
}

/// Refer to the Noise protocol framework specification in order to understand these fields.
#[cfg_attr(test, derive(Clone))]
pub struct PQResponderHandshakeState {
    /// rolling hash
    h: Vec<u8>,
    /// chaining key
    ck: Vec<u8>,
    /// remote static key received
    rs: pqc_kem::PublicKey,
    /// remote ephemeral key receiced
    re: pqc_kem::PublicKey,
}

impl PQNoiseConfig {
    /// A peer must create a NoiseConfig through this function before being able to connect with other peers.
    pub fn new(private_key: pqc_kem::PrivateKey, public_key: pqc_kem::PublicKey) -> Self {
        Self {
            private_key,
            public_key,
        }
    }

    /// Handy getter to access the configuration's public key
    pub fn public_key(&self) -> pqc_kem::PublicKey {
        self.public_key
    }

    //
    // Initiator
    // ---------

    /// An initiator can use this function to initiate a handshake with a known responder.
    pub fn initiate_connection(
        &self,
        prologue: &[u8],
        remote_public: pqc_kem::PublicKey,
        payload: Option<&[u8]>,
        response_buffer: &mut [u8],
    ) -> Result<PQInitiatorHandshakeState, PQNoiseError> {
        // checks
        let payload_len = payload.map(<[u8]>::len).unwrap_or(0);
        let buffer_size_required = handshake_init_msg_len(payload_len);
        if buffer_size_required > MAX_SIZE_NOISE_MSG {
            return Err(PQNoiseError::PayloadTooLarge);
        }
        if response_buffer.len() < buffer_size_required {
            return Err(PQNoiseError::ResponseBufferTooSmall);
        }
        // initialize
        let mut h = PROTOCOL_NAME.to_vec();
        let mut ck = PROTOCOL_NAME.to_vec();
        let rs = remote_public; // for name consistency with the specification
        mix_hash(&mut h, &prologue);
        mix_hash(&mut h, &rs.to_bytes());

        // -> e
        let (e, e_pub) = pqc_kem::keypair();
        mix_hash(&mut h, &e_pub.to_bytes());
        let mut response_buffer = Cursor::new(response_buffer);
        response_buffer
            .write(&e_pub.to_bytes())
            .map_err(|_| PQNoiseError::ResponseBufferTooSmall)?;

        // -> skem1
        let (skem1, shared_secret) = rs.encapsulate();
        let skem1 = pqc_kem::CiphertextVecToArray(skem1.clone().into_vec());
        let shared_secret = pqc_kem::SharedSecretVecToArray(shared_secret.clone().into_vec());
        mix_hash(&mut h, &skem1);
        response_buffer
            .write(&skem1)
            .map_err(|_| PQNoiseError::Encapsulation)?;
        let k = mix_key(&mut ck, &shared_secret)?;

        // -> s
        let aead = Aes256Gcm::new(GenericArray::from_slice(&k));
        let msg_and_ad = Payload {
            msg: &self.public_key.to_bytes(),
            aad: &h,
        };
        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let encrypted_static = aead
            .encrypt(nonce, msg_and_ad)
            .map_err(|_| PQNoiseError::Encrypt)?;
        mix_hash(&mut h, &encrypted_static);
        response_buffer
            .write(&encrypted_static)
            .map_err(|_| PQNoiseError::ResponseBufferTooSmall)?;

        // -> payload
        let aead = Aes256Gcm::new(GenericArray::from_slice(&k));
        let msg_and_ad = Payload {
            msg: payload.unwrap_or_else(|| &[]),
            aad: &h,
        };
        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let encrypted_payload = aead
            .encrypt(nonce, msg_and_ad)
            .map_err(|_| PQNoiseError::Encrypt)?;

        mix_hash(&mut h, &encrypted_payload);

        response_buffer
            .write(&encrypted_payload)
            .map_err(|_| PQNoiseError::ResponseBufferTooSmall)?;

        // return
        let handshake_state = PQInitiatorHandshakeState { h, ck, e, rs };
        Ok(handshake_state)
    }

    /// A client can call this to finalize a connection, after receiving an answer from a server.
    pub fn finalize_connection(
        &self,
        handshake_state: PQInitiatorHandshakeState,
        received_message: &[u8],
    ) -> Result<(Vec<u8>, PQNoiseSession), PQNoiseError> {
        // checks
        if received_message.len() > MAX_SIZE_NOISE_MSG {
            return Err(PQNoiseError::ReceivedMsgTooLarge);
        }
        let PQInitiatorHandshakeState {
            mut h,
            mut ck,
            e,
            rs,
        } = handshake_state;

        // <- ekem2
        let aead = Aes256Gcm::new(GenericArray::from_slice(&ck));
        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let mut received_encrypted_rekem2 = [0u8; pqc_kem::CIPHERTEXT_LENGTH + AES_GCM_TAGLEN];
        let mut cursor = Cursor::new(received_message);
        cursor
            .read_exact(&mut received_encrypted_rekem2)
            .map_err(|_| PQNoiseError::MsgTooShort)?;
        let ct_and_ad = Payload {
            msg: &received_encrypted_rekem2,
            aad: &h,
        };
        let received_rekem2 = aead
            .decrypt(nonce, ct_and_ad)
            .map_err(|_| PQNoiseError::Decrypt)?;
        mix_hash(&mut h, &received_encrypted_rekem2);
        let rekem2 = pqc_kem::SharedSecretVecToArray(
            e.decapsulate_from_raw(&pqc_kem::CiphertextVecToArray(received_rekem2))
                .clone()
                .into_vec(),
        );
        let k = mix_key(&mut ck, &rekem2)?;

        // <- skem2
        let aead = Aes256Gcm::new(GenericArray::from_slice(&k));
        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let mut received_encrypted_rskem2 = [0u8; pqc_kem::CIPHERTEXT_LENGTH + AES_GCM_TAGLEN];
        cursor
            .read_exact(&mut received_encrypted_rskem2)
            .map_err(|_| PQNoiseError::MsgTooShort)?;
        let ct_and_ad = Payload {
            msg: &received_encrypted_rskem2,
            aad: &h,
        };
        let received_rskem2 = aead
            .decrypt(nonce, ct_and_ad)
            .map_err(|_| PQNoiseError::Decrypt)?;
        mix_hash(&mut h, &received_encrypted_rskem2);
        let rskem2 = pqc_kem::SharedSecretVecToArray(
            self
                .private_key
                .decapsulate_from_raw(&pqc_kem::CiphertextVecToArray(received_rskem2))
                .clone()
                .into_vec(),
        );
        let k = mix_key(&mut ck, &rskem2)?;

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
            .map_err(|_| PQNoiseError::Decrypt)?;
        // split
        let (k1, k2) = hkdf(&ck, None)?;
        let session = PQNoiseSession::new(k1, k2, rs);

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
            pqc_kem::PublicKey,        // initiator's public key
            PQResponderHandshakeState, // state to be used in respond_to_client
            Vec<u8>,                   // payload received
        ),
        PQNoiseError,
    > {
        // checks
        if received_message.len() > MAX_SIZE_NOISE_MSG {
            return Err(PQNoiseError::ReceivedMsgTooLarge);
        }

        // initialize
        let mut h = PROTOCOL_NAME.to_vec();
        let mut ck = PROTOCOL_NAME.to_vec();
        mix_hash(&mut h, prologue);
        mix_hash(&mut h, &self.public_key.to_bytes());

        // buffer message received
        let mut cursor = Cursor::new(received_message);

        // <- e
        let mut re = [0u8; pqc_kem::PUBLIC_KEY_LENGTH];
        cursor.read_exact(&mut re)
            .map_err(|_| PQNoiseError::MsgTooShort)?;
        mix_hash(&mut h, &re);
        let re = pqc_kem::PublicKey::from(re);

        // <- skem1
        let mut received_rskem1 = [0u8; pqc_kem::CIPHERTEXT_LENGTH];
        cursor.read_exact(&mut received_rskem1)
            .map_err(|_| PQNoiseError::MsgTooShort)?;
        mix_hash(&mut h, &received_rskem1);
        let rskem1 = pqc_kem::SharedSecretVecToArray(
            self.private_key.decapsulate_from_raw(&received_rskem1).clone().into_vec()
        );
        let k = mix_key(&mut ck, &rskem1)?;

        // <- s
        let mut encrypted_remote_static = [0u8; pqc_kem::PUBLIC_KEY_LENGTH + AES_GCM_TAGLEN];
        cursor.read_exact(&mut encrypted_remote_static)
            .map_err(|_| PQNoiseError::MsgTooShort)?;
        let aead = Aes256Gcm::new(GenericArray::from_slice(&k));

        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let ct_and_ad = Payload {
            msg: &encrypted_remote_static,
            aad: &h,
        };
        let rs = aead
            .decrypt(nonce, ct_and_ad)
            .map_err(|_| PQNoiseError::Decrypt)?;
        let rs = pqc_kem::PublicKey::try_from(rs.as_slice())
            .map_err(|_| PQNoiseError::WrongPublicKeyReceived)?;
        mix_hash(&mut h, &encrypted_remote_static);

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
            .map_err(|_| PQNoiseError::Decrypt)?;

        // return
        let handshake_state = PQResponderHandshakeState { h, ck, rs, re };
        Ok((rs, handshake_state, received_payload))
    }

    /// A responder can respond to an initiator by calling this function with the state obtained,
    /// after calling parse_client_init_message
    pub fn respond_to_client(
        &self,
        handshake_state: PQResponderHandshakeState,
        payload: Option<&[u8]>,
        response_buffer: &mut [u8],
    ) -> Result<PQNoiseSession, PQNoiseError> {
        // checks
        let payload_len = payload.map(<[u8]>::len).unwrap_or(0);
        let buffer_size_required = handshake_resp_msg_len(payload_len);
        if buffer_size_required > MAX_SIZE_NOISE_MSG {
            return Err(PQNoiseError::PayloadTooLarge);
        }
        if response_buffer.len() < buffer_size_required {
            return Err(PQNoiseError::ResponseBufferTooSmall);
        }

        // retrieve handshake state
        let PQResponderHandshakeState {
            mut h,
            mut ck,
            rs,
            re,
        } = handshake_state;

        // -> ekem2
        let (ekem2, shared_secret) = re.encapsulate();
        let ekem2 = pqc_kem::CiphertextVecToArray(ekem2.clone().into_vec());
        let shared_secret = pqc_kem::SharedSecretVecToArray(shared_secret.clone().into_vec());
        let aead = Aes256Gcm::new(GenericArray::from_slice(&ck));
        let msg_and_ad = Payload {
            msg: &ekem2,
            aad: &h,
        };
        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let encrypted_ekem2 = aead.encrypt(nonce, msg_and_ad)
            .map_err(|_| PQNoiseError::Encrypt)?;
        mix_hash(&mut h, &encrypted_ekem2);
        response_buffer.write(&encrypted_ekem2)
            .map_err(|_| PQNoiseError::ResponseBufferTooSmall)?;
        let k = mix_key(&mut ck, &shared_secret)?;
        
        // -> skem2
        let (skem2, shared_secret) = rs.encapsulate();
        let skem2 = pqc_kem::CiphertextVecToArray(skem2.clone().into_vec());
        let shared_secret = pqc_kem::SharedSecretVecToArray(shared_secret.clone().into_vec());
        let aead = Aes256Gcm::new(GenericArray::from_slice(&k));
        let msg_and_ad = Payload {
            msg: &skem2,
            aad: &h,
        };
        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let encrypted_skem2 = aead.encrypt(nonce, msg_and_ad)
            .map_err(|_| PQNoiseError::Encrypt)?;
        mix_hash(&mut h, &encrypted_skem2);
        response_buffer.write(&encrypted_skem2)
            .map_err(|_| PQNoiseError::ResponseBufferTooSmall)?;
        let k = mix_key(&mut ck, &shared_secret)?;

        // -> payload
        let aead = Aes256Gcm::new(GenericArray::from_slice(&k));
        let msg_and_ad = Payload {
            msg: payload.unwrap_or_else(|| &[]),
            aad: &h,
        };
        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let encrypted_payload = aead
            .encrypt(nonce, msg_and_ad)
            .map_err(|_| PQNoiseError::Encrypt)?;

        mix_hash(&mut h, &encrypted_payload);

        response_buffer
            .write(&encrypted_payload)
            .map_err(|_| PQNoiseError::ResponseBufferTooSmall)?;

        // split
        let (k1, k2) = hkdf(&ck, None)?;
        let session = PQNoiseSession::new(k2, k1, rs);

        //
        Ok(session)
    }

    /// This function is a one-call that replaces calling the two functions parse_client_init_message
    /// and respond_to_client consecutively
    pub fn respond_to_client_and_finalize(
        &self,
        prologue: &[u8],
        received_message: &[u8],
        payload: Option<&[u8]>,
        response_buffer: &mut [u8],
    ) -> Result<
        (
            Vec<u8>,      // the payload the initiator sent
            PQNoiseSession, // The created session
        ),
        PQNoiseError,
    > {
        let (_, handshake_state, received_payload) =
            self.parse_client_init_message(prologue, received_message)?;
        let session = self.respond_to_client(handshake_state, payload, response_buffer)?;
        Ok((received_payload, session))
    }
}

//
// Post-Handshake
// --------------

/// A NoiseSession is produced after a successful Noise handshake, and can be use to encrypt and decrypt messages to the other peer.
#[cfg_attr(test, derive(Clone))]
pub struct PQNoiseSession {
    /// a session can be marked as invalid if it has seen a decryption failure
    valid: bool,
    /// the public key of the other peer
    remote_public_key: pqc_kem::PublicKey,
    /// key used to encrypt messages to the other peer
    write_key: Vec<u8>,
    /// associated nonce (in practice the maximum u64 value cannot be reached)
    write_nonce: u64,
    /// key used to decrypt messages received from the other peer
    read_key: Vec<u8>,
    /// associated nonce (in practice the maximum u64 value cannot be reached)
    read_nonce: u64,
}

impl PQNoiseSession {
    fn new(write_key: Vec<u8>, read_key: Vec<u8>, remote_public_key: pqc_kem::PublicKey) -> Self {
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
            [0u8; pqc_kem::PUBLIC_KEY_LENGTH].into(),
        )
    }

    /// obtain remote static public key
    pub fn get_remote_static(&self) -> pqc_kem::PublicKey {
        self.remote_public_key
    }

    /// encrypts a message for the other peers (post-handshake)
    /// the function encrypts in place, and returns the authentication tag as result
    pub fn write_message_in_place(&mut self, message: &mut [u8]) -> Result<Vec<u8>, PQNoiseError> {
        // checks
        if !self.valid {
            return Err(PQNoiseError::SessionClosed);
        }
        if message.len() > MAX_SIZE_NOISE_MSG - AES_GCM_TAGLEN {
            return Err(PQNoiseError::PayloadTooLarge);
        }

        // encrypt in place
        let aead = Aes256Gcm::new(GenericArray::from_slice(&self.write_key));
        let mut nonce = [0u8; 4].to_vec();
        nonce.extend_from_slice(&self.write_nonce.to_be_bytes());
        let nonce = GenericArray::from_slice(&nonce);

        let authentication_tag = aead
            .encrypt_in_place_detached(nonce, b"", message)
            .map_err(|_| PQNoiseError::Encrypt)?;

        // increment nonce
        self.write_nonce = self
            .write_nonce
            .checked_add(1)
            .ok_or(PQNoiseError::NonceOverflow)?;

        // return a subslice without the authentication tag
        Ok(authentication_tag.to_vec())
    }

    /// decrypts a message from the other peer (post-handshake)
    /// the function decrypts in place, and returns a subslice without the auth tag
    pub fn read_message_in_place<'a>(
        &mut self,
        message: &'a mut [u8],
    ) -> Result<&'a [u8], PQNoiseError> {
        // checks
        if !self.valid {
            return Err(PQNoiseError::SessionClosed);
        }
        if message.len() > MAX_SIZE_NOISE_MSG {
            self.valid = false;
            return Err(PQNoiseError::ReceivedMsgTooLarge);
        }
        if message.len() < AES_GCM_TAGLEN {
            self.valid = false;
            return Err(PQNoiseError::ResponseBufferTooSmall);
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
                PQNoiseError::Decrypt
            })?;

        // increment nonce
        self.read_nonce = self
            .read_nonce
            .checked_add(1)
            .ok_or(PQNoiseError::NonceOverflow)?;

        // return a subslice of the buffer representing the decrypted plaintext
        Ok(buffer)
    }
}

impl std::fmt::Debug for PQNoiseSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NoiseSession[...]")
    }
}
