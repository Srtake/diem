use std::{fs::File, io::BufReader, path::PathBuf};

use crate::{
    hfs_noise::{handshake_init_msg_len, handshake_resp_msg_len, HfsNoiseConfig, MAX_SIZE_NOISE_MSG},
    test_utils::TEST_SEED,
    x25519, Uniform as _,
};

use rand::SeedableRng;
use serde::*；

#[test]
fn simple_handshake() {
    // setup peers
    let mut rng = ::rand::rngs::StdRng::from_seed(TEST_SEED);
    let initiator_private = x25519::PrivateKey::generate(&mut rng);
    let initiator_public = initiator_private.public_key();
    let responder_private = x25519::PrivateKey::generate(&mut rng);
    let responder_public = responder_private.public_key();
    let initiator = HfsNoiseConfig::new(initiator_private);
    let responder = HfsNoiseConfig::new(responder_private);

    // test the two APIs
    for i in 0..2 {
        // initiator sends first message
        let prologue = b"prologue";
        let payload1 = b"payload1";
        let mut first_message = vec![0u8; handshake_init_msg_len(payload1.len())];
        let initiator_state = initiator.initiate_connection(
            &mut rng,
            prologue,
            responder_public,
            Some(payload1),
            &mut first_message,
        ).unwrap();

        let payload2 = b"payload2";
        let mut second_message = vec![0u8; handshake_resp_msg_len(payload2.len())];

        // responder parses the first message and responds
        let mut responder_session = if i == 0 {
            let (received_payload, responder_session) = responder
                .respond_to_client_and_finalize(
                    &mut rng,
                    prologue,
                    &first_message,
                    Some(payload2),
                    &mut second_message,
                ).unwrap();
            let remote_static = responder_session.get_remote_static();
            assert_eq!(remote_static, initiator_public);
            assert_eq!(received_payload, b"payload1");
            responder_session
        } else {
            let payload2 = b"payload2";
            let (remote_static, handshake_state, received_payload) = responder
                .parse_client_init_message(prologue, &first_message)
                .unwrap();
            assert_eq!(remote_static, initiator_public);
            assert_eq!(received_payload, b"payload1");

            responder.respond_to_client(
                &mut rng,
                handshake_state,
                Some(payload2),
                &mut second_message,
            ).unwrap()
        };

        // initiator parses the response
        let (received_payload, mut initiator_session) = initiator
            .finalize_connection(initiator_state, &second_message)
            .unwrap();
        assert_eq!(received_payload, b"payload2");

        // session usage
        let mut message_sent = b"payload".to_vec();
        for i in 0..10 {
            message_sent.push(i);
            let mut message = message_sent.clone();
            let received_message = if i % 2 == 0 {
                let auth_tag = initiator_session
                    .write_message_in_place(&mut message)
                    .expect("session should not be closed");
                message.extend_from_slice(&auth_tag);
                responder_session
                    .read_message_in_place(&mut message)
                    .expect("session should not be closed");
            } else {
                let auth_tag = responder_session
                    .write_message_in_place(&mut message)
                    .expect("session should not be closed");
                message.extend_from_slice(&auth_tag);
                initiator_session
                    .read_message_in_place(&mut message)
                    .expect("session should not be closed");
            };
            assert_eq!(received_message, message_sent.as_slice());
        }
    }
}

// #[test]
// fn test_vectors() {
//     // structures needed to deserialize test vectors
//     #[derive(Serialize, Deserialize)]
//     struct TestVectors {
//         vectors: Vec<TestVector>,
//     }
//     #[derive(Serialize, Deserialize, Debug)]
//     struct TestVector {
//         protocol_name: String,
//         init_prologue: String,
//         init_static: Option<String>,
//         init_ephemeral: String,
//         init_ephemeral_pqc: String,
//         init_remote_static: Option<String>,
//         resp_static: Option<String>,
//         resp_ephemeral: Option<String>,
//         resp_ephemeral_pqc: Option<String>,
//         handshake_hash: String,
//         messages: Vec<TestMessage>,
//     }
//     #[derive(Serialize, Deserialize, Debug)]
//     struct TestMessage {
//         payload: String,
//         ciphertext: String,
//     }

//     // EphemeralRng is used to get deterministic ephemeral keys based on test vectors
//     struct EphemeralRng {
//         ephemeral: Vec<u8>
//     }
//     impl rand::RngCore for EphemeralRng {
//         fn next_u32(&mut self) -> u32 {
//             unreachable!()
//         }
//         fn next_u64(&mut self) -> u64 {
//             unreachable!()
//         }
//         fn fill_bytes(&mut self, dest: &mut [u8]) {
//             dest.copy_from_slice(&self.ephemeral);
//         }
//         fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand::Error> {
//             unreachable!()
//         }
//     }
//     impl rand::CryptoRng for EphemeralRng {}

//     // test vectors are taken from the cacophony library

// }