use std::{fs::File, io::BufReader, path::PathBuf};

use crate::{
    pqc_noise::{handshake_init_msg_len, handshake_resp_msg_len, PQNoiseConfig, MAX_SIZE_NOISE_MSG},
    test_utils::TEST_SEED,
    pqc_kem, Uniform as _,
};

use rand::SeedableRng;
use serde::*;

#[test]
fn simple_handshake() {
    // setup peers
    let (initiator_private, initiator_public) = pqc_kem::keypair();
    let (responder_private, responder_public) = pqc_kem::keypair();
    let initiator = PQNoiseConfig::new(initiator_private, initiator_public.clone());
    let responder = PQNoiseConfig::new(responder_private, responder_public.clone());

    // test the two APIs
    for i in 0..2 {
        let prologue = b"prologue";
        let payload1 = b"payload1";
        let mut first_message = vec![0u8; handshake_init_msg_len(payload1.len())];
        let initiator_state = initiator.initiate_connection(
            prologue,
            responder_public.clone(),
            Some(payload1),
            &mut first_message,
        ).unwrap();

        let payload2 = b"payload2";
        let mut second_message = vec![0u8; handshake_resp_msg_len(payload2.len())];

        // responder parses the first message and responds
        let mut responder_session = if i == 0 {
            let (received_payload, responder_session) = responder
                .respond_to_client_and_finalize(
                    prologue,
                    &first_message,
                    Some(payload2),
                    &mut second_message,
                ).unwrap();
            let remote_static = responder_session.get_remote_static();
            assert_eq!(remote_static, initiator_public.clone());
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
                handshake_state,
                Some(payload2),
                &mut second_message
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
                    .expect("session should not be closed")
            } else {
                let auth_tag = responder_session
                    .write_message_in_place(&mut message)
                    .expect("session should not be closed");
                message.extend_from_slice(&auth_tag);
                initiator_session
                    .read_message_in_place(&mut message)
                    .expect("session should not be closed")
            };
            assert_eq!(received_message, message_sent.as_slice());
        }
    }
}