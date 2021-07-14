//! `RUSTFLAGS="-Ctarget-cpu=skylake -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"`.
//! 

#[macro_use]
extern crate criterion;

use criterion::{Criterion, Throughput};
use rand::SeedableRng;
use std::convert::TryFrom as _;

use diem_crypto::{
    pqc_noise::{handshake_init_msg_len, handshake_resp_msg_len, PQNoiseConfig, AES_GCM_TAGLEN},
    pqc_kem, bench_utils, ValidCryptoMaterial as _,
};

const MSG_SIZE: usize = 4096;

fn benchmarks(c: &mut Criterion) {
    // bench the handshake
    let mut group = c.benchmark_group("pqhandshake+transport");
    group.throughput(Throughput::Bytes(MSG_SIZE as u64 * 2));
    group.bench_function("noiseikpq+aes256gcm", |b| {
        let mut buffer_msg = [0u8; MSG_SIZE * 2];
        // setup keys first
        let initiator_static = pqc_kem::PrivateKey::new_from_encoded_string(&(String::from(bench_utils::CLASSIC_MCELIECE_348864_CLIENT_SECRET_KEY)));
        let initiator_public = pqc_kem::PublicKey::new_from_encoded_string(&(String::from(bench_utils::CLASSIC_MCELIECE_348864_CLIENT_PUBLIC_KEY))).unwrap();
        let initiator_static = initiator_static.unwrap().to_bytes();
        let responder_static = pqc_kem::PrivateKey::new_from_encoded_string(&(String::from(bench_utils::CLASSIC_MCELIECE_348864_SERVER_SECRET_KEY)));
        let responder_public = pqc_kem::PublicKey::new_from_encoded_string(&(String::from(bench_utils::CLASSIC_MCELIECE_348864_SERVER_PUBLIC_KEY))).unwrap();
        let responder_static = responder_static.unwrap().to_bytes();

        let mut first_message = [0u8; handshake_init_msg_len(0)];
        let mut second_message = [0u8; handshake_resp_msg_len(0)];

        b.iter(|| {
            let initiator_static = 
                pqc_kem::PrivateKey::try_from(initiator_static.clone()).unwrap();
            let responder_static = 
                pqc_kem::PrivateKey::try_from(responder_static.clone()).unwrap();
            let initiator_public = 
                pqc_kem::PublicKey::try_from(initiator_public.clone()).unwrap();
            let responder_public = 
                pqc_kem::PublicKey::try_from(responder_public.clone()).unwrap();
            
            let initiator = PQNoiseConfig::new(initiator_static, initiator_public.clone());
            let responder = PQNoiseConfig::new(responder_static, responder_public.clone());

            let initiator_state = initiator
                .initiate_connection(
                    b"prologue",
                    responder_public,
                    None,
                    &mut first_message,
                )
                .unwrap();
            
            let (_, mut responder_session) = responder
                .respond_to_client_and_finalize(
                    b"prologue",
                    &first_message,
                    None,
                    &mut second_message,
                )
                .unwrap();
            
            let (_, mut initiator_session) = initiator
                .finalize_connection(initiator_state, &second_message)
                .unwrap();
            
            // Send messages
            for i in 0..1 {
                let auth_tag = initiator_session
                    .write_message_in_place(&mut buffer_msg[..MSG_SIZE])
                    .expect("session should not be closed");
                
                buffer_msg[MSG_SIZE..MSG_SIZE + AES_GCM_TAGLEN].copy_from_slice(&auth_tag);

                let _plaintext = responder_session
                    .read_message_in_place(&mut buffer_msg[..MSG_SIZE + AES_GCM_TAGLEN])
                    .expect("session should not be closed");
            }
        })
    });
    group.finish();
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);