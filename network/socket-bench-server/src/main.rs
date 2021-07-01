// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Standalone server for socket_bench
//! ========================================
//!
//! You can run `socket_bench` across a real network by running this bench
//! server remotely. For example,
//!
//! `RUSTFLAGS="-Ctarget-cpu=skylake -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3" TCP_ADDR=/ip6/::1/tcp/12345 cargo run --release -p socket-bench-server`
//!
//! will run the socket bench server handling the remote_tcp benchmark. A
//! corresponding client would exercise this benchmark using
//!
//! `RUSTFLAGS="-Ctarget-cpu=skylake -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3" TCP_ADDR=/ip6/::1/tcp/12345 cargo x bench -p network remote_tcp`

use diem_logger::info;
use netcore::transport::tcp::TcpTransport;
use diem_crypto::{pqc_kem, test_utils::TEST_SEED, x25519, Uniform as _};
use socket_bench_server::{build_tcp_noise_transport, build_tcp_noise_hfs_transport, build_tcp_noise_pq_transport, start_stream_server, Args};
use tokio::runtime::Builder;
use rand::prelude::*;

const TEST_SEED_2: [u8; 32] = [1u8; 32];

fn main() {
    ::diem_logger::Logger::new().init();

    let args = Args::from_env();

    let rt = Builder::new_multi_thread()
        .worker_threads(32)
        .enable_all()
        .build()
        .unwrap();
    let executor = rt.handle();

    if let Some(addr) = args.tcp_addr {
        let addr = start_stream_server(&executor, TcpTransport::default(), addr);
        info!("bench: tcp: listening on: {}", addr);
    }

    else if let Some(addr) = args.tcp_noise_addr {
        if let Some(local_private_key) = args.local_x25519_private {
            let local_public_key = local_private_key.public_key();
            let mut rng: StdRng = SeedableRng::from_seed(TEST_SEED_2);
            let remote_x25519_private = x25519::PrivateKey::generate(&mut rng);
            let remote_x25519_public = remote_x25519_private.public_key();
            let addr = start_stream_server(&executor, build_tcp_noise_transport(
                remote_x25519_private.clone(), remote_x25519_public.clone(), local_public_key.clone()), addr);
            info!("bench: tcp+noise: listening on: {}", addr);
            info!("bench: remote_x25519_public: {:?}", remote_x25519_public);
        } else {
            panic!("bench: local private key not set");
        }
    }

    else if let Some(addr) = args.tcp_noise_hfs_addr {
        if let Some(local_private_key) = args.local_x25519_private {
            let local_public_key = local_private_key.public_key();
            let mut rng: StdRng = SeedableRng::from_seed(TEST_SEED_2);
            let remote_x25519_private = x25519::PrivateKey::generate(&mut rng);
            let remote_x25519_public = remote_x25519_private.public_key();
            let addr = start_stream_server(&executor, build_tcp_noise_hfs_transport(
                remote_x25519_private.clone(), remote_x25519_public.clone(), local_public_key.clone()
            ), addr);
            info!("bench: tcp+noisehfs: listening on: {}", addr);
            info!("bench: remote_x25519_public: {:?}", remote_x25519_public);
        } else {
            panic!("bench: local private key not set");
        }
    }

    else if let Some(addr) = args.tcp_noise_pq_addr {
        if let Some(local_private_key) = args.local_pq_private {
            if let Some(local_public_key) = args.local_pq_public {
                let (remote_pq_private, remote_pq_public) = pqc_kem::keypair();
                let (local_pq_private, local_pq_public) = pqc_kem::keypair();
                let addr = start_stream_server(&executor, build_tcp_noise_pq_transport(
                    remote_pq_private.clone(), remote_pq_public.clone(), local_public_key.clone()
                ), addr);
                info!("bench: tcp+noisepq: listening on: {}", addr);
                info!("bench: remote_pq_public: {:?}", remote_pq_public);
            }
            else {
                panic!("bench: local public key not set");
            }
        } else {
            panic!("bench: local private key not set");
        }
    }

    std::thread::park();
}
