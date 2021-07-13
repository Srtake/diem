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
use diem_crypto::{pqc_kem, test_utils::TEST_SEED, bench_utils, x25519, Uniform as _};
use socket_bench_server::{build_tcp_noise_transport, build_tcp_noise_hfs_transport, build_tcp_noise_pq_transport, start_stream_server, Args};
use tokio::runtime::Builder;

fn main() {
    ::diem_logger::Logger::new().init();

    let args = Args::from_env();

    let rt = Builder::new_multi_thread()
        .worker_threads(32)
        .enable_all()
        .build()
        .unwrap();
    let executor = rt.handle();

    // Remote (server) keypairs
    let x25519_remote_private = x25519::PrivateKey::from_encoded_string(bench_utils::X25519_SERVER_SECRET_KEY).unwrap();
    let x25519_remote_public = x25519_remote_private.public_key();
    let pq_remote_private = pqc_kem::PrivateKey::new_from_encoded_string(
        &(String::from(bench_utils::HQC_128_SERVER_SECRET_KEY))).unwrap();
    let pq_remote_public = pqc_kem::PublicKey::new_from_encoded_string(
        &(String::from(bench_utils::HQC_128_SERVER_PUBLIC_KEY))).unwrap();

    // Start noise ik stream server
    if let Some(addr) = args.tcp_noise_addr {
        let x25519_local_ik_private = x25519::PrivateKey::from_encoded_string(bench_utils::X25519_SERVER_SECRET_KEY).unwrap();
        let x25519_local_ik_public = x25519_local_ik_private.public_key();
        let addr = start_stream_server(
            &executor, 
            build_tcp_noise_transport(
                x25519_remote_private.clone(),
                x25519_remote_public.clone(),
                x25519_local_ik_public.clone(),
            ),
            addr
        );
        info!("bench: tcp+noise: listening on: {}", addr);
    }

    if let Some(addr) = args.tcp_noise_hfs_addr {
        let x25519_local_ikhfs_private = x25519::PrivateKey::from_encoded_string(bench_utils::X25519_SERVER_SECRET_KEY).unwrap();
        let x25519_local_ikhfs_public = x25519_local_ikhfs_private.public_key();
        let addr = start_stream_server(
            &executor,
            build_tcp_noise_hfs_transport(
                x25519_remote_private.clone(),
                x25519_remote_public.clone(),
                x25519_local_ikhfs_public.clone(),
            ),
            addr
        );
        info!("bench: tcp+noisehfs: listening on: {}", addr);
    }

    if let Some(addr) = args.tcp_noise_pq_addr {
        let pq_local_ikpq_private = pqc_kem::PrivateKey::new_from_encoded_string(
            &(String::from(bench_utils::HQC_128_CLIENT_SECRET_KEY)));
        let pq_local_ikpq_public = pqc_kem::PublicKey::new_from_encoded_string(
            &(String::from(bench_utils::HQC_128_CLIENT_PUBLIC_KEY)));
        let addr = start_stream_server(
            &executor,
            build_tcp_noise_pq_transport(
                pq_remote_private.clone(),
                pq_remote_public.clone(),
                pq_local_ikpq_public.clone(),
            ),
            addr
        );
        info!("bench: tcp+noisepq: listening on {}", addr);
    }

    std::thread::park();
}
