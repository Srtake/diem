// Allow KiB, MiB consts
#![allow(non_upper_case_globals, non_snake_case)]
// Allow fns to take &usize, since criterion only passes parameters by ref
#![allow(clippy::trivially_copy_pass_by_ref)]
// Allow writing 1 * KiB or 1 * MiB
#![allow(clippy::identity_op)]
// Criterion API has changed, TODO: Remove parameterized groups, and bench()
#![allow(deprecated)]

use bytes::{Bytes, BytesMut};
use criterion::{
    criterion_group, criterion_main, AxisScale, Bencher, Criterion, ParameterizedBenchmark,
    PlotConfiguration, Throughput,
};
use diem_crypto::{pqc_kem, x25519, test_utils::TEST_SEED, bench_utils, Uniform as _};
use diem_logger::prelude::*;
use diem_types::{network_address::NetworkAddress, PeerId};
use futures::{
    executor::block_on,
    io::{AsyncRead, AsyncWrite},
    sink::{Sink, SinkExt},
    stream::{self, FuturesUnordered, Stream, StreamExt},
};
use netcore::transport::{memory::MemoryTransport, tcp::TcpTransport, Transport};
use network::{constants, protocols::wire::messaging::v1::network_message_frame_codec};
use rand::prelude::*;
use socket_bench_server::{
    build_memsocket_noise_transport,
    build_memsocket_noise_hfs_transport,
    build_memsocket_noise_pq_transport,
    build_tcp_noise_transport,
    build_tcp_noise_hfs_transport,
    build_tcp_noise_pq_transport,
    start_stream_server,
    Args,
};
use std::{fmt::Debug, io, time::Duration};
use tokio::runtime::{Builder, Runtime};
use tokio_util::{codec::Framed, compat::FuturesAsyncReadCompatExt};

const KiB: usize = 1 << 10;
const MiB: usize = 1 << 20;

// The number of messages to send per `Bencher::iter`. We also flush to ensure
// we measure all the messages being sent.
const SENDS_PER_ITER: usize = 100;

const TEST_SEED_2: [u8; 32] = [1u8; 32];

/// Send `msg_amount` messages of size `msg_len` over `client_stream`.
fn bench_client_send<S>(msg_amount: usize, msg_len: usize, client_stream: &mut S)
where
    S: Sink<Bytes> + Stream<Item = Result<BytesMut, io::Error>> + Unpin,
    S::Error: Debug,
{
    // Send over the in-memory stream.
    let data = Bytes::from(vec![0u8; msg_len]);
    for i in 0..msg_amount {
        // Create a stream of messages to send
        let mut data_stream = stream::repeat(data.clone()).take(msg_amount).map(Ok);
        // Send the batch of messages. Note that `Sink::send_all` will flush the 
        // sink after exhausting the `data_stream`, which is necessary to ensure
        // we measure sending all of the messages.
        block_on(client_stream.send_all(&mut data_stream)).unwrap();
    }

    // Client half-closes their side of the stream
    block_on(client_stream.close()).unwrap();

    // Wait for server to half-close to complete the shutdown
    assert!(block_on(client_stream.next()).is_none());
}

/// Setup and benchmark the client side for the simple stream case
/// (tcp or in-memory).
fn bench_client_stream_send<T, S>(
    msg_amount: usize,
    msg_len: usize,
    runtime: &mut Runtime,
    server_addr: NetworkAddress,
    client_transport: T,
) -> impl Stream
where
    T: Transport<Output = S> + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Client dials the server. Some of our transports have timeouts built in,
    // which means the futures must be run on a tokio Runtime.
    let server_peer_id = PeerId::random();
    let client_socket = runtime
        .block_on(client_transport.dial(server_peer_id, server_addr).unwrap())
        .unwrap();
    let codec = network_message_frame_codec(constants::MAX_FRAME_SIZE);
    let mut client_stream = Framed::new(client_socket.compat(), codec);

    // Benchmark client sending data to server.
    bench_client_send(msg_amount, msg_len, &mut client_stream);

    // Return the client stream so we can drop it after the bench completes
    client_stream
}

/// Benchmark the handshake and throughput of sending `msg_amount` messages of size `msg_len`
/// over an in-memory socket with Noise encryption.
fn bench_memsocket_noise_send(
    b: &mut Bencher,
    msg_amount: &usize,
    msg_len: &usize,
    server_addr: NetworkAddress,
) {
    // Generate and setup local and remote keys
    let local_private_key = x25519::PrivateKey::from_encoded_string(bench_utils::X25519_CLIENT_SECRET_KEY).unwrap();
    let local_public_key = local_private_key.public_key();
    let remote_private_key = x25519::PrivateKey::from_encoded_string(bench_utils::X25519_SERVER_SECRET_KEY).unwrap();
    let remote_public_key = remote_private_key.public_key();

    // Setup runtime
    let mut runtime = Runtime::new().unwrap();

    // Benchmark handshake and throughput
    b.iter(|| {
        let client_transport = build_memsocket_noise_transport(
            local_private_key.clone(),
            local_public_key.clone(),
            remote_public_key.clone(),
        );
        let _client_stream =
            bench_client_stream_send(*msg_amount, *msg_len, &mut runtime, server_addr, clinet_transport);
    });
}

/// Benchmark the handshake and throughput of sending `msg_amount` messages of size
/// `msg_len` over an in-memory socket with Noise hybrid forward secrecy encryption.
fn bench_memsocket_noise_hfs_send(
    b: &mut Bencher,
    msg_amount: &usize,
    msg_len: &usize,
    server_addr: NetworkAddress,
) {
    // Generate and setup local and remote keys
    let local_private_key = x25519::PrivateKey::from_encoded_string(bench_utils::X25519_CLIENT_SECRET_KEY).unwrap();
    let local_public_key = local_private_key.public_key();
    let remote_private_key = x25519::PrivateKey::from_encoded_string(bench_utils::X25519_SERVER_SECRET_KEY).unwrap();
    let remote_public_key = remote_private_key.public_key();

    // Setup runtime
    let mut runtime = Runtime::new().unwrap();

    // Benchmark handshake and throughput
    b.iter(|| {
        let client_transport = build_memsocket_noise_hfs_transport(
            local_private_key.clone(),
            local_public_key.clone(),
            remote_public_key.clone(),
        );
        let _client_stream =
            bench_client_stream_send(*msg_amount, *msg_len, &mut runtime, server_addr, clinet_transport);
    });
}

/// Benchmark the throughput of sending `msg_amount` messages of size `msg_len` over an
/// in-memory socket with Noise post-quantum only encryption.
fn bench_memsocket_noise_pq_send(
    b: &mut Bencher,
    msg_amount: &usize,
    msg_len: &usize,
    server_addr: NetworkAddress,
) {
    // Generate and setup local and remote keys
    let local_private_key = pqc_kem::PrivateKey::new_from_encoded_string(
        &(String::from(bench_utils::HQC_128_CLIENT_SECRET_KEY))).unwrap();
    let local_public_key = pqc_kem::PublicKey::new_from_encoded_string(
        &(String::from(bench_utils::HQC_128_CLIENT_PUBLIC_KEY))).unwrap();
    let remote_private_key = pqc_kem::PrivateKey::new_from_encoded_string(
        &(String::from(bench_utils::HQC_128_SERVER_SECRET_KEY))).unwrap();
    let remote_public_key = pqc_kem::PublicKey::new_from_encoded_string(
        &(String::from(bench_utils::HQC_128_SERVER_PUBLIC_KEY))).unwrap();

    // Setup runtime
    let mut runtime = Runtime::new().unwrap();

    // Benchmark handshake and throughput
    b.iter(|| {
        let client_transport = build_memsocket_noise_pq_transport(
            local_private_key.clone(),
            local_public_key.clone(),
            remote_public_key.clone(),
        );
        let _client_stream =
            bench_client_stream_send(*msg_amount, *msg_len, &mut runtime, server_addr, clinet_transport);
    });    
}

/// Benchmark the handshake and throughput of sending `msg_amount` of size `msg_len` over tcp with
/// Noise encryption to server at multiaddr `server_addr`.
fn bench_tcp_noise_send(
    b: &mut Bencher,
    msg_amount: &usize,
    msg_len: &usize,
    server_addr: NetworkAddress,
) {
    // Generate and setup local and remote keys
    let local_private_key = x25519::PrivateKey::from_encoded_string(bench_utils::X25519_CLIENT_SECRET_KEY).unwrap();
    let local_public_key = local_private_key.public_key();
    let remote_private_key = x25519::PrivateKey::from_encoded_string(bench_utils::X25519_SERVER_SECRET_KEY).unwrap();
    let remote_public_key = remote_private_key.public_key();

    // Setup runtime
    let mut runtime = Runtime::new().unwrap();

    // Benchmark handshake and throughput
    b.iter(|| {
        let client_transport = build_tcp_noise_transport(
            local_private_key.clone(),
            local_public_key.clone(),
            remote_public_key.clone(),
        );
        let _client_stream =
            bench_client_stream_send(*msg_amount, *msg_len, &mut runtime, server_addr, clinet_transport);
    });
}

/// Benchmark the throughput of sending `msg_amount` messages of size `msg_len` over tcp with
/// Noise hybrid forward secrecy encryption to server at multiaddr `server_addr`.
fn bench_tcp_noise_hfs_send(
    b: &mut Bencher,
    msg_amount: &usize,
    msg_len: &usize,
    server_addr: NetworkAddress,
) {
    // Generate and setup local and remote keys
    let local_private_key = x25519::PrivateKey::from_encoded_string(bench_utils::X25519_CLIENT_SECRET_KEY).unwrap();
    let local_public_key = local_private_key.public_key();
    let remote_private_key = x25519::PrivateKey::from_encoded_string(bench_utils::X25519_SERVER_SECRET_KEY).unwrap();
    let remote_public_key = remote_private_key.public_key();

    // Setup runtime
    let mut runtime = Runtime::new().unwrap();

    // Benchmark handshake and throughput
    b.iter(|| {
        let client_transport = build_tcp_noise_hfs_transport(
            local_private_key.clone(),
            local_public_key.clone(),
            remote_public_key.clone(),
        );
        let _client_stream =
            bench_client_stream_send(*msg_amount, *msg_len, &mut runtime, server_addr, clinet_transport);
    });
}

/// Benchmark the throughput of sending `msg_amount` messages of size `msg_len` over tcp with
/// Noise post-quantum only encryption to server at multiaddr `server_addr`.
fn bench_tcp_noise_pq_send(
    b: &mut Bencher,
    msg_amount: &usize,
    msg_len: &usize,
    server_addr: NetworkAddress,
) {
    // Generate and setup local and remote keys
    let local_private_key = pqc_kem::PrivateKey::new_from_encoded_string(
        &(String::from(bench_utils::HQC_128_CLIENT_SECRET_KEY))).unwrap();
    let local_public_key = pqc_kem::PublicKey::new_from_encoded_string(
        &(String::from(bench_utils::HQC_128_CLIENT_PUBLIC_KEY))).unwrap();
    let remote_private_key = pqc_kem::PrivateKey::new_from_encoded_string(
        &(String::from(bench_utils::HQC_128_SERVER_SECRET_KEY))).unwrap();
    let remote_public_key = pqc_kem::PublicKey::new_from_encoded_string(
        &(String::from(bench_utils::HQC_128_SERVER_PUBLIC_KEY))).unwrap();

    // Setup runtime
    let mut runtime = Runtime::new().unwrap();

    // Benchmark handshake and throughput
    b.iter(|| {
        let client_transport = build_tcp_noise_pq_transport(
            local_private_key.clone(),
            local_public_key.clone(),
            remote_public_key.clone(),
        );
        let _client_stream =
            bench_client_stream_send(*msg_amount, *msg_len, &mut runtime, server_addr, clinet_transport);
    });    
}

/// Measure sending messages of varying sizes over varying transports
/// local (no addr arguments) or remote (need remote addr args)
/// For each bench we measure NoiseIK, NoiseIKhfs and NoiseIKpq protocols.
fn socket_bench(c: &mut Criterion) {
    ::diem_logger::Logger::init_for_testing();
    let concurrency_param: Vec<u64> = vec![1];

    let rt = Runtime::new().unwrap();
    let executor = rt.handle().clone();

    let args = Args::from_env();

    // Parameterize benchmarks over the message length.
    let default_msg_lens = vec![128 * KiB];
    let msg_lens = args.msg_lens.unwrap_or(default_msg_lens);
    let default_msg_amount = vec![1];
    let msg_amount = args.msg_amount.unwrap_or(default_msg_amount);

    // Remote keypairs
    let x25519_remote_private = x25519::PrivateKey::from_encoded_string(bench_utils::X25519_SERVER_SECRET_KEY).unwrap();
    let x25519_remote_public = x25519_remote_private.public_key();
    let pq_remote_private = pqc_kem::PrivateKey::new_from_encoded_string(
        &(String::from(bench_utils::HQC_128_SERVER_SECRET_KEY))).unwrap();
    let pq_remote_public = pqc_kem::PublicKey::new_from_encoded_string(
        &(String::from(bench_utils::HQC_128_SERVER_PUBLIC_KEY))).unwrap();

    // Start local noiseik bench server
    let x25519_local_ik_private = x25519::PrivateKey::from_encoded_string(bench_utils::X25519_SERVER_SECRET_KEY).unwrap();
    let x25519_local_ik_public = x25519_local_ik_private.public_key();
    let default_tcp_noise_addr = start_stream_server(
        &executor,
        build_tcp_noise_transport(
            x25519_remote_private.clone(),
            x25519_remote_public.clone(),
            x25519_local_ik_public.clone(),
        ),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
    );
    let tcp_noise_addr = args.tcp_noise_addr.unwrap_or(default_tcp_noise_addr);

    // Start local noiseikhfs bench server
    let x25519_local_ikhfs_private = x25519::PrivateKey::from_encoded_string(bench_utils::X25519_SERVER_SECRET_KEY).unwrap();
    let x25519_local_ikhfs_public = x25519_local_ikhfs_private.public_key();
    let default_tcp_noise_hfs_addr = start_stream_server(
        &executor,
        build_tcp_noise_hfs_transport(
            x25519_remote_private.clone(),
            x25519_remote_public.clone(),
            x25519_local_ikhfs_public.clone(),
        ),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
    );
    let tcp_noise_hfs_addr = args.tcp_noise_hfs_addr.unwrap_or(default_tcp_noise_addr);

    // Start local noiseikpq bench server
    let pq_local_ikpq_private = pqc_kem::PrivateKey::new_from_encoded_string(
        &(String::from(bench_utils::HQC_128_CLIENT_SECRET_KEY)));
    let pq_local_ikpq_public = pqc_kem::PublicKey::new_from_encoded_string(
        &(String::from(bench_utils::HQC_128_CLIENT_PUBLIC_KEY)));
    let default_tcp_noise_pq_addr = start_stream_server(
        &executor,
        build_tcp_noise_pq_transport(
            pq_remote_private.clone(),
            pq_remote_public.clone(),
            pq_local_ikpq_public.clone(),
        ),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
    );
    let tcp_noise_pq_addr = args.tcp_noise_pq_addr.unwrap_or(default_tcp_noise_pq_addr);

    // Add the tcp loopback socket benches
    let mut bench = ParameterizedBenchmark::new(
        "noise_ik_connections",
        move |b| {
            let local_sk = x25519_local_ik_private.clone();
            let local_pk = x25519_local_ik_public.clone();
            let remote_pk = x25519_remote_public.clone();
            bench_memsocket_noise_send(
                b,
                msg_amount,
                msg_lens,
                tcp_noise_addr.clone(),
            ),
            msg_amount,
        }
    )
    .with_function("noise_ikhfs_connections", move |b| {
        let local_sk = x25519_local_ikhfs_private.clone();
        let local_pk = x25519_local_ikhfs_public.clone();
        let remote_pk = x25519_remote_public.clone();
        bench_tcp_noise_hfs_send(
            b,
            msg_amount,
            msg_lens,
            tcp_noise_hfs_addr.clone(),
        ),
        msg_amount,
    })
    .with_function("noise_ikpq_connections", move |b| {
        let local_sk = pq_local_ikpq_private.clone();
        let local_pk = pq_local_ikpq_public.clone();
        let remote_pk = pq_remote_public.clone();
        bench_tcp_noise_pq_send(
            b,
            msg_amount,
            msg_lens,
            tcp_noise_pq_addr.clone(),
        ),
        msg_amount,
    });

    // Setup benchmark
    bench = bench
        .warm_up_time(Duration::from_secs(5))
        .measurement_time(Duration::from_secs(10))
        .sample_size(100)
        .plot_config(PlotConfiguration::default().summary_scale(AxisScale::Logarithmic))
        .throughput(|msg_len| {
            let msg_len = *msg_len as u32;
            let num_msgs = msg_amount as u32;
            Throughput::Bytes(u64::from(msg_len * num_msgs)
        });
    
    c.bench("noise_connections", bench);
}

criterion_group!(network_benches, socket_bench);
criterion_main!(network_benches);