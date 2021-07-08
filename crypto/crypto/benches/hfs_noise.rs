//! `RUSTFLAGS="-Ctarget-cpu=skylake -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"`.
//! 

#[macro_use]
extern crate criterion;

use criterion::{Criterion, Throughput};
use rand::SeedableRng;
use std::convert::TryFrom as _;
use diem_crypto::{
    hfs_noise::{handshake_init_msg_len, handshake_resp_msg_len, HfsNoiseConfig, AES_GCM_TAGLEN},
    x25519, ValidCryptoMaterial as _,
};

const MSG_SIZE: usize = 4096;

fn benchmarks(c: &mut Criterion) {
    // TODO
}