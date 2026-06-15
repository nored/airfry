//! FairPlay SAP exchange — a self-contained ARM64 interpreter that runs Apple's
//! embedded FairPlay code, ported faithfully from doubletake's Go `fpemu`.
//!
//! Public API mirrors the Go entry points:
//!   - `fp_sap_exchange_standalone([u8;128]) -> [u8;20]`  (the core)
//!   - `fp_sap_exchange_m3(&[u8]) -> Result<Vec<u8>, String>`  (FPLY m2 -> m3)
//!
//! The 165575-byte Apple snapshot lives in `fp_blob.bin` (embedded below).

mod cpu;
mod decode;
mod helpers;
mod loader;
mod mem;
mod stubs;

pub use cpu::Cpu;
pub use loader::{fp_sap_exchange_m3, fp_sap_exchange_standalone};
pub use mem::Mem;

use std::collections::HashMap;

use aes::{Aes128, Aes192, Aes256};
use ctr::cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher};

/// The Apple FairPlay snapshot (code + data + GOT), generated at build time by
/// `build.rs` from the doubletake submodule into `$OUT_DIR/fp_blob.bin`. It is
/// never committed here — it is Apple's proprietary code, extracted on build.
pub static FP_BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fp_blob.bin"));

// Memory layout constants (port of the Go consts).
pub const FP_TRAMPOLINE_ADDR: u64 = 0x10000000;
pub const FP_STACK_BASE: u64 = 0x70000000;
pub const FP_STACK_SZ: u64 = 0x800000; // 8 MB
pub const FP_HEAP_BASE: u64 = 0x80000000;
pub const FP_CODE_BASE: u64 = 0x1a1210000;
pub const FP_CODE_END: u64 = 0x1a1316000;
pub const FP_DATA_BASE: u64 = 0x1b10a3000;
pub const FP_GOT_BASE: u64 = 0x1aeab6000;
pub const FP_ENTRY: u64 = 0x1a12bfb88;

/// Incremental SHA context used by the CC_SHA{1,512} stubs.
pub enum ShaCtx {
    Sha1(sha1::Sha1),
    Sha512(sha2::Sha512),
}

/// AES-CTR stream context used by the AES_CTR_* stubs (any AES key size).
pub struct AesCtrCtx {
    pub cipher: Box<dyn StreamCipher + Send>,
}

impl AesCtrCtx {
    pub fn new(key: &[u8], iv: &[u8; 16]) -> Option<Self> {
        let iv = GenericArray::from_slice(iv);
        let cipher: Box<dyn StreamCipher + Send> = match key.len() {
            16 => Box::new(ctr::Ctr128BE::<Aes128>::new(GenericArray::from_slice(key), iv)),
            24 => Box::new(ctr::Ctr128BE::<Aes192>::new(GenericArray::from_slice(key), iv)),
            32 => Box::new(ctr::Ctr128BE::<Aes256>::new(GenericArray::from_slice(key), iv)),
            _ => return None,
        };
        Some(AesCtrCtx { cipher })
    }
}

/// Full interpreter state: CPU + memory + heap + crypto stub contexts.
pub struct State {
    pub cpu: Cpu,
    pub mem: Mem,
    pub heap_ptr: u64,
    pub sha_ctxs: HashMap<u64, ShaCtx>,
    pub aes_ctxs: HashMap<u64, AesCtrCtx>,
    pub stubs: HashMap<u64, String>, // stub address -> name
}

impl State {
    pub fn new() -> Self {
        State {
            cpu: Cpu::new(),
            mem: Mem::new(),
            heap_ptr: FP_HEAP_BASE,
            sha_ctxs: HashMap::new(),
            aes_ctxs: HashMap::new(),
            stubs: HashMap::new(),
        }
    }

    /// 16-byte-aligned bump allocator (port of fpState.heapAlloc).
    pub fn heap_alloc(&mut self, n: u64) -> u64 {
        let n = (n + 15) & !15;
        let addr = self.heap_ptr;
        self.heap_ptr += n;
        addr
    }
}

// Public API lives in `loader` (fp_sap_exchange_standalone / fp_sap_exchange_m3),
// re-exported above. They reproduce the Go fpemu byte-for-byte — see tests/vectors.rs.
