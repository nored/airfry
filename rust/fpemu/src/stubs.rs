//! libc / CommonCrypto stubs — faithful port of fpState.handleStub and
//! fpState.fpDynStubClassify.

use crate::{AesCtrCtx, ShaCtx, State};
use sha1::{Digest, Sha1};
use sha2::Sha512;

impl State {
    pub fn handle_stub(&mut self, name: &str) -> Result<(), String> {
        let x0 = self.cpu.x[0];
        let x1 = self.cpu.x[1];
        let x2 = self.cpu.x[2];
        let x3 = self.cpu.x[3];

        match name {
            "_malloc" => {
                let sz = if x0 == 0 { 16 } else { x0 };
                self.cpu.x[0] = self.heap_alloc(sz);
            }
            "_calloc" => {
                let total = if x0.wrapping_mul(x1) == 0 { 16 } else { x0.wrapping_mul(x1) };
                let addr = self.heap_alloc(total);
                self.mem.write_n(addr, &vec![0u8; total as usize]);
                self.cpu.x[0] = addr;
            }
            "_realloc" => {
                let sz = if x1 == 0 { 16 } else { x1 };
                self.cpu.x[0] = self.heap_alloc(sz);
            }
            "_free" => self.cpu.x[0] = 0,
            "_memcpy" | "_memmove" | "___memcpy_chk" => {
                if x2 > 0 && x1 != 0 && x0 != 0 {
                    let src = self.mem.read_n(x1, x2 as usize);
                    self.mem.write_n(x0, &src);
                }
                self.cpu.x[0] = x0;
            }
            "_memset" | "___memset_chk" => {
                if x2 > 0 {
                    self.mem.write_n(x0, &vec![x1 as u8; x2 as usize]);
                }
                self.cpu.x[0] = x0;
            }
            "_memcmp" => {
                if x2 == 0 {
                    self.cpu.x[0] = 0;
                } else {
                    let a = self.mem.read_n(x0, x2 as usize);
                    let b = self.mem.read_n(x1, x2 as usize);
                    let mut r = 0u64;
                    for i in 0..x2 as usize {
                        if a[i] != b[i] {
                            r = if a[i] < b[i] { !0u64 } else { 1 };
                            break;
                        }
                    }
                    self.cpu.x[0] = r;
                }
            }
            "_bzero" => {
                if x1 > 0 {
                    self.mem.write_n(x0, &vec![0u8; x1 as usize]);
                }
            }
            "_strlen" => {
                let mut n = 0u64;
                loop {
                    if self.mem.read8(x0 + n) == 0 {
                        break;
                    }
                    n += 1;
                    if n > 1 << 20 {
                        break;
                    }
                }
                self.cpu.x[0] = n;
            }

            "_CC_SHA1_Init" => {
                self.sha_ctxs.insert(x0, ShaCtx::Sha1(Sha1::new()));
                self.cpu.x[0] = 1;
            }
            "_CC_SHA1_Update" => {
                let data = if x2 > 0 { self.mem.read_n(x1, x2 as usize) } else { Vec::new() };
                let h = self.sha_ctxs.entry(x0).or_insert_with(|| ShaCtx::Sha1(Sha1::new()));
                if let ShaCtx::Sha1(h) = h {
                    if !data.is_empty() {
                        h.update(&data);
                    }
                }
                self.cpu.x[0] = 1;
            }
            "_CC_SHA1_Final" => {
                match self.sha_ctxs.remove(&x1) {
                    Some(ShaCtx::Sha1(h)) => {
                        let out = h.finalize();
                        self.mem.write_n(x0, &out[..20]);
                    }
                    Some(ShaCtx::Sha512(h)) => {
                        let out = h.finalize();
                        self.mem.write_n(x0, &out[..20]);
                    }
                    None => self.mem.write_n(x0, &[0u8; 20]),
                }
                self.cpu.x[0] = 1;
            }
            "_CC_SHA512_Init" => {
                self.sha_ctxs.insert(x0, ShaCtx::Sha512(Sha512::new()));
                self.cpu.x[0] = 1;
            }
            "_CC_SHA512_Update" => {
                let data = if x2 > 0 { self.mem.read_n(x1, x2 as usize) } else { Vec::new() };
                let h = self.sha_ctxs.entry(x0).or_insert_with(|| ShaCtx::Sha512(Sha512::new()));
                if let ShaCtx::Sha512(h) = h {
                    if !data.is_empty() {
                        h.update(&data);
                    }
                }
                self.cpu.x[0] = 1;
            }
            "_CC_SHA512_Final" => {
                match self.sha_ctxs.remove(&x1) {
                    Some(ShaCtx::Sha512(h)) => {
                        let out = h.finalize();
                        self.mem.write_n(x0, &out[..64]);
                    }
                    Some(ShaCtx::Sha1(h)) => {
                        let out = h.finalize();
                        let mut buf = [0u8; 64];
                        buf[..20].copy_from_slice(&out);
                        self.mem.write_n(x0, &buf);
                    }
                    None => self.mem.write_n(x0, &[0u8; 64]),
                }
                self.cpu.x[0] = 1;
            }

            "_AES_CTR_Init" => {
                let key = self.mem.read_n(x1, x2 as usize);
                let iv_v = self.mem.read_n(x3, 16);
                let mut iv = [0u8; 16];
                iv.copy_from_slice(&iv_v);
                match AesCtrCtx::new(&key, &iv) {
                    Some(c) => {
                        self.aes_ctxs.insert(x0, c);
                        self.cpu.x[0] = 0;
                    }
                    None => self.cpu.x[0] = !0u64,
                }
            }
            "_AES_CTR_Update" => {
                if x2 > 0 {
                    let mut buf = self.mem.read_n(x1, x2 as usize);
                    if let Some(ctx) = self.aes_ctxs.get_mut(&x0) {
                        ctx.cipher.apply_keystream(&mut buf);
                        self.mem.write_n(x3, &buf);
                    }
                }
                self.cpu.x[0] = 0;
            }
            "_AES_CTR_Final" => {
                self.aes_ctxs.remove(&x0);
                self.cpu.x[0] = 0;
            }

            "_abort" => return Err(format!("abort() called from LR=0x{:x}", self.cpu.x[30])),
            "_arc4random" => {
                // The Go reference uses crypto/rand here, yet its m3 output is
                // deterministic — so the value is unused/masked. A fixed value
                // keeps the port deterministic and matches.
                self.cpu.x[0] = 0;
            }
            "_FigGetUpTimeNanoseconds" => self.cpu.x[0] = 1_000_000_000,
            "_CFRetain" => {} // X0 unchanged
            "_pthread_once" | "_FigThreadRunOnce" => {
                if self.mem.read8(x0) == 0 {
                    self.mem.write_n(x0, &[1, 0, 0, 0]);
                }
                self.cpu.x[0] = 0;
            }
            "_dispatch_once" => {
                if self.mem.read64(x0) == 0 {
                    self.mem.write64(x0, !0u64);
                }
                self.cpu.x[0] = 0;
            }

            _ => self.cpu.x[0] = 0, // nop returning 0
        }
        Ok(())
    }

    /// Classify an unknown stub by heuristic (port of fpDynStubClassify).
    pub fn dyn_stub_classify(&self, pc: u64) -> &'static str {
        const STUB_PB: u64 = 0x20000000;
        const STUB_PS: u64 = 0x10000;
        if pc >= STUB_PB && pc < STUB_PB + STUB_PS {
            return "_nop";
        }
        let x0 = self.cpu.x[0];
        let x1 = self.cpu.x[1];
        let x2 = self.cpu.x[2];
        let is_text = |v: u64| v >= 0x1a1210000 && v < 0x1a1316000;
        let is_global_data = |v: u64| v >= 0x1a0000000 && v < 0x1c0000000;
        if is_global_data(x0) && (is_text(x1) || is_text(x2)) {
            return "_dispatch_once";
        }
        if x0 > 0 && x0 < 0x100000 {
            return "_malloc";
        }
        "_nop"
    }
}
