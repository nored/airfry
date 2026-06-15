//! ARM64 CPU state — faithful port of fpCPU in doubletake's fpexchange_interp.go.

/// Minimal ARM64 processor state.
pub struct Cpu {
    pub x: [u64; 31], // X0-X30 (X30=LR); X31 reads as 0
    pub sp: u64,
    pub pc: u64,
    pub n: bool,
    pub z: bool,
    pub c: bool,
    pub v: bool,
    pub vreg: [[u64; 2]; 32], // NEON 128-bit as [lo64, hi64]
}

impl Cpu {
    pub fn new() -> Self {
        Cpu {
            x: [0; 31],
            sp: 0,
            pc: 0,
            n: false,
            z: false,
            c: false,
            v: false,
            vreg: [[0; 2]; 32],
        }
    }

    /// Read Xn; X31 (XZR) reads as 0.
    #[inline]
    pub fn reg(&self, n: u32) -> u64 {
        if n >= 31 {
            0
        } else {
            self.x[n as usize]
        }
    }

    /// Write Xn; writes to X31 (XZR) are discarded.
    #[inline]
    pub fn set_reg(&mut self, n: u32, v: u64) {
        if n < 31 {
            self.x[n as usize] = v;
        }
    }

    /// Read Xn where 31 means SP (not XZR).
    #[inline]
    pub fn reg_sp(&self, n: u32) -> u64 {
        if n == 31 {
            self.sp
        } else {
            self.x[n as usize]
        }
    }

    /// Write Xn where 31 means SP (not XZR).
    #[inline]
    pub fn set_reg_sp(&mut self, n: u32, v: u64) {
        if n == 31 {
            self.sp = v;
        } else {
            self.x[n as usize] = v;
        }
    }

    /// Evaluate an ARM64 condition code against NZCV (port of fpCPU.condHolds).
    pub fn cond_holds(&self, cond: u32) -> bool {
        let mut r = match cond >> 1 {
            0 => self.z,
            1 => self.c,
            2 => self.n,
            3 => self.v,
            4 => self.c && !self.z,
            5 => self.n == self.v,
            6 => self.n == self.v && !self.z,
            7 => true,
            _ => false,
        };
        if cond & 1 != 0 && cond != 15 {
            r = !r;
        }
        r
    }
}
