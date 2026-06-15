//! Paged memory — faithful port of fpMem in doubletake's fpexchange_interp.go.
//!
//! Access methods take `&mut self` because a touched page is lazily allocated
//! (matching the Go `pageCached`). The Go page-pointer cache is a speed-only
//! optimization and is omitted here for clarity; correctness is identical.

use std::collections::HashMap;

pub struct Mem {
    pages: HashMap<u64, Vec<u8>>,
    code_insts: Vec<u32>,
    code_base: u64,
    code_end: u64,
}

impl Mem {
    pub fn new() -> Self {
        Mem {
            pages: HashMap::new(),
            code_insts: Vec::new(),
            code_base: 0,
            code_end: 0,
        }
    }

    #[inline]
    fn page(&mut self, addr: u64) -> &mut [u8] {
        let pa = addr & !0xFFF;
        self.pages.entry(pa).or_insert_with(|| vec![0u8; 4096])
    }

    pub fn fetch_inst(&self, pc: u64) -> u32 {
        if pc >= self.code_base && pc < self.code_end {
            return self.code_insts[((pc - self.code_base) >> 2) as usize];
        }
        match self.pages.get(&(pc & !0xFFF)) {
            None => 0,
            Some(p) => {
                let o = (pc & 0xFFF) as usize;
                u32::from_le_bytes([p[o], p[o + 1], p[o + 2], p[o + 3]])
            }
        }
    }

    #[inline]
    pub fn read8(&mut self, a: u64) -> u8 {
        self.page(a)[(a & 0xFFF) as usize]
    }
    #[inline]
    pub fn write8(&mut self, a: u64, v: u8) {
        let o = (a & 0xFFF) as usize;
        self.page(a)[o] = v;
    }

    pub fn read16(&mut self, a: u64) -> u16 {
        if a & 0xFFF <= 0xFFE {
            let o = (a & 0xFFF) as usize;
            let p = self.page(a);
            u16::from_le_bytes([p[o], p[o + 1]])
        } else {
            self.read8(a) as u16 | (self.read8(a + 1) as u16) << 8
        }
    }
    pub fn write16(&mut self, a: u64, v: u16) {
        if a & 0xFFF <= 0xFFE {
            let o = (a & 0xFFF) as usize;
            let p = self.page(a);
            p[o..o + 2].copy_from_slice(&v.to_le_bytes());
        } else {
            self.write8(a, v as u8);
            self.write8(a + 1, (v >> 8) as u8);
        }
    }

    pub fn read32(&mut self, a: u64) -> u32 {
        if a & 0xFFF <= 0xFFC {
            let o = (a & 0xFFF) as usize;
            let p = self.page(a);
            u32::from_le_bytes([p[o], p[o + 1], p[o + 2], p[o + 3]])
        } else {
            self.read8(a) as u32
                | (self.read8(a + 1) as u32) << 8
                | (self.read8(a + 2) as u32) << 16
                | (self.read8(a + 3) as u32) << 24
        }
    }
    pub fn write32(&mut self, a: u64, v: u32) {
        if a & 0xFFF <= 0xFFC {
            let o = (a & 0xFFF) as usize;
            let p = self.page(a);
            p[o..o + 4].copy_from_slice(&v.to_le_bytes());
        } else {
            self.write8(a, v as u8);
            self.write8(a + 1, (v >> 8) as u8);
            self.write8(a + 2, (v >> 16) as u8);
            self.write8(a + 3, (v >> 24) as u8);
        }
    }

    pub fn read64(&mut self, a: u64) -> u64 {
        if a & 0xFFF <= 0xFF8 {
            let o = (a & 0xFFF) as usize;
            let p = self.page(a);
            let mut b = [0u8; 8];
            b.copy_from_slice(&p[o..o + 8]);
            u64::from_le_bytes(b)
        } else {
            self.read32(a) as u64 | (self.read32(a + 4) as u64) << 32
        }
    }
    pub fn write64(&mut self, a: u64, v: u64) {
        if a & 0xFFF <= 0xFF8 {
            let o = (a & 0xFFF) as usize;
            let p = self.page(a);
            p[o..o + 8].copy_from_slice(&v.to_le_bytes());
        } else {
            self.write32(a, v as u32);
            self.write32(a + 4, (v >> 32) as u32);
        }
    }

    pub fn read_n(&mut self, addr: u64, n: usize) -> Vec<u8> {
        let mut b = vec![0u8; n];
        let mut off = 0usize;
        while off < n {
            let cur = addr + off as u64;
            let page_off = (cur & 0xFFF) as usize;
            let p = self.page(cur);
            let nc = std::cmp::min(b.len() - off, p.len() - page_off);
            b[off..off + nc].copy_from_slice(&p[page_off..page_off + nc]);
            off += nc;
        }
        b
    }

    pub fn write_n(&mut self, addr: u64, data: &[u8]) {
        let mut off = 0usize;
        while off < data.len() {
            let cur = addr + off as u64;
            let page_off = (cur & 0xFFF) as usize;
            let p = self.page(cur);
            let nc = std::cmp::min(data.len() - off, p.len() - page_off);
            p[page_off..page_off + nc].copy_from_slice(&data[off..off + nc]);
            off += nc;
        }
    }

    pub fn map_range(&mut self, addr: u64, size: u64) {
        let mut p = addr & !0xFFF;
        while p < addr + size {
            self.page(p);
            p += 0x1000;
        }
    }

    pub fn set_code_region(&mut self, base: u64, end: u64) {
        let n = (end - base) / 4;
        let mut insts = vec![0u32; n as usize];
        for i in 0..n {
            let addr = base + i * 4;
            let pa = addr & !0xFFF;
            if let Some(p) = self.pages.get(&pa) {
                let o = (addr & 0xFFF) as usize;
                insts[i as usize] = u32::from_le_bytes([p[o], p[o + 1], p[o + 2], p[o + 3]]);
            }
        }
        self.code_insts = insts;
        self.code_base = base;
        self.code_end = end;
    }
}
