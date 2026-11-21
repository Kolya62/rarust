// SPDX-License-Identifier: GPL-3.0-or-later

//! Reed-Solomon erasure decoding for recovery volumes.
//!
//! RAR 3.x: a Reed-Solomon code over GF(2^8) (polynomial 0x11D) across
//! volumes: byte `k` of every data and recovery volume forms a codeword
//! c_0..c_{n-1} whose polynomial sum c_k x^(n-1-k) has the roots
//! a^1..a^p, a = 2, p = number of recovery volumes.
//!
//! RAR 5.0: 16-bit little endian words over GF(2^16) (polynomial
//! 0x1100B). Recovery volume r (numbered after the n data volumes) holds
//! sum_j D_j / (r xor j), a Cauchy matrix code.

/// Multiplication tables of GF(2^m) with generator 2.
pub struct Field {
    exp: Vec<u32>,
    log: Vec<u32>,
    order: u32,
}

impl Field {
    pub fn new(bits: u32, poly: u32) -> Field {
        let order = (1u32 << bits) - 1;
        let mut exp = vec![0u32; 2 * order as usize];
        let mut log = vec![0u32; order as usize + 1];
        let mut x = 1u32;
        for i in 0..order {
            exp[i as usize] = x;
            exp[(i + order) as usize] = x;
            log[x as usize] = i;
            x <<= 1;
            if x > order {
                x ^= poly;
            }
        }
        Field { exp, log, order }
    }

    #[inline(always)]
    pub fn mul(&self, a: u32, b: u32) -> u32 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp[(self.log[a as usize] + self.log[b as usize]) as usize]
        }
    }

    pub fn inv(&self, a: u32) -> u32 {
        if a == 0 {
            0
        } else {
            self.exp[((self.order - self.log[a as usize]) % self.order) as usize]
        }
    }

    /// 2^e.
    pub fn pow2(&self, e: u64) -> u32 {
        self.exp[(e % self.order as u64) as usize]
    }

    /// Inverts a square matrix (rows of `n`). Returns None if singular.
    pub fn invert(&self, m: &[u32], n: usize) -> Option<Vec<u32>> {
        let mut a = m.to_vec();
        let mut r: Vec<u32> = (0..n * n).map(|i| (i / n == i % n) as u32).collect();
        for col in 0..n {
            let pivot = (col..n).find(|&row| a[row * n + col] != 0)?;
            if pivot != col {
                for k in 0..n {
                    a.swap(pivot * n + k, col * n + k);
                    r.swap(pivot * n + k, col * n + k);
                }
            }
            let p = self.inv(a[col * n + col]);
            for k in 0..n {
                a[col * n + k] = self.mul(a[col * n + k], p);
                r[col * n + k] = self.mul(r[col * n + k], p);
            }
            for row in 0..n {
                let f = a[row * n + col];
                if row != col && f != 0 {
                    for k in 0..n {
                        a[row * n + k] ^= self.mul(f, a[col * n + k]);
                        r[row * n + k] ^= self.mul(f, r[col * n + k]);
                    }
                }
            }
        }
        Some(r)
    }
}

/// RAR 3.x erasure decoder for codewords of `n` bytes with `parity`
/// check symbols and erased positions `erased`.
pub struct Rs8 {
    f: Field,
    n: usize,
    erased: Vec<usize>,
    /// `solve[e][i]`: coefficient of syndrome i in erased value e; empty
    /// when the erasures cannot be recovered.
    solve: Vec<Vec<u32>>,
}

impl Rs8 {
    pub fn new(n: usize, parity: usize, erased: &[usize]) -> Rs8 {
        let f = Field::new(8, 0x11d);
        let k = erased.len();
        let mut solve = Vec::new();
        if k > 0 && k <= parity {
            // With erased symbols set to zero, syndrome i (root a^(i+1))
            // equals sum_e v_e * X_e^(i+1), X_e = a^(n-1-e). The first k
            // syndromes determine the k values.
            let mut m = vec![0u32; k * k];
            for i in 0..k {
                for (j, &e) in erased.iter().enumerate() {
                    m[i * k + j] = f.pow2((n - 1 - e) as u64 * (i as u64 + 1));
                }
            }
            if let Some(inv) = f.invert(&m, k) {
                solve = (0..k).map(|j| (0..k).map(|i| inv[j * k + i]).collect()).collect();
            }
        }
        Rs8 { f, n, erased: erased.to_vec(), solve }
    }

    /// Restores the erased bytes of one codeword (erased bytes are zero).
    pub fn decode(&self, word: &mut [u8]) {
        if self.solve.is_empty() {
            return;
        }
        let k = self.erased.len();
        let mut syn = vec![0u32; k];
        for (i, s) in syn.iter_mut().enumerate() {
            let root = self.f.pow2(i as u64 + 1);
            *s = word[..self.n].iter().fold(0, |acc, &b| self.f.mul(acc, root) ^ b as u32);
        }
        if syn.iter().all(|&s| s == 0) {
            return;
        }
        for (j, &e) in self.erased.iter().enumerate() {
            let v = (0..k).fold(0, |acc, i| acc ^ self.f.mul(self.solve[j][i], syn[i]));
            word[e] = v as u8;
        }
    }
}

/// RAR 5.0 decoder: each missing data volume is a linear combination of
/// the available data volumes and as many recovery volumes.
pub struct Rs16 {
    f: Field,
    /// `coef[k][col]` for missing volume k; `col` is a data volume index,
    /// and for missing data volumes stands for the recovery volume used
    /// in its place.
    coef: Vec<Vec<u32>>,
    logs: Vec<u32>,
}

impl Rs16 {
    /// `valid` flags data volumes followed by recovery volumes. Fails if
    /// there are not enough recovery volumes or nothing to do.
    pub fn new(data: usize, rec: usize, valid: &[bool]) -> Option<Rs16> {
        if data == 0 || rec == 0 || data + rec > 65535 {
            return None;
        }
        let missing: Vec<usize> = (0..data).filter(|&i| !valid[i]).collect();
        let recs: Vec<usize> = (data..data + rec).filter(|&i| valid[i]).collect();
        let k = missing.len();
        if k == 0 || recs.is_empty() || k > recs.len() {
            return None;
        }
        let f = Field::new(16, 0x1100b);
        let cauchy = |r: usize, j: usize| f.inv((r ^ j) as u32);
        let used = &recs[..k];
        // R_r = sum_j C[r][j] D_j, so for the used recovery volumes
        // A * D_missing = R_used + B * D_valid, A = C[used][missing].
        let mut a = vec![0u32; k * k];
        for (i, &r) in used.iter().enumerate() {
            for (j, &m) in missing.iter().enumerate() {
                a[i * k + j] = cauchy(r, m);
            }
        }
        let ainv = f.invert(&a, k)?;
        let mut coef = vec![vec![0u32; data]; k];
        for (row, c) in coef.iter_mut().enumerate() {
            for col in 0..data {
                c[col] = if let Some(slot) = missing.iter().position(|&m| m == col) {
                    ainv[row * k + slot]
                } else {
                    (0..k).fold(0, |acc, i| acc ^ f.mul(ainv[row * k + i], cauchy(used[i], col)))
                };
            }
        }
        Some(Rs16 { f, coef, logs: Vec::new() })
    }

    /// Adds `coef[k][col] * input` to `out` word by word; `input` is the
    /// volume in column `col` (a data volume or the substitute recovery
    /// volume). `first` starts a new output block.
    pub fn accumulate(&mut self, col: usize, k: usize, input: &[u8], out: &mut [u8], first: bool) {
        if col == 0 && first {
            out.fill(0);
        }
        if k == 0 {
            self.logs.clear();
            self.logs.extend(input.chunks(2).map(|w| {
                let v = w[0] as u32 | (*w.get(1).unwrap_or(&0) as u32) << 8;
                if v == 0 { u32::MAX } else { self.f.log[v as usize] }
            }));
        }
        let c = self.coef[k][col];
        if c == 0 {
            return;
        }
        let lc = self.f.log[c as usize];
        for (i, w) in out.chunks_mut(2).enumerate() {
            let l = self.logs[i];
            if l == u32::MAX {
                continue;
            }
            let v = self.f.exp[(l + lc) as usize];
            w[0] ^= v as u8;
            if w.len() > 1 {
                w[1] ^= (v >> 8) as u8;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rs8_recovers_erasures() {
        // Build a codeword: 5 data bytes, 3 parity bytes so that all
        // syndromes vanish, by erasure decoding the parity itself.
        let data = [10u8, 200, 3, 77, 9];
        let n = 8;
        let mut w = [0u8; 8];
        w[..5].copy_from_slice(&data);
        Rs8::new(n, 3, &[5, 6, 7]).decode(&mut w);
        let full = w;
        for erased in [vec![0usize], vec![1, 4], vec![0, 2, 7], vec![5, 6, 7]] {
            let mut x = full;
            for &e in &erased {
                x[e] = 0;
            }
            Rs8::new(n, 3, &erased).decode(&mut x);
            assert_eq!(x, full, "{erased:?}");
        }
    }

    #[test]
    fn rs16_recovers_volumes() {
        let f = Field::new(16, 0x1100b);
        let d = 4;
        let vols: Vec<[u8; 6]> = (0..d).map(|i| [i as u8 * 31 + 1, 7, 200, i as u8, 5, 99]).collect();
        // Recovery volumes 4 and 5.
        let rec: Vec<Vec<u8>> = (d..d + 2)
            .map(|r| {
                let mut out = vec![0u8; 6];
                for (j, v) in vols.iter().enumerate() {
                    let c = f.inv((r ^ j) as u32);
                    for w in 0..3 {
                        let x = f.mul(c, v[2 * w] as u32 | (v[2 * w + 1] as u32) << 8);
                        out[2 * w] ^= x as u8;
                        out[2 * w + 1] ^= (x >> 8) as u8;
                    }
                }
                out
            })
            .collect();
        let valid = [true, false, true, false, true, true];
        let mut rs = Rs16::new(d, 2, &valid).unwrap();
        let mut out = vec![vec![0u8; 6]; 2];
        let mut next_rec = 0;
        for col in 0..d {
            let input: Vec<u8> = if valid[col] {
                vols[col].to_vec()
            } else {
                next_rec += 1;
                rec[next_rec - 1].clone()
            };
            for (k, o) in out.iter_mut().enumerate() {
                rs.accumulate(col, k, &input, o, true);
            }
        }
        assert_eq!(out[0], vols[1]);
        assert_eq!(out[1], vols[3]);
    }
}
