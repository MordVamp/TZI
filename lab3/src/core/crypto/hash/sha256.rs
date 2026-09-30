const INITIAL_HASH: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Clone)]
pub struct Sha256 {
    hash: [u32; 8],
    buffer: [u8; 64],
    length: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            hash: INITIAL_HASH,
            buffer: [0; 64],
            length: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        let mut data_pos = 0;
        let buffer_len = (self.length % 64) as usize;

        // 1. Filling a partial buffer
        if buffer_len > 0 {
            let to_copy = (64 - buffer_len).min(data.len());
            self.buffer[buffer_len..buffer_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.length += to_copy as u64;
            data_pos += to_copy;

            if buffer_len + to_copy == 64 {
                self.process_block();
            }
        }

        // 2.Process remaining data in 64-byte chunks
        while data_pos + 64 <= data.len() {
            self.buffer.copy_from_slice(&data[data_pos..data_pos + 64]);
            self.process_block();
            self.length += 64;
            data_pos += 64;
        }

        // 3.Copy any remaining data to the buffer
        let remaining = &data[data_pos..];
        if !remaining.is_empty() {
            let new_len = (self.length % 64) as usize;
            self.buffer[new_len..new_len + remaining.len()].copy_from_slice(remaining);
            self.length += remaining.len() as u64;
        }

        self
    }

    fn process_block(&mut self) {
        let mut words = [0u32; 64];
        for i in 0..16 {
            words[i] = u32::from_be_bytes([
                self.buffer[i * 4],
                self.buffer[i * 4 + 1],
                self.buffer[i * 4 + 2],
                self.buffer[i * 4 + 3],
            ]);
        }

        for i in 16..64 {
            let s0 = words[i-15].rotate_right(7) ^ words[i-15].rotate_right(18) ^ (words[i-15] >> 3);
            let s1 = words[i-2].rotate_right(17) ^ words[i-2].rotate_right(19) ^ (words[i-2] >> 10);
            words[i] = words[i-16].wrapping_add(s0).wrapping_add(words[i-7]).wrapping_add(s1);
        }

        let mut a = self.hash[0];
        let mut b = self.hash[1];
        let mut c = self.hash[2];
        let mut d = self.hash[3];
        let mut e = self.hash[4];
        let mut f = self.hash[5];
        let mut g = self.hash[6];
        let mut h = self.hash[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(words[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.hash[0] = self.hash[0].wrapping_add(a);
        self.hash[1] = self.hash[1].wrapping_add(b);
        self.hash[2] = self.hash[2].wrapping_add(c);
        self.hash[3] = self.hash[3].wrapping_add(d);
        self.hash[4] = self.hash[4].wrapping_add(e);
        self.hash[5] = self.hash[5].wrapping_add(f);
        self.hash[6] = self.hash[6].wrapping_add(g);
        self.hash[7] = self.hash[7].wrapping_add(h);
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let len_bits = self.length * 8;
        let buffer_len = (self.length % 64) as usize;

        self.buffer[buffer_len] = 0x80;
        let after_80 = buffer_len + 1;

        if after_80 <= 56 {
            // Is there enough room for length in this block?
            self.buffer[after_80..56].fill(0);
            self.buffer[56..64].copy_from_slice(&len_bits.to_be_bytes());
            self.process_block();
        } else {
            // Need an additional block
            self.buffer[after_80..64].fill(0);
            self.process_block();
            self.buffer[0..56].fill(0);
            self.buffer[56..64].copy_from_slice(&len_bits.to_be_bytes());
            self.process_block();
        }

        let mut result = [0u8; 32];
        for (i, &word) in self.hash.iter().enumerate() {
            result[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        result
    }
}