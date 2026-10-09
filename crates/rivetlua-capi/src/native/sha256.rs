//! 私有 SHA-256；與 P05 transport 相同的位元演算法，不依賴外部行程。

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

fn block(state: &mut [u32; 8], data: &[u8; 64]) {
    let mut words = [0_u32; 64];
    for (index, bytes) in data.chunks_exact(4).enumerate() {
        words[index] = u32::from_be_bytes(bytes.try_into().expect("四位元組"));
    }
    for index in 16..64 {
        let a = words[index - 15];
        let b = words[index - 2];
        words[index] = words[index - 16]
            .wrapping_add(a.rotate_right(7) ^ a.rotate_right(18) ^ (a >> 3))
            .wrapping_add(words[index - 7])
            .wrapping_add(b.rotate_right(17) ^ b.rotate_right(19) ^ (b >> 10));
    }
    let mut w = *state;
    for (index, word) in words.into_iter().enumerate() {
        let t1 = w[7]
            .wrapping_add(w[4].rotate_right(6) ^ w[4].rotate_right(11) ^ w[4].rotate_right(25))
            .wrapping_add((w[4] & w[5]) ^ (!w[4] & w[6]))
            .wrapping_add(K[index])
            .wrapping_add(word);
        let t2 = (w[0].rotate_right(2) ^ w[0].rotate_right(13) ^ w[0].rotate_right(22))
            .wrapping_add((w[0] & w[1]) ^ (w[0] & w[2]) ^ (w[1] & w[2]));
        w = [
            t1.wrapping_add(t2),
            w[0],
            w[1],
            w[2],
            w[3].wrapping_add(t1),
            w[4],
            w[5],
            w[6],
        ];
    }
    for (slot, work) in state.iter_mut().zip(w) {
        *slot = slot.wrapping_add(work);
    }
}

pub(crate) fn digest(bytes: &[u8]) -> Option<[u8; 32]> {
    let bits = u64::try_from(bytes.len()).ok()?.checked_mul(8)?;
    let mut state = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut chunks = bytes.chunks_exact(64);
    for chunk in &mut chunks {
        block(&mut state, chunk.try_into().expect("完整區塊"));
    }
    let tail = chunks.remainder();
    let mut final_blocks = [0_u8; 128];
    final_blocks[..tail.len()].copy_from_slice(tail);
    final_blocks[tail.len()] = 0x80;
    let used = if tail.len() < 56 { 64 } else { 128 };
    final_blocks[used - 8..used].copy_from_slice(&bits.to_be_bytes());
    for chunk in final_blocks[..used].chunks_exact(64) {
        block(&mut state, chunk.try_into().expect("完整區塊"));
    }
    let mut output = [0_u8; 32];
    for (index, word) in state.into_iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::digest;

    #[test]
    fn known_vectors() {
        assert_eq!(
            digest(b"").unwrap(),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
        assert_eq!(
            digest(b"abc").unwrap(),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn padding_and_multiple_blocks() {
        for (length, expected) in [
            (
                55,
                "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
            ),
            (
                56,
                "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
            ),
            (
                63,
                "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
            ),
            (
                64,
                "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
            ),
            (
                128,
                "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e",
            ),
        ] {
            let actual = digest(&vec![b'a'; length]).unwrap();
            let hex = actual
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(hex, expected, "input length {length}");
        }
    }
}
