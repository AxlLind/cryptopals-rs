use std::iter;
use itertools::Itertools;

// challenge 28 says to find an implementation online,
// however implementing it yourself is more fun

fn process_block(h: [u32; 5], mut block: impl Iterator<Item=u8>) -> [u32; 5] {
  let mut w = [0; 80];
  for i in 0..16 {
    let (a,b,c,d) = block.next_tuple().unwrap();
    w[i] = u32::from_be_bytes([a,b,c,d]);
  }
  for i in 16..80 {
    w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
  }
  let [mut a, mut b, mut c, mut d, mut e] = h;
  for i in 0..80 {
    let (k, f) = match i {
      0..=19  => (0x5A827999, (b & c) | (!b & d)),
      20..=39 => (0x6ED9EBA1, b ^ c ^ d),
      40..=59 => (0x8F1BBCDC, (b & c) | (b & d) | (c & d)),
      _       => (0xCA62C1D6, b ^ c ^ d),
    };
    let tmp = a.rotate_left(5) + f + e + k + w[i];
    [a, b, c, d, e] = [tmp, a, b.rotate_left(30), c, d];
  }
  [h[0]+a, h[1]+b, h[2]+c, h[3]+d, h[4]+e]
}

pub fn sha1_padding(len: usize) -> impl Iterator<Item=u8> {
  let padding = if len % 64 < 56 {0} else {64} + 56 - len % 64;
  iter::once(0x80).pad_using(padding, |_| 0).chain((8 * len as u64).to_be_bytes())
}

pub fn sha1_from_state(h: [u32; 5], bytes: &[u8]) -> [u8; 20] {
  let final_state = bytes.iter()
    .copied()
    .chain(sha1_padding(bytes.len()))
    .chunks(64)
    .into_iter()
    .fold(h, process_block);
  let mut digest = [0; 20];
  for i in 0..5 {
    digest[i*4..(i+1)*4].copy_from_slice(&final_state[i].to_be_bytes());
  }
  digest
}

pub fn sha1(bytes: &[u8]) -> [u8; 20] {
  let initial_h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
  sha1_from_state(initial_h, bytes)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::to_hex_str;

  macro_rules! assert_sha1_eq {
    ($expected:expr, $input:expr) => {
      assert_eq!($expected, to_hex_str(&sha1($input)))
    };
  }

  #[test]
  fn known_test_vectors() {
    // source: https://en.wikipedia.org/wiki/SHA-1#Example_hashes
    assert_sha1_eq!("da39a3ee5e6b4b0d3255bfef95601890afd80709", b"");
    assert_sha1_eq!("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", b"The quick brown fox jumps over the lazy dog");
    assert_sha1_eq!("de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3", b"The quick brown fox jumps over the lazy cog");

    // source: https://www.di-mgt.com.au/sha_testvectors.html
    assert_sha1_eq!("a9993e364706816aba3e25717850c26c9cd0d89d", b"abc");
    assert_sha1_eq!("84983e441c3bd26ebaae4aa1f95129e5e54670f1", b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert_sha1_eq!("a49b2446a02c645bf419f995b67091253a04a259", b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
    assert_sha1_eq!("34aa973cd4c4daa4f61eeb2bdbad27316534016f", &[b'a'; 1_000_000]);
  }
}
