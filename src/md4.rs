use std::iter;
use itertools::Itertools;

// Implemented myself following the RFC.
// source: https://datatracker.ietf.org/doc/html/rfc1186

const ROUND1_PARAMS: [(usize, u32); 16] = [(0,3),(1,7),(2,11),(3,19),(4,3),(5,7),(6,11),(7,19),(8,3),(9,7),(10,11),(11,19),(12,3),(13,7),(14,11),(15,19)];
const ROUND2_PARAMS: [(usize, u32); 16] = [(0,3),(4,5),(8,9),(12,13),(1,3),(5,5),(9,9),(13,13),(2,3),(6,5),(10,9),(14,13),(3,3),(7,5),(11,9),(15,13)];
const ROUND3_PARAMS: [(usize, u32); 16] = [(0,3),(8,9),(4,11),(12,15),(2,3),(10,9),(6,11),(14,15),(1,3),(9,9),(5,11),(13,15),(3,3),(11,9),(7,11),(15,15)];

fn f(x: u32, y: u32, z: u32) -> u32 { (x & y) | (!x & z) }
fn g(x: u32, y: u32, z: u32) -> u32 { (x & y) | (x & z) | (y & z) }
fn h(x: u32, y: u32, z: u32) -> u32 { x ^ y ^ z }

fn process_block(s: [u32; 4], mut block: impl Iterator<Item=u8>) -> [u32; 4] {
  let mut x = [0; 16];
  for i in 0..16 {
    let (a,b,c,d) = block.next_tuple().unwrap();
    x[i] = u32::from_le_bytes([a,b,c,d]);
  }
  let [mut a, mut b, mut c, mut d] = s;
  macro_rules! md4round {
    ($params:ident, $f:ident, $n:expr) => {
      a = (a + $f(b, c, d) + $n + x[$params[0].0]).rotate_left($params[0].1);
      d = (d + $f(a, b, c) + $n + x[$params[1].0]).rotate_left($params[1].1);
      c = (c + $f(d, a, b) + $n + x[$params[2].0]).rotate_left($params[2].1);
      b = (b + $f(c, d, a) + $n + x[$params[3].0]).rotate_left($params[3].1);
      a = (a + $f(b, c, d) + $n + x[$params[4].0]).rotate_left($params[4].1);
      d = (d + $f(a, b, c) + $n + x[$params[5].0]).rotate_left($params[5].1);
      c = (c + $f(d, a, b) + $n + x[$params[6].0]).rotate_left($params[6].1);
      b = (b + $f(c, d, a) + $n + x[$params[7].0]).rotate_left($params[7].1);
      a = (a + $f(b, c, d) + $n + x[$params[8].0]).rotate_left($params[8].1);
      d = (d + $f(a, b, c) + $n + x[$params[9].0]).rotate_left($params[9].1);
      c = (c + $f(d, a, b) + $n + x[$params[10].0]).rotate_left($params[10].1);
      b = (b + $f(c, d, a) + $n + x[$params[11].0]).rotate_left($params[11].1);
      a = (a + $f(b, c, d) + $n + x[$params[12].0]).rotate_left($params[12].1);
      d = (d + $f(a, b, c) + $n + x[$params[13].0]).rotate_left($params[13].1);
      c = (c + $f(d, a, b) + $n + x[$params[14].0]).rotate_left($params[14].1);
      b = (b + $f(c, d, a) + $n + x[$params[15].0]).rotate_left($params[15].1)
    }
  }
  md4round!(ROUND1_PARAMS, f, 0);
  md4round!(ROUND2_PARAMS, g, 0x5A827999);
  md4round!(ROUND3_PARAMS, h, 0x6ED9EBA1);
  [s[0]+a, s[1]+b, s[2]+c, s[3]+d]
}

pub fn md4_padding(len: usize) -> impl Iterator<Item=u8> {
  let padding = if len % 64 < 56 {0} else {64} + 56 - len % 64;
  iter::once(0x80).pad_using(padding, |_| 0).chain((8 * len as u64).to_le_bytes())
}

pub fn md4_from_state(h: [u32; 4], bytes: &[u8]) -> [u8; 16] {
  let final_state = bytes.iter()
    .copied()
    .chain(md4_padding(bytes.len()))
    .chunks(64)
    .into_iter()
    .fold(h, process_block);
  let mut digest = [0; 16];
  for i in 0..4 {
    digest[i*4..(i+1)*4].copy_from_slice(&final_state[i].to_le_bytes());
  }
  digest
}

pub fn md4(bytes: &[u8]) -> [u8; 16] {
  let initial_state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
  md4_from_state(initial_state, bytes)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{to_hex_str, from_hex_str};

  macro_rules! assert_md4_eq {
    ($expected:expr, $input:expr) => {
      assert_eq!($expected, to_hex_str(&md4($input)))
    };
  }

  #[test]
  fn wikipedia_test_vectors() {
    // testcase from wiki: https://en.wikipedia.org/wiki/MD4#MD4_test_vectors
    assert_md4_eq!("31d6cfe0d16ae931b73c59d7e0c089c0", b"");
    assert_md4_eq!("bde52cb31de33e46245e05fbdbd6fb24", b"a");
    assert_md4_eq!("a448017aaf21d8525fc10ae87aa6729d", b"abc");
    assert_md4_eq!("d9130a8164549fe818874806e1c7014b", b"message digest");
    assert_md4_eq!("d79e1c308aa5bbcdeea8ed63df412da9", b"abcdefghijklmnopqrstuvwxyz");
    assert_md4_eq!("043f8582f241db351ce627e153e7f0e4", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    assert_md4_eq!("e33b4ddc9c38f2199c3e7b164fcc0536", b"12345678901234567890123456789012345678901234567890123456789012345678901234567890");
    assert_md4_eq!("1bee69a46ba811185c194762abaeae90", b"The quick brown fox jumps over the lazy dog");
    assert_md4_eq!("b86e130ce7028da59e672d56ad0113df", b"The quick brown fox jumps over the lazy cog");

    // collision example
    assert_md4_eq!("4d7e6a1defa93d2dde05b45d864c429b", &from_hex_str("839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edd45e51fe39708bf9427e9c3e8b9").unwrap());
    assert_md4_eq!("4d7e6a1defa93d2dde05b45d864c429b", &from_hex_str("839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edc45e51fe39708bf9427e9c3e8b9").unwrap());
  }
}
