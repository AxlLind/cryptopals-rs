use std::iter;
use itertools::Itertools;
use cryptopals_rs::{aes_ecb_decrypt};

const INPUT: &str = include_str!("../../inputs/10.in");
const KEY: &[u8] = b"YELLOW SUBMARINE";

fn aes_cbc_decrypt(plaintext: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
  iter::once(iv)
    .chain(plaintext.chunks_exact(16))
    .rev()
    .tuple_windows()
    .flat_map(|(a,b)| {
      let mut decrypted = aes_ecb_decrypt(a, key);
      for i in 0..decrypted.len() {
        decrypted[i] ^= b[i];
      }
      decrypted
    })
    .collect()
}

fn main() {
  let bytes = cryptopals_rs::base64_decode(&INPUT.lines().join(""));
  let plaintext = aes_cbc_decrypt(&bytes, &[0;16], KEY);
  println!("{}", String::from_utf8(plaintext).unwrap());
}
