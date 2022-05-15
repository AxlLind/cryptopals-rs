use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, encrypt};


#[derive(PartialEq, Eq, Clone, Copy)]
enum Mode { Ecb, Cbc }

struct Oracle {
  last_mode: Mode
}

impl Oracle {
  fn new() -> Self {
    Self { last_mode: Mode::Ecb }
  }

  fn encrypt(&mut self, bytes: &[u8]) -> Vec<u8> {
    let prefix_len = cryptopals_rs::rand_range(5, 10) as usize;
    let suffix_len = cryptopals_rs::rand_range(5, 10) as usize;
    let len = prefix_len + bytes.len() + suffix_len;
    let mut out = vec![0; len];
    while out.len() % 16 != 0 {
      out.push(0)
    }
    rand_bytes(&mut out[0..prefix_len]).unwrap();
    rand_bytes(&mut out[len - suffix_len..]).unwrap();
    out[prefix_len..len-suffix_len].copy_from_slice(&bytes);
    let mut key = [0; 16];
    rand_bytes(&mut key).unwrap();
    if cryptopals_rs::rand_range(0, 10) % 2 == 0 {
      self.last_mode = Mode::Ecb;
      encrypt(Cipher::aes_128_ecb(), &key, None, &out).unwrap()
    } else {
      self.last_mode = Mode::Cbc;
      let mut iv = [0; 16];
      rand_bytes(&mut iv).unwrap();
      encrypt(Cipher::aes_128_cbc(), &key, Some(&iv), &out).unwrap()
    }
  }

  fn guess_mode(&self, mode: Mode) -> bool {
    mode == self.last_mode
  }
}

fn main() {
  let mut oracle = Oracle::new();

  // encrypt three identical blocks
  // even with the oracle padding this ensures blocks 2 and 3 are identical
  let plaintext = [0; 3*16];
  for _ in 0..100000 {
    let ciphertext = oracle.encrypt(&plaintext);
    let guess = if ciphertext[16..32] == ciphertext[32..48] { Mode::Ecb } else { Mode::Cbc };
    assert!(oracle.guess_mode(guess));
  }
}
