use cryptopals_rs::{aes_ctr, aes_ecb_decrypt, b64};
use itertools::Itertools;
use openssl::rand::rand_bytes;

const INPUTS: &str = include_str!("../../inputs/25.in");

struct Oracle {
  key: [u8; 16],
  nonce: [u8; 8],
}

impl Oracle {
  fn new() -> Self {
    let mut key = [0; 16];
    rand_bytes(&mut key).unwrap();
    let mut nonce = [0; 8];
    rand_bytes(&mut nonce).unwrap();
    Self { key, nonce }
  }

  fn encrypt(&self) -> Vec<u8> {
    let ciphertext = b64::decode(&INPUTS.lines().join(""));
    let plaintext = aes_ecb_decrypt(&ciphertext, b"YELLOW SUBMARINE");
    println!("{}", plaintext.iter().map(|&b| b as char).collect::<String>());
    aes_ctr(&self.key, &self.nonce, &plaintext)
  }

  fn edit(&self, ciphertext: &[u8], offset: usize, newtext: &[u8]) -> Vec<u8> {
    let mut plaintext = aes_ctr(&self.key, &self.nonce, ciphertext);
    plaintext[offset..offset+newtext.len()].copy_from_slice(newtext);
    aes_ctr(&self.key, &self.nonce, &plaintext)
  }
}

fn main() {
  let oracle = Oracle::new();
  let ciphertext = oracle.encrypt();
  let zerotext = oracle.edit(&ciphertext, 0, &vec![0; ciphertext.len()]);
  let plaintext = ciphertext.iter().zip(zerotext).map(|(&a,b)| a^b).collect::<Vec<_>>();
  println!("{}", String::from_utf8(plaintext).unwrap());
}
