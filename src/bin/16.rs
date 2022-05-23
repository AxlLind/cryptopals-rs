use std::collections::HashMap;
use itertools::Itertools;
use cryptopals_rs::{aes_cbc_encrypt, aes_cbc_decrypt};
use openssl::rand::rand_bytes;

struct Oracle {
  key: [u8; 16]
}

impl Oracle {
  fn new() -> Self {
    let mut key = [0;16];
    rand_bytes(&mut key).unwrap();
    Self { key }
  }

  fn encrypt(&self, bytes: &[u8]) -> Vec<u8> {
    if bytes.contains(&b';') || bytes.contains(&b'=') {
      panic!("Invalid character ';' or '='");
    }
    let mut tmp = b"comment1=cooking%20MCs;userdata=".iter()
      .chain(bytes)
      .chain(b";comment2=%20like%20a%20pound%20of%20bacon")
      .copied()
      .collect();
    cryptopals_rs::pkcs_pad(&mut tmp);
    aes_cbc_encrypt(&tmp, &self.key)
  }

  fn decrypt(&self, bytes: &[u8]) -> Vec<u8> {
    let mut plaintext = aes_cbc_decrypt(&bytes, &self.key);
    assert!(cryptopals_rs::pkcs_depad(&mut plaintext));
    plaintext
  }
}

fn main() {
  let oracle = Oracle::new();
  let mut ciphertext = oracle.encrypt(b"such__data__here");

  let xor_block = b";admin=true;add=".iter()
    .zip(b";comment2=%20lik")
    .map(|(&a, &b)| a^b);
  for (i,x) in xor_block.enumerate() {
    ciphertext[32+i] ^= x;
  }
  let plaintext = oracle.decrypt(&ciphertext).iter()
    .map(|&b| b as char)
    .collect::<String>();

  let props = plaintext.split(';')
    .map(|s| s.split_once('=').unwrap())
    .collect::<HashMap<_,_>>();
  assert_eq!(props.get("admin"), Some(&"true"));
  for (k,v) in props.iter().sorted() {
    println!("{} = {:?}", k, v);
  }
}
