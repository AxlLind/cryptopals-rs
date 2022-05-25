use std::collections::HashMap;
use itertools::Itertools;
use cryptopals_rs::aes_ctr;
use openssl::rand::rand_bytes;

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

  fn encrypt(&self, bytes: &[u8]) -> Vec<u8> {
    if bytes.contains(&b';') || bytes.contains(&b'=') {
      panic!("Invalid character ';' or '='");
    }
    let tmp = b"comment1=cooking%20MCs;userdata=".iter()
      .chain(bytes)
      .chain(b";comment2=%20like%20a%20pound%20of%20bacon")
      .copied()
      .collect::<Vec<_>>();
    aes_ctr(&self.key, &self.nonce, &tmp)
  }

  fn decrypt(&self, bytes: &[u8]) -> Vec<u8> {
    aes_ctr(&self.key, &self.nonce, bytes)
  }
}

fn main() {
  let oracle = Oracle::new();
  let mut ciphertext = oracle.encrypt(&[0; 16]);

  for (i,x) in b";admin=true;add=".iter().enumerate() {
    ciphertext[32+i] ^= x;
  }
  let plaintext = String::from_utf8(oracle.decrypt(&ciphertext)).unwrap();

  let props = plaintext.split(';')
    .map(|s| s.split_once('=').unwrap())
    .collect::<HashMap<_,_>>();
  assert_eq!(props.get("admin"), Some(&"true"));
  for (k,v) in props.iter().sorted() {
    println!("{} = {:?}", k, v);
  }
}
