use cryptopals_rs::mt19937::MT19937;
use openssl::rand::rand_bytes;
use std::time::{SystemTime, UNIX_EPOCH};

fn mt19937_cipher(key: u16, bytes: &[u8]) -> Vec<u8> {
  let mut mt19937 = MT19937::from_seed(key as u32);
  let key_stream = (0..).flat_map(|_| mt19937.gen().to_be_bytes());
  key_stream.zip(bytes).map(|(a, &b)| a ^ b).collect()
}

struct Oracle {
  key: u16
}

impl Oracle {
  fn new() -> Self {
    Self { key: 0 }
  }

  fn encrypt(&mut self, bytes: &[u8]) -> Vec<u8> {
    self.key = {
      let mut tmp = [0;2];
      rand_bytes(&mut tmp).unwrap();
      u16::from_be_bytes(tmp)
    };
    mt19937_cipher(self.key, bytes)
  }

  fn guess(&self, key: u16) -> bool { self.key == key }
}

fn gen_pw_reset_token() -> Vec<u8> {
  let key = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs() as u16;
  let mut mt19937 = MT19937::from_seed(key as u32);
  (0..).flat_map(|_| mt19937.gen().to_be_bytes()).take(32).collect()
}

fn validate_pw_reset_token(token: &[u8]) -> bool {
  (0..=u16::MAX).any(|key| {
    let mut mt19937 = MT19937::from_seed(key as u32);
    (0..).flat_map(|_| mt19937.gen().to_be_bytes()).take(32).eq(token.iter().copied())
  })
}

fn main() {
  // verify that the cipher works
  let ciphertext = mt19937_cipher(1337, b"secret message");
  assert_eq!(mt19937_cipher(1337, &ciphertext), b"secret message");

  // brute force key
  let mut oracle = Oracle::new();
  let ciphertext = oracle.encrypt(b"aaaaaaaaaaaaaaaaaaaa");
  let key = (0..=u16::MAX)
    .find(|&key| mt19937_cipher(key, &ciphertext) == b"aaaaaaaaaaaaaaaaaaaa")
    .unwrap();
  assert!(oracle.guess(key));

  // validate pw reset token
  let token = gen_pw_reset_token();
  assert!(validate_pw_reset_token(&token));
  assert!(!validate_pw_reset_token(&[0; 32]));
}
