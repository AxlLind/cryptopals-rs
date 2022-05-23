use cryptopals_rs::b64;
use itertools::Itertools;
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, encrypt, decrypt};

const MESSAGES: [&str; 10] = [
  "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
  "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
  "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
  "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
  "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
  "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
  "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
  "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
  "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
  "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];

struct Oracle {
  iv: [u8; 16],
  key: [u8; 16],
  messages: Vec<Vec<u8>>,
}

impl Oracle {
  fn new() -> Self {
    let mut iv = [0;16];
    rand_bytes(&mut iv).unwrap();
    let mut key = [0;16];
    rand_bytes(&mut key).unwrap();
    let mut messages = MESSAGES.iter()
      .map(|&s| b64::decode(s))
      .collect::<Vec<_>>();
    for i in 0..messages.len() {
      cryptopals_rs::pkcs_pad(&mut messages[i]);
    }
    Self { iv, key, messages }
  }

  fn get_iv(&self) -> [u8; 16] { self.iv }

  fn get_ciphertext(&self) -> Vec<u8> {
    let i = cryptopals_rs::rand_range(0, 9) as usize;
    encrypt(Cipher::aes_128_cbc(), &self.key, Some(&self.iv), &self.messages[i]).unwrap()
  }

  fn decrypt(&self, bytes: &[u8], iv: &[u8]) -> bool {
    decrypt(Cipher::aes_128_cbc(), &self.key, Some(iv), bytes).is_ok()
  }
}

fn fetch_all_ciphertexts(oracle: &Oracle) -> Vec<Vec<u8>> {
  (0..).map(|_| oracle.get_ciphertext()).unique().take(10).collect()
}

fn decrypt_byte(oracle: &Oracle, text: &mut Vec<u8>, block: &[u8], b: u8) -> u8 {
  let len = text.len();
  for guess in 2..=0x7f {
    text[len - 1 - b as usize] ^= (b+1) ^ guess;
    let ciphertext = text[16..].iter().chain(block).copied().collect::<Vec<_>>();
    if oracle.decrypt(&ciphertext, &text[..16]) {
      return guess;
    }
    text[len - 1 - b as usize] ^= (b+1) ^ guess;
  }
  panic!("Could not find byte!")
}

fn pad_oracle_exploit(oracle: &Oracle, ciphertext: &[u8]) -> Vec<u8> {
  let iv = oracle.get_iv();
  let mut plaintext = Vec::new();
  for i in (0..ciphertext.len()).step_by(16) {
    let mut decrypted = Vec::new();
    for b in 0..16 {
      let mut text = iv.iter().chain(&ciphertext[0..i]).copied().collect::<Vec<_>>();
      let len = text.len();
      for (j, x) in decrypted.iter().enumerate() {
        text[len - 1 - j] ^= (b+1) ^ x;
      }
      decrypted.push(decrypt_byte(oracle, &mut text, &ciphertext[i..i+16], b));
    }
    plaintext.extend(decrypted.iter().rev())
  }
  assert!(cryptopals_rs::pkcs_depad(&mut plaintext));
  assert!(cryptopals_rs::pkcs_depad(&mut plaintext));
  plaintext
}

fn main() {
  let oracle = Oracle::new();
  let ciphertexts = fetch_all_ciphertexts(&oracle);
  let plaintexts = ciphertexts.iter().map(|c| pad_oracle_exploit(&oracle, &c)).sorted();
  for s in plaintexts {
    println!("{}", String::from_utf8(s).unwrap());
  }
}
