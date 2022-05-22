use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, encrypt};
use cryptopals_rs::b64;

const INPUT: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

struct Oracle {
  key: [u8; 16],
  target: Vec<u8>,
}

impl Oracle {
  fn new() -> Self {
    let mut key = [0; 16];
    rand_bytes(&mut key).unwrap();
    let target = b64::decode(INPUT);
    Self { key, target }
  }

  fn encrypt(&self, bytes: &[u8]) -> Vec<u8> {
    let tmp = bytes.iter()
      .chain(self.target.iter())
      .chain(&[0;16])
      .copied()
      .collect::<Vec<_>>();
    encrypt(Cipher::aes_128_ecb(), &self.key, None, &tmp).unwrap()
  }
}

fn find_blocksize(oracle: &Oracle) -> usize {
  let mut plaintext = Vec::new();
  let mut last_size = 1000;
  let mut prelen = None;
  loop {
    plaintext.push(b'a');
    let ciphertext = oracle.encrypt(&plaintext);
    if last_size < ciphertext.len() {
      if let Some(prelen) = prelen {
        return plaintext.len() - prelen;
      }
      prelen = Some(plaintext.len());
    }
    last_size = ciphertext.len();
  }
}

fn decrypt_byte(oracle: &Oracle, known_text: &[u8]) -> u8 {
  // we need to pad the message such that the
  // target byte ends up at the end of a block
  let mut msg = vec![0; 15 - known_text.len() % 16];
  let expectedtext = oracle.encrypt(&msg);

  // extend the padding with the decrypted plaintext
  // and push a spot for the guess byte
  msg.extend(known_text);
  msg.push(0);
  let n = msg.len() - 1;
  (0u8..=0xff).find(|&b| {
    // guess that the byte is `b`
    // check if the ciphertext is the expected one
    msg[n] = b;
    let ciphertext = oracle.encrypt(&msg);
    ciphertext[n-15..=n] == expectedtext[n-15..=n]
  }).unwrap()
}

fn main() {
  let oracle = Oracle::new();

  // find the block size
  let blocksize = find_blocksize(&oracle);
  assert_eq!(blocksize, 16);

  // verify that it's using ecb
  let ecb_test = oracle.encrypt(&[0; 32]);
  assert_eq!(ecb_test[0..16], ecb_test[16..32]);

  let mut plaintext = vec![];
  loop {
    let b = decrypt_byte(&oracle, &plaintext);
    if b == 0 { break }
    plaintext.push(b);
  }
  println!("{}", String::from_utf8(plaintext).unwrap());
}
