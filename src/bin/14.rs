use itertools::Itertools;
use openssl::rand::rand_bytes;
use cryptopals_rs::b64;

const INPUT: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

struct Oracle {
  key: [u8; 16],
  prefix: Vec<u8>,
  target: Vec<u8>,
}

impl Oracle {
  fn new() -> Self {
    let mut key = [0; 16];
    rand_bytes(&mut key).unwrap();
    let prefix_len = cryptopals_rs::rand_range(5, 20);
    let mut prefix = vec![0; prefix_len as usize];
    rand_bytes(&mut prefix).unwrap();
    let target = b64::decode(INPUT);
    Self { key, prefix, target }
  }

  fn encrypt(&self, bytes: &[u8]) -> Vec<u8> {
    let mut tmp = self.prefix.iter()
      .chain(bytes.iter())
      .chain(self.target.iter())
      .copied()
      .collect::<Vec<_>>();
    cryptopals_rs::pkcs_pad(&mut tmp);
    cryptopals_rs::aes_ecb_encrypt(&tmp, &self.key)
  }
}

fn find_prefix_len(oracle: &Oracle) -> usize {
  // if we're unlucky the final byte of the prefix is the same as our block
  // so do the process twice and take the maximum
  [0, 1].iter()
    .map(|&block_byte| {
      // try to line up two identical blocks at exactly a block boundry
      // from what we can find the prefix length
      let mut msg = vec![block_byte; 32];
      loop {
        let ciphertext = oracle.encrypt(&msg);
        let zero_block = ciphertext.chunks(16)
          .tuple_windows()
          .enumerate()
          .find(|(_, (a,b))| a == b);
        if let Some((i, _)) = zero_block {
          return i * 16 - msg.len() + 32;
        }
        msg.push(block_byte);
      }
    })
    .max()
    .unwrap()
}

fn decrypt_byte(oracle: &Oracle, prefix_len: usize, known_text: &[u8]) -> Option<u8> {
  // we need to pad the message such that the
  // target byte ends up at the end of a block
  let pad_len = (16 - prefix_len % 16) + 15 - known_text.len() % 16;
  let mut msg = vec![0; pad_len];
  let expectedtext = oracle.encrypt(&msg);

  msg.extend(known_text);
  msg.push(0);
  let n = msg.len() - 1;
  (0u8..=0xff).find(|&b| {
    msg[n] = b;
    let ciphertext = oracle.encrypt(&msg);
    ciphertext[n-15..=n] == expectedtext[n-15..=n]
  })
}

fn main() {
  let oracle = Oracle::new();

  let prefix_len = find_prefix_len(&oracle);

  let mut plaintext = Vec::new();
  while let Some(b) = decrypt_byte(&oracle, prefix_len, &plaintext) {
    plaintext.push(b);
  }
  cryptopals_rs::pkcs_depad(&mut plaintext);
  println!("{}", String::from_utf8(plaintext).unwrap());
}
