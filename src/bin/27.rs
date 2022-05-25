use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, Mode, Crypter};

fn aes_cbc(block: &[u8], key: &[u8], iv: &[u8], mode: Mode) -> Vec<u8> {
  let mut encrypter = Crypter::new(Cipher::aes_128_cbc(), mode, key, Some(iv)).unwrap();
  encrypter.pad(false);
  let mut out = vec![0;block.len()+16];
  encrypter.update(&block, &mut out).unwrap();
  out.truncate(block.len());
  out
}

struct Oracle {
  key: [u8; 16],
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
    let tmp = b"comment1=cooking%20MCs;userdata=".iter()
      .chain(bytes)
      .chain(b";comment2=%20like%20a%20pound%20of%20bacon")
      .copied()
      .collect::<Vec<_>>();
    aes_cbc(&tmp, &self.key, &self.key, Mode::Encrypt)
  }

  fn decrypt(&self, bytes: &[u8]) -> Vec<u8> {
    aes_cbc(bytes, &self.key, &self.key, Mode::Decrypt)
  }

  fn guess(&self, key: &[u8]) -> bool {
    self.key == key
  }
}

fn main() {
  let oracle = Oracle::new();
  let ciphertext = oracle.encrypt(&[0; 16]);
  let msg = ciphertext[0..16].iter()
    .chain(&[0; 16])
    .chain(&ciphertext[0..16])
    .copied()
    .collect::<Vec<_>>();
  let decrypted = oracle.decrypt(&msg);
  let key = decrypted[0..16].iter()
    .zip(&decrypted[32..48])
    .map(|(&a, &b)| a^b)
    .collect::<Vec<_>>();
  assert!(oracle.guess(&key));
}
