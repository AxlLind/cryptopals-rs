use std::iter;
use itertools::Itertools;
use openssl::symm::{Cipher, Mode, Crypter};

pub mod b64;

fn from_hex_char(c: char) -> Option<u8> {
  match c {
    '0'..='9' => Some((c as u8) - b'0'),
    'a'..='f' => Some((c as u8) - b'a' + 10),
    'A'..='F' => Some((c as u8) - b'A' + 10),
    _ => None
  }
}

pub fn from_hex_str(hex: &str) -> Option<Vec<u8>> {
  hex.chars()
    .tuples()
    .map(|(c1,c2)| {
      let d1 = from_hex_char(c1)?;
      let d2 = from_hex_char(c2)?;
      Some(d1 * 16 + d2)
    })
    .collect()
}

pub fn to_hex_str(bytes: &[u8]) -> String {
  bytes.iter()
    .flat_map(|&b| [b >> 4, b & 0b1111])
    .map(|b| match b {
      0..=9 => (b + b'0') as char,
      10..=16 => (b + b'a' - 10) as char,
      _ => unreachable!(),
    })
    .collect()
}

// source: https://www3.nd.edu/~busiforc/handouts/cryptography/letterfrequencies.html
pub fn frequency_score(b: u8) -> u64 {
  match (b as char).to_ascii_uppercase() {
    ' ' => 20000,
    'E' => 12000,
    'T' => 9000,
    'A'|'I'|'N'|'O'|'S' => 8000,
    'H' => 6400,
    'R' => 6200,
    'D' => 4400,
    'L' => 4000,
    'U' => 3400,
    'C'|'M' => 3000,
    'F' => 2500,
    'W'|'Y' => 2000,
    'G'|'P' => 1700,
    'B' => 1600,
    'V' => 1200,
    'K' => 800,
    'Q' => 500,
    'J'|'X' => 400,
    'Z' => 200,
    _ => 0
  }
}

pub fn pkcs_pad(bytes: &mut Vec<u8>) {
  let pad_len = (16 - bytes.len() % 16) as u8;
  bytes.extend(iter::repeat(pad_len).take(pad_len as usize));
  assert_eq!(bytes.len() % 16, 0);
}

pub fn pkcs_depad(bytes: &mut Vec<u8>) -> bool {
  if bytes.len() < 16 { return false }
  if bytes.len() % 16 != 0 { return false }
  let pad_byte = *bytes.last().unwrap();
  if pad_byte > 16 { return false }
  let valid_pad = bytes[bytes.len() - pad_byte as usize..].iter().all(|&b| b == pad_byte);
  if !valid_pad { return false }
  bytes.truncate(bytes.len() - pad_byte as usize);
  true
}

fn aes(block: &[u8], key: &[u8], cipher: Cipher, mode: Mode) -> Vec<u8> {
  assert_eq!(block.len() % 16, 0);
  let mut encrypter = Crypter::new(cipher, mode, key, None).unwrap();
  encrypter.pad(false);
  let mut out = vec![0;block.len()+16];
  encrypter.update(&block, &mut out).unwrap();
  out.truncate(block.len());
  out
}

pub fn aes_ecb_decrypt(block: &[u8], key: &[u8]) -> Vec<u8> {
  aes(block, key, Cipher::aes_128_ecb(), Mode::Decrypt)
}

pub fn aes_ecb_encrypt(block: &[u8], key: &[u8]) -> Vec<u8> {
  aes(block, key, Cipher::aes_128_ecb(), Mode::Encrypt)
}

pub fn aes_cbc_decrypt(block: &[u8], key: &[u8]) -> Vec<u8> {
  aes(block, key, Cipher::aes_128_cbc(), Mode::Decrypt)

}

pub fn aes_cbc_encrypt(block: &[u8], key: &[u8]) -> Vec<u8> {
  aes(block, key, Cipher::aes_128_cbc(), Mode::Encrypt)
}

pub fn rand_range(min: u64, max: u64) -> u64 {
  let range = max - min;
  let mut r = range+1;
  while r > range {
    let mut bytes = [0u8;8];
    openssl::rand::rand_bytes(&mut bytes).unwrap();
    r = u64::from_be_bytes(bytes) % range.next_power_of_two();
  }
  r + min
}
