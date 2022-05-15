use itertools::Itertools;
use openssl::symm::{Cipher, Mode, Crypter};

const B64_ENCODE_TBL: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_DECODE_TBL: [u8; 256] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 0, 0, 0, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0, 0, 0, 0, 0, 0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

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

pub fn base64_encode(bytes: &[u8]) -> String {
  let nchars = ((bytes.len() - 1) / 3) * 4 + 4;
  let mut chars = vec![b'='; nchars];
  let (mut i, mut j) = (0, 0);
  while i < bytes.len() {
    let a = *bytes.get(i+0).unwrap_or(&0) as u32;
    let b = *bytes.get(i+1).unwrap_or(&0) as u32;
    let c = *bytes.get(i+2).unwrap_or(&0) as u32;
    i += 3;

    let combined = ((a << 0x10) + (b << 0x08) + c) as usize;
    chars[j+0] = B64_ENCODE_TBL[(combined >> 3 * 6) & 0x3f];
    chars[j+1] = B64_ENCODE_TBL[(combined >> 2 * 6) & 0x3f];
    chars[j+2] = B64_ENCODE_TBL[(combined >> 1 * 6) & 0x3f];
    chars[j+3] = B64_ENCODE_TBL[(combined >> 0 * 6) & 0x3f];
    j += 4;
  }
  String::from_utf8(chars).unwrap()
}

pub fn base64_decode(s: &str) -> Vec<u8> {
  let s = s.as_bytes();
  assert_eq!(s.len() % 4, 0);
  let mut nbytes = (s.len() / 4) * 3;
  if s[s.len()-1] == b'=' { nbytes -= 1; }
  if s[s.len()-2] == b'=' { nbytes -= 1; }
  let mut bytes = vec![0u8; nbytes];
  let (mut i, mut j) = (0, 0);
  while i < s.len() {
    let a = if s[i+0] == b'=' {0} else {B64_DECODE_TBL[s[i+0] as usize] as u32};
    let b = if s[i+1] == b'=' {0} else {B64_DECODE_TBL[s[i+1] as usize] as u32};
    let c = if s[i+2] == b'=' {0} else {B64_DECODE_TBL[s[i+2] as usize] as u32};
    let d = if s[i+3] == b'=' {0} else {B64_DECODE_TBL[s[i+3] as usize] as u32};
    i += 4;

    let combined = (a << 3*6) + (b << 2*6) + (c << 6) + d;
    if j+0 < nbytes { bytes[j+0] = (combined >> 2*8) as u8; }
    if j+1 < nbytes { bytes[j+1] = (combined >> 1*8) as u8; }
    if j+2 < nbytes { bytes[j+2] = (combined >> 0*8) as u8; }
    j += 3;
  }
  bytes
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

fn aes_ecb(block: &[u8], key: &[u8], mode: Mode) -> Vec<u8> {
  assert_eq!(block.len() % 16, 0);
  let mut encrypter = Crypter::new(Cipher::aes_128_cbc(), mode, key, None).unwrap();
  encrypter.pad(false);
  let mut out = vec![0;block.len()+16];
  encrypter.update(&block, &mut out).unwrap();
  out.truncate(block.len());
  out
}

pub fn aes_ecb_decrypt(block: &[u8], key: &[u8]) -> Vec<u8> {
  aes_ecb(block, key, Mode::Decrypt)
}

pub fn aes_ecb_encrypt(block: &[u8], key: &[u8]) -> Vec<u8> {
  aes_ecb(block, key, Mode::Encrypt)
}
