use itertools::Itertools;

const B64_TABLE: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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
  let mut chars = vec![0; nchars];
  let (mut i, mut j) = (0, 0);
  while i < bytes.len() {
    let a = *bytes.get(i+0).unwrap_or(&0) as u32;
    let b = *bytes.get(i+1).unwrap_or(&0) as u32;
    let c = *bytes.get(i+2).unwrap_or(&0) as u32;
    i += 3;

    let combined = ((a << 0x10) + (b << 0x08) + c) as usize;
    chars[j+0] = B64_TABLE[(combined >> 3 * 6) & 0x3f];
    chars[j+1] = B64_TABLE[(combined >> 2 * 6) & 0x3f];
    chars[j+2] = B64_TABLE[(combined >> 1 * 6) & 0x3f];
    chars[j+3] = B64_TABLE[(combined >> 0 * 6) & 0x3f];
    j += 4;
  }
  String::from_utf8(chars).unwrap()
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
