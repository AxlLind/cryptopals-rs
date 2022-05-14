use itertools::Itertools;

// You should probably just use a lib for this
// but since the challenge is 'nothing' if you do
// I implemented it myself.

const B64_TABLE: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const INPUT: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
const OUTPUT: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

fn hex_char_to_u8(c: char) -> Option<u8> {
  match c {
    '0'..='9' => Some((c as u8) - b'0'),
    'a'..='f' => Some((c as u8) - b'a' + 10),
    'A'..='F' => Some((c as u8) - b'A' + 10),
    _ => None
  }
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
  hex.chars()
    .tuples()
    .map(|(c1,c2)| {
      let d1 = hex_char_to_u8(c1)?;
      let d2 = hex_char_to_u8(c2)?;
      Some(d1 * 16 + d2)
    })
    .collect()
}

fn base64_encode(bytes: &[u8]) -> String {
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

fn main() {
  let bytes = hex_to_bytes(INPUT).unwrap();
  let base64_str = base64_encode(&bytes);
  println!("Found:    {}", base64_str);
  println!("Expected: {}", OUTPUT);
  assert_eq!(base64_str, OUTPUT);
}
