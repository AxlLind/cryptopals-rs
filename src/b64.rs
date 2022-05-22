const B64_ENCODE_TBL: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_DECODE_TBL: [u8; 256] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 0, 0, 0, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0, 0, 0, 0, 0, 0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

pub fn encode(bytes: &[u8]) -> String {
  if bytes.len() == 0 { return String::new(); }
  let mut chars = vec![0; ((bytes.len() - 1) / 3) * 4 + 4];
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

  let padding = [0,2,1][bytes.len() % 3];
  for i in 0..padding {
    let len = chars.len();
    chars[len - 1 - i] = b'=';
  }

  String::from_utf8(chars).unwrap()
}

pub fn decode(s: &str) -> Vec<u8> {
  if s.len() == 0 { return Vec::new(); }
  let s = s.as_bytes();
  assert_eq!(s.len() % 4, 0);
  let mut nbytes = (s.len() / 4) * 3;
  if let Some(b'=') = s.get(s.len()-1) { nbytes -= 1; }
  if let Some(b'=') = s.get(s.len()-2) { nbytes -= 1; }
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_encode() {
    // source: https://stackoverflow.com/questions/12069598/is-there-a-dataset-available-to-fully-test-a-base64-encode-decoder
    assert_eq!(encode(b""), "");
    assert_eq!(encode(b"f"), "Zg==");
    assert_eq!(encode(b"fo"), "Zm8=");
    assert_eq!(encode(b"foo"), "Zm9v");
    assert_eq!(encode(b"foob"), "Zm9vYg==");
    assert_eq!(encode(b"fooba"), "Zm9vYmE=");
    assert_eq!(encode(b"foobar"), "Zm9vYmFy");
  }

  #[test]
  fn test_decode() {
    assert_eq!(decode(""), b"");
    assert_eq!(decode("Zg=="), b"f");
    assert_eq!(decode("Zm8="), b"fo");
    assert_eq!(decode("Zm9v"), b"foo");
    assert_eq!(decode("Zm9vYg=="), b"foob");
    assert_eq!(decode("Zm9vYmE="), b"fooba");
    assert_eq!(decode("Zm9vYmFy"), b"foobar");
  }
}
