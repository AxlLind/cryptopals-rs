fn pkcs_depad(bytes: &mut Vec<u8>) -> bool {
  if bytes.len() < 16 { return false }
  if bytes.len() % 16 != 0 { return false }
  let pad_byte = *bytes.last().unwrap();
  if pad_byte > 16 { return false }
  let valid_pad = bytes[bytes.len() - pad_byte as usize..].iter().all(|&b| b == pad_byte);
  if !valid_pad { return false }
  bytes.truncate(bytes.len() - pad_byte as usize);
  true
}

fn main() {
  let mut valid = b"ICE ICE BABY\x04\x04\x04\x04".to_vec();
  assert!(pkcs_depad(&mut valid));
  assert_eq!(String::from_utf8(valid).unwrap(), "ICE ICE BABY");

  let mut invalid1 = b"ICE ICE BABY\x05\x05\x05\x05".to_vec();
  assert!(!pkcs_depad(&mut invalid1));

  let mut invalid2 = b"ICE ICE BABY\x01\x02\x03\x04".to_vec();
  assert!(!pkcs_depad(&mut invalid2));
}
