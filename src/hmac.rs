use crate::sha1;

// note that keys larger than block size is not implemented
pub fn hmac_sha1(key: &[u8], bytes: &[u8]) -> [u8; 20] {
  assert!(key.len() <= 64);
  let mut k = [0; 64];
  k[..key.len()].copy_from_slice(key);
  let inner = k.iter().map(|&b| b ^ 0x36).chain(bytes.iter().copied()).collect::<Vec<_>>();
  let inner_hash = sha1::sha1(&inner);
  let tmp = k.iter().map(|&b| b ^ 0x5c)
    .chain(inner_hash)
    .collect::<Vec<_>>();
  sha1::sha1(&tmp)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{to_hex_str, from_hex_str};

  macro_rules! assert_hmac_sha1_eq {
    ($expected:expr, $key:expr, $input:expr) => {
      assert_eq!($expected, to_hex_str(&hmac_sha1($key, $input)))
    };
  }

  #[test]
  fn known_test_vectors() {
    // source: https://datatracker.ietf.org/doc/html/rfc2202
    assert_hmac_sha1_eq!("b617318655057264e28bc0b6fb378c8ef146be00", &[0x0b; 20], b"Hi There");
    assert_hmac_sha1_eq!("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", b"Jefe", b"what do ya want for nothing?");
    assert_hmac_sha1_eq!("125d7342b9ac11cd91a39af48aa17b4f63f175d3", &[0xaa; 20], &[0xdd; 50]);
    assert_hmac_sha1_eq!("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04", &[0x0c; 20], b"Test With Truncation");
    assert_hmac_sha1_eq!("4c9007f4026250c6bc8414f9bf50c86c2d7235da", &from_hex_str("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap(), &[0xcd; 50]);
  }
}
