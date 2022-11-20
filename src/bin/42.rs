use std::iter;

use cryptopals_rs::miller_rabin;
use num::{BigUint, One, Integer};
use num_bigint::ToBigUint;
use cryptopals_rs::sha1::sha1;

const ASN1_SHA: [u8; 15] = [0x30, 0x21, 0x30, 0x9, 0x6, 0x5, 0x2b, 0xe, 0x3, 0x2, 0x1a, 0x5, 0x0, 0x4, 0x14];
const SECRET_MESSAGE: &[u8] = b"hi mom";

fn gen_rsa_prime(e: &BigUint) -> BigUint {
  let one = BigUint::one();
  loop {
    let p = miller_rabin::rand_prime(1024);
    if (&p - &one).gcd(e).is_one() {
      return p
    }
  }
}

fn produce_signature(d: &BigUint, n: &BigUint, message: &[u8]) -> BigUint {
  // Pad according to: https://datatracker.ietf.org/doc/html/rfc3447#section-9.2
  let padded_msg = [0, 1].iter()
    .chain(iter::repeat(&0xff).take(message.len() - 3))
    .chain([0].iter())
    .chain(&ASN1_SHA)
    .chain(sha1(message).iter())
    .copied()
    .collect::<Vec<_>>();
  BigUint::from_bytes_be(&padded_msg).modpow(d, n)
}

fn verify_signature(n: &BigUint, message: &[u8], signature: &BigUint) -> bool {
  let m = signature.modpow(&3.to_biguint().unwrap(), n).to_bytes_be();
  if m[0] != 1 {
    return false;
  }
  let Some(i) = m[1..].iter().position(|&b| b != 0xff) else { return false };
  if m[i+1] != 0 {
    return false;
  }
  if !m[i+2..].starts_with(&ASN1_SHA) {
    return false;
  }
  m[i+2+15..].starts_with(&cryptopals_rs::sha1::sha1(message))
}

fn main() {
  let e = 3.to_biguint().unwrap();
  let p = gen_rsa_prime(&e);
  let q = gen_rsa_prime(&e);
  let n = &p * &q;
  let one = BigUint::one();
  let d = cryptopals_rs::modinv(&e, &((&p - &one) * (&q - &one))).unwrap();

  let signature = produce_signature(&d, &n, SECRET_MESSAGE);
  assert!(verify_signature(&n, SECRET_MESSAGE, &signature));

  let malicious_padding = [0, 1, 0xff, 0].iter()
    .chain(&ASN1_SHA)
    .chain(sha1(SECRET_MESSAGE).iter())
    .chain(iter::repeat(&0))
    .take(128)
    .copied()
    .collect::<Vec<_>>();
  // +1 since nth_root rounds down
  let malicious_signature = BigUint::from_bytes_be(&malicious_padding).nth_root(3) + BigUint::one();
  assert!(verify_signature(&n, &SECRET_MESSAGE, &malicious_signature));
}
