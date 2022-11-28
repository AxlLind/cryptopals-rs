use cryptopals_rs::bn;
use num::{BigUint, One};
use num_bigint::ToBigUint;

fn encrypt(e: &BigUint, n: &BigUint, msg: &[u8]) -> Vec<u8> {
  let m = BigUint::from_bytes_be(msg);
  m.modpow(e, n).to_bytes_be()
}

fn decrypt(d: &BigUint, n: &BigUint, ciphertext: &[u8]) -> Vec<u8> {
  let c = BigUint::from_bytes_be(ciphertext);
  c.modpow(d, n).to_bytes_be()
}

fn main() {
  let e = 3.to_biguint().unwrap();
  let p = bn::gen_rsa_prime(&e, 1024);
  let q = bn::gen_rsa_prime(&e, 1024);
  let n = &p * &q;
  let one = BigUint::one();
  let d = bn::modinv(&e, &((&p - &one) * (&q - &one))).unwrap();

  let tests = ["42", "The quick brown fox jumps over the lazy dog"];
  for t in tests {
    let ciphertext = encrypt(&e, &n, t.as_bytes());
    assert_eq!(decrypt(&d, &n, &ciphertext), t.as_bytes())
  }
}
