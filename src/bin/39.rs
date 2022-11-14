use cryptopals_rs::miller_rabin;
use num::{BigUint, One, Integer};
use num_bigint::ToBigUint;

fn gen_rsa_prime(e: &BigUint) -> BigUint {
  let one = BigUint::one();
  loop {
    let p = miller_rabin::rand_prime(1024);
    if (&p - &one).gcd(e).is_one() {
      return p
    }
  }
}

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
  let p = gen_rsa_prime(&e);
  let q = gen_rsa_prime(&e);
  let n = &p * &q;
  let one = BigUint::one();
  let d = cryptopals_rs::modinv(&e, &((&p - &one) * (&q - &one)));

  let tests = ["42", "The quick brown fox jumps over the lazy dog"];
  for t in tests {
    let ciphertext = encrypt(&e, &n, t.as_bytes());
    assert_eq!(decrypt(&d, &n, &ciphertext), t.as_bytes())
  }
}
