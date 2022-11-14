use cryptopals_rs::miller_rabin;
use num::{BigUint, One, Integer};
use num_bigint::ToBigUint;

const SECRET_MESSAGE: &[u8] = b"super secret message to decrypt";

fn gen_rsa_prime(e: &BigUint) -> BigUint {
  let one = BigUint::one();
  loop {
    let p = miller_rabin::rand_prime(1024);
    if (&p - &one).gcd(e).is_one() {
      return p
    }
  }
}

fn main() {
  let e = 3.to_biguint().unwrap();
  let n1 = gen_rsa_prime(&e) * gen_rsa_prime(&e);
  let n2 = gen_rsa_prime(&e) * gen_rsa_prime(&e);
  let n3 = gen_rsa_prime(&e) * gen_rsa_prime(&e);

  let m = BigUint::from_bytes_be(SECRET_MESSAGE);
  let c1 = m.modpow(&e, &n1);
  let c2 = m.modpow(&e, &n2);
  let c3 = m.modpow(&e, &n3);

  let result = cryptopals_rs::crt(&[c1, c2, c3], &[n1, n2, n3]).unwrap();
  assert_eq!(result.nth_root(3).to_bytes_be(), SECRET_MESSAGE);
}
