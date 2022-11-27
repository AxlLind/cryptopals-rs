use num::{BigUint, Zero, Num};
use num_bigint::{RandBigInt};

fn int_hash(message: &[u8]) -> BigUint { BigUint::from_bytes_be(&cryptopals_rs::sha1::sha1(message)) }

fn dsa_sign(p: &BigUint, q: &BigUint, g: &BigUint, x: &BigUint, message: &[u8]) -> (BigUint, BigUint, BigUint) {
  let mut rng = rand::thread_rng();
  let h = int_hash(message);
  loop {
    let k = rng.gen_biguint_below(q);
    let r = g.modpow(&k, p) % q;
    // this check should normally be done, however with malicious parameters we hit this always
    // if r.is_zero() {
    //   continue;
    // }
    let s = (cryptopals_rs::modinv(&k, q).unwrap() * (&h + x * &r)) % q;
    if !s.is_zero() {
      return (r, s, k);
    }
  }
}

fn dsa_verify(p: &BigUint, q: &BigUint, g: &BigUint, y: &BigUint, message: &[u8], r: &BigUint, s: &BigUint) -> bool {
  if r >= q || s >= q {
    return false;
  }
  let h = int_hash(message);
  let w = cryptopals_rs::modinv(s, q).unwrap();
  let u1 = (&h * &w) % q;
  let u2 = (r * &w) % q;
  let v = ((g.modpow(&u1, p) * y.modpow(&u2, p)) % p) % q;
  &v == r
}

fn main() {
  let p = BigUint::from_str_radix("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16).unwrap();
  let q = BigUint::from_str_radix("f4f47f05794b256174bba6e9b396a7707e563c5b", 16).unwrap();
  let mut rng = rand::thread_rng();
  let x = rng.gen_biguint_below(&q);

  // g = 0 => r = 0
  assert_eq!(dsa_sign(&p, &q, &BigUint::zero(), &x, b"Hello, world").0, BigUint::zero());
  assert_eq!(dsa_sign(&p, &q, &BigUint::zero(), &x, b"Goodbye, world").0, BigUint::zero());

  let g = &p + BigUint::zero();
  let y = g.modpow(&x, &p);

  let z = rng.gen_biguint_below(&q);
  let r = y.modpow(&z, &p) % &q;
  let s = (&r * cryptopals_rs::modinv(&z, &q).unwrap()) % &q;
  assert!(dsa_verify(&p, &q, &g, &y, b"Hello, world", &r, &s));
  assert!(dsa_verify(&p, &q, &g, &y, b"Goodbye, world", &r, &s));
}
