use num::Integer;
use num::{BigUint, Zero, One, BigInt, Signed};
use crate::miller_rabin;

pub fn modinv(n: &BigUint, p: &BigUint) -> Option<BigUint> {
  let n = BigInt::from_biguint(num_bigint::Sign::Plus, n.clone());
  let p = BigInt::from_biguint(num_bigint::Sign::Plus, p.clone());
  let (mut a, mut m, mut x, mut inv) = (n.clone(), p.clone(), BigInt::zero(), BigInt::one());
  while a > BigInt::one() {
    if m.is_zero() {
      return None;
    }
    let (div, rem) = a.div_rem(&m);
    inv -= div * &x;
    a = rem;
    std::mem::swap(&mut a, &mut m);
    std::mem::swap(&mut x, &mut inv);
  }
  Some((if inv.is_negative() {inv + p} else {inv}).to_biguint().unwrap())
}

pub fn crt(residues: &[BigUint], modulii: &[BigUint]) -> Option<BigUint> {
  let prod = modulii.iter().product::<BigUint>();
  let mut sum = BigUint::zero();
  for (residue, modulus) in residues.iter().zip(modulii) {
    let p = &prod / modulus;
    sum += residue * modinv(&p, &modulus)? * p
  }
  Some(sum % prod)
}

pub fn gen_rsa_prime(e: &BigUint, bits: u64) -> BigUint {
  let one = BigUint::one();
  loop {
    let p = miller_rabin::rand_prime(bits);
    if (&p - &one).gcd(e).is_one() {
      return p
    }
  }
}
