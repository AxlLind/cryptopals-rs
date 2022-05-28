#![allow(non_snake_case)]
use num_bigint::{ToBigUint, RandBigInt, BigUint};

const NIST_MODULI: &[u8] = b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";

fn diffie_hellman(g: &BigUint, p: &BigUint) -> (BigUint, BigUint, BigUint, BigUint, BigUint) {
  let mut rng = rand::thread_rng();
  let a = rng.gen_biguint_below(&p);
  let A = g.modpow(&a, &p);

  let b = rng.gen_biguint_below(&p);
  let B = g.modpow(&b, &p);

  let s = A.modpow(&b, &p);
  (a, A, b, B, s)
}

fn main() {
  let p = 37.to_biguint().unwrap();
  let g = 5.to_biguint().unwrap();
  let (a, A, b, B, s) = diffie_hellman(&g, &p);
  assert_eq!(A.modpow(&b, &p), s);
  assert_eq!(B.modpow(&a, &p), s);

  let p = BigUint::parse_bytes(NIST_MODULI, 16).unwrap();
  let g = 2.to_biguint().unwrap();
  let (a, A, b, B, s) = diffie_hellman(&g, &p);
  assert_eq!(A.modpow(&b, &p), s);
  assert_eq!(B.modpow(&a, &p), s);
}
