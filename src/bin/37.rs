#![allow(non_snake_case)]
use once_cell::sync::Lazy;
use num_bigint::{ToBigUint, RandBigInt, BigUint};
use openssl::hash::{MessageDigest, hash};

const NIST_MODULI: &[u8] = b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
const G: Lazy<BigUint> = Lazy::new(|| 2.to_biguint().unwrap());
const P: Lazy<BigUint> = Lazy::new(|| BigUint::parse_bytes(NIST_MODULI, 16).unwrap());
const PASSWORD: &[u8] = b"Some super strong password!!#";

struct SrpServer {
  v: BigUint,
  b: BigUint,
  B: BigUint,
}

impl SrpServer {
  fn new() -> Self {
    let mut salt = [0; 32];
    openssl::rand::rand_bytes(&mut salt).unwrap();

    let hash_data = salt.iter().chain(PASSWORD).copied().collect::<Vec<_>>();
    let xH = hash(MessageDigest::sha256(), &hash_data).unwrap();
    let x = BigUint::from_bytes_be(&xH);
    let v = G.modpow(&x, &P);

    let mut rng = rand::thread_rng();
    let b = rng.gen_biguint_below(&P);
    let B = 3.to_biguint().unwrap() * &v + G.modpow(&b, &P);

    Self { v, b, B }
  }

  fn verify(&self, A: &BigUint, hmac: &[u8]) -> bool {
    let hash_data = A.to_bytes_be().iter()
      .chain(self.B.to_bytes_be().iter())
      .copied()
      .collect::<Vec<_>>();
    let uH = hash(MessageDigest::sha256(), &hash_data).unwrap();
    let u = BigUint::from_bytes_be(&uH);

    let s = (A * self.v.modpow(&u, &P)).modpow(&self.b, &P);
    hmac == &*hash(MessageDigest::sha256(), &s.to_bytes_be()).unwrap()
  }
}

fn main() {
  let server = SrpServer::new();

  // S = (A * v**u) ** b % N
  // A == 0 => S = (0 * v**u) ** b % N = 0
  let broken_hmac = hash(MessageDigest::sha256(), &[0]).unwrap().to_vec();
  for i in 0..100 {
    // A = x*p mod p = 0
    let A = i.to_biguint().unwrap() * &*P;
    assert!(server.verify(&A, &broken_hmac));
  }
}
