#![allow(non_snake_case)]
use once_cell::sync::Lazy;
use num_bigint::{ToBigUint, RandBigInt, BigUint};
use openssl::hash::{MessageDigest, hash};

const NIST_MODULI: &[u8] = b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
const G: Lazy<BigUint> = Lazy::new(|| 2.to_biguint().unwrap());
const P: Lazy<BigUint> = Lazy::new(|| BigUint::parse_bytes(NIST_MODULI, 16).unwrap());
const PASSWORD: &[u8] = b"Some super strong password!!#";

struct SrpServer {
  salt: [u8; 32],
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

    Self { salt, v, b, B }
  }

  fn public_key(&self) -> &BigUint { &self.B }

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

struct SrpClient {
  a: BigUint,
  A: BigUint,
}

impl SrpClient {
  fn new() -> Self {
    let mut rng = rand::thread_rng();
    let a = rng.gen_biguint_below(&P);
    let A = G.modpow(&a, &P);
    Self { a, A }
  }

  fn public_key(&self) -> &BigUint { &self.A }

  fn compute_hmac(&self, B: &BigUint, salt: &[u8], pw: &[u8]) -> Vec<u8> {
    let hash_data = self.A.to_bytes_be().iter()
      .chain(B.to_bytes_be().iter())
      .copied()
      .collect::<Vec<_>>();
    let uH = hash(MessageDigest::sha256(), &hash_data).unwrap();
    let u = BigUint::from_bytes_be(&uH);

    let hash_data = salt.iter().chain(pw).copied().collect::<Vec<_>>();
    let xH = hash(MessageDigest::sha256(), &hash_data).unwrap();
    let x = BigUint::from_bytes_be(&xH);

    let s = ((&*P + B) - 3.to_biguint().unwrap() * G.modpow(&x, &P) % &*P).modpow(&(&self.a + u * x), &P);
    hash(MessageDigest::sha256(), &s.to_bytes_be()).unwrap().to_vec()
  }
}

fn main() {
  let server = SrpServer::new();
  let client = SrpClient::new();

  let hmac = client.compute_hmac(server.public_key(), &server.salt, &PASSWORD);
  assert!(server.verify(client.public_key(), &hmac));

  let invalid_hmac = client.compute_hmac(server.public_key(), &server.salt, b"Some incorrect password");
  assert!(!server.verify(client.public_key(), &invalid_hmac));
}
