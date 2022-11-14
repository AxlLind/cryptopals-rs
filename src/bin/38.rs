#![allow(non_snake_case)]
use once_cell::sync::Lazy;
use num_bigint::{ToBigUint, RandBigInt, BigUint};
use openssl::hash::{MessageDigest, hash};
use rand::{Rng, seq::SliceRandom};

const NIST_MODULI: &[u8] = b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
const G: Lazy<BigUint> = Lazy::new(|| 2.to_biguint().unwrap());
const P: Lazy<BigUint> = Lazy::new(|| BigUint::parse_bytes(NIST_MODULI, 16).unwrap());
const PASSWORDS: &str = include_str!("../../inputs/top-100-passwords.txt");

fn sha256_salt(salt: &[u8], bytes: &[u8]) -> Vec<u8> {
  let hash_data = salt.iter().chain(bytes).copied().collect::<Vec<_>>();
  hash(MessageDigest::sha256(), &hash_data).unwrap().to_vec()
}

struct Client {
  a: BigUint,
  pw: String,
}

impl Client {
  fn new(passwords: &[&str]) -> Self {
    let mut rng = rand::thread_rng();
    let a = rng.gen_biguint_below(&P);
    let pw = passwords.choose(&mut rng).unwrap().to_string();
    Self { a, pw }
  }

  fn public_key(&self) -> BigUint { G.modpow(&self.a, &P) }

  fn srp_hmac(&self, B: &BigUint, salt: &[u8], u: &BigUint) -> Vec<u8> {
    let x = BigUint::from_bytes_be(&sha256_salt(salt, self.pw.as_bytes()));
    let S = B.modpow(&(&self.a + u * x), &P);
    hash(MessageDigest::sha256(), &S.to_bytes_be()).unwrap().to_vec()
  }

  fn verify(&self, password: &str) -> bool { self.pw == password }
}

fn setup_server() -> ([u8;32], BigUint, BigUint, BigUint) {
  let mut rng = rand::thread_rng();
  let salt = rng.gen();
  let b = rng.gen_biguint_below(&P);
  let B = G.modpow(&b, &P);
  let u = rng.gen_biguint_below(&P);
  (salt, u, b, B)
}

fn verify_protocol() -> bool {
  let (salt, u, b, B) = setup_server();
  let hidden_password = "MargaretThatcheris110%SEXY";
  let client = Client::new(&vec![hidden_password]);
  let A = client.public_key();

  let x = BigUint::from_bytes_be(&sha256_salt(&salt, hidden_password.as_bytes()));
  let v = G.modpow(&x, &P);

  let S = (A * v.modpow(&u, &P)).modpow(&b, &P);
  let srp_hmac = hash(MessageDigest::sha256(), &S.to_bytes_be()).unwrap().to_vec();

  srp_hmac == client.srp_hmac(&B, &salt, &u)
}

fn exploit_protocol(passwords: &[&str]) -> bool {
  let (salt, u, b, B) = setup_server();
  let client = Client::new(&passwords);
  let A = client.public_key();
  let client_srp_hmac = client.srp_hmac(&B, &salt, &u);
  passwords.iter()
    .find(|pw| {
      // S = B**(a + ux) = g**b**(a + ux) = g**(a + ux)**b = (A * g**(ux))**b
      let x = BigUint::from_bytes_be(&sha256_salt(&salt, pw.as_bytes()));
      let S = (&A * G.modpow(&(&u * &x), &P)).modpow(&b, &P);
      let srp_hmac = hash(MessageDigest::sha256(), &S.to_bytes_be()).unwrap().to_vec();
      srp_hmac == client_srp_hmac
    })
    .map(|pw| client.verify(pw))
    .unwrap_or(false)
}

fn main() {
  assert!(verify_protocol());

  let passwords = PASSWORDS.lines().collect::<Vec<_>>();
  for _ in 0..10 {
    assert!(exploit_protocol(&passwords));
  }
}
