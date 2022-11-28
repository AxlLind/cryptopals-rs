use std::collections::HashSet;

use num::{BigUint, One};
use num_bigint::{ToBigUint, RandBigInt};
use cryptopals_rs::bn;

const SECRET_MESSAGE: &[u8] = b"super secret message";

struct Server {
  n: BigUint,
  d: BigUint,
  seen_messages: HashSet<Vec<u8>>,
}

impl Server {
  fn new(e: &BigUint) -> Self {
    let p = bn::gen_rsa_prime(e, 512);
    let q = bn::gen_rsa_prime(e, 512);
    let n = &p * &q;
    let one = BigUint::one();
    let d = bn::modinv(e, &((&p - &one) * (&q - &one))).unwrap();
    Self { n, d, seen_messages: HashSet::default() }
  }

  fn public_mod(&self) -> &BigUint { &self.n }

  fn decrypt(&mut self, ciphertext: &Vec<u8>) -> Option<Vec<u8>> {
    if !self.seen_messages.insert(ciphertext.clone()) {
      return None;
    }
    let c = BigUint::from_bytes_be(ciphertext);
    Some(c.modpow(&self.d, &self.n).to_bytes_be())
  }
}

fn main() {
  let e = 3.to_biguint().unwrap();
  let mut server = Server::new(&e);
  let n = server.public_mod().clone();
  let ciphertext = BigUint::from_bytes_be(SECRET_MESSAGE).modpow(&e, &n).to_bytes_be();

  assert_eq!(server.decrypt(&ciphertext).unwrap(), SECRET_MESSAGE);
  assert!(server.decrypt(&ciphertext).is_none());

  let s = rand::thread_rng().gen_biguint_below(&n);
  let hacked_ciphertext = (s.modpow(&e, &n) * BigUint::from_bytes_be(&ciphertext)) % &n;
  let plaintext = server.decrypt(&hacked_ciphertext.to_bytes_be()).unwrap();

  let s_inv = bn::modinv(&s, &n).unwrap();
  let message = (BigUint::from_bytes_be(&plaintext) * s_inv) % &n;
  assert_eq!(message.to_bytes_be(), SECRET_MESSAGE);
}
