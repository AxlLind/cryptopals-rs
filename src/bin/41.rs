use std::collections::HashSet;

use cryptopals_rs::miller_rabin;
use num::{BigUint, One, Integer};
use num_bigint::{ToBigUint, RandBigInt};

const SECRET_MESSAGE: &[u8] = b"super secret message";

fn gen_rsa_prime(e: &BigUint) -> BigUint {
  let one = BigUint::one();
  loop {
    let p = miller_rabin::rand_prime(512);
    if (&p - &one).gcd(e).is_one() {
      return p
    }
  }
}

struct Server {
  n: BigUint,
  d: BigUint,
  seen_messages: HashSet<Vec<u8>>,
}

impl Server {
  fn new(e: &BigUint) -> Self {
    let p = gen_rsa_prime(e);
    let q = gen_rsa_prime(e);
    let n = &p * &q;
    let one = BigUint::one();
    let d = cryptopals_rs::modinv(e, &((&p - &one) * (&q - &one)));
    Self { n, d, seen_messages: HashSet::default() }
  }

  fn public_key(&self) -> &BigUint { &self.n }

  fn decrypt(&mut self, ciphertext: &Vec<u8>) -> Option<Vec<u8>> {
    if !self.seen_messages.insert(ciphertext.clone()) {
      return None;
    }
    let c = BigUint::from_bytes_be(ciphertext);
    let m = c.modpow(&self.d, &self.n).to_bytes_be();
    Some(m)
  }
}

fn main() {
  let e = 3.to_biguint().unwrap();
  let mut server = Server::new(&e);
  let ciphertext = BigUint::from_bytes_be(SECRET_MESSAGE).modpow(&e, server.public_key()).to_bytes_be();

  assert_eq!(server.decrypt(&ciphertext).unwrap(), SECRET_MESSAGE);
  assert!(server.decrypt(&ciphertext).is_none());

  let s = rand::thread_rng().gen_biguint_below(server.public_key());
  let hacked_ciphertext = (s.modpow(&e, server.public_key()) * BigUint::from_bytes_be(&ciphertext)) % server.public_key();
  let plaintext = server.decrypt(&hacked_ciphertext.to_bytes_be()).unwrap();

  let s_inv = cryptopals_rs::modinv(&s, server.public_key());
  let message = (BigUint::from_bytes_be(&plaintext) * s_inv) % server.public_key();
  assert_eq!(message.to_bytes_be(), SECRET_MESSAGE);
}
