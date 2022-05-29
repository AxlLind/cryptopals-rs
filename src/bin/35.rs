#![allow(non_snake_case)]
use cryptopals_rs::sha1;
use once_cell::sync::Lazy;
use num_bigint::{ToBigUint, RandBigInt, BigUint};
use openssl::symm::{Cipher, encrypt, decrypt};

const NIST_MODULI: &[u8] = b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
const P: Lazy<BigUint> = Lazy::new(|| BigUint::parse_bytes(NIST_MODULI, 16).unwrap());

struct Client {
  a: BigUint,
  A: BigUint,
  s: Option<BigUint>,
  secret: &'static [u8],
}

impl Client {
  fn new(g: &BigUint, secret: &'static [u8]) -> Self {
    let mut rng = rand::thread_rng();
    let a = rng.gen_biguint_below(&P);
    let A = g.modpow(&a, &P);
    Self { a, A, s: None, secret }
  }

  fn public_key(&self) -> &BigUint { &self.A }

  fn handshake(&mut self, B: &BigUint) {
    self.s = Some(B.modpow(&self.a, &P));
  }

  fn encrypt_secret(&self) -> (Vec<u8>, [u8; 16]) {
    let mut iv = [0; 16];
    openssl::rand::rand_bytes(&mut iv).unwrap();
    let key = sha1::sha1(&self.s.as_ref().unwrap().to_bytes_be());
    let ciphertext = encrypt(Cipher::aes_128_cbc(), &key[..16], Some(&iv), self.secret).unwrap();
    (ciphertext, iv)
  }

  fn decrypt_message(&self, (message, iv): &(Vec<u8>, [u8; 16])) -> Vec<u8> {
    let key = sha1::sha1(&self.s.as_ref().unwrap().to_bytes_be());
    decrypt(Cipher::aes_128_cbc(), &key[..16], Some(iv), message).unwrap()
  }

  fn guess_secret(&self, secret: &[u8]) -> bool {
    self.secret == secret
  }

  fn share_secrets(alice: &Self, bob: &Self) {
    let alice_msg = alice.encrypt_secret();
    let bob_guess = bob.decrypt_message(&alice_msg);
    assert!(alice.guess_secret(&bob_guess));

    let bob_msg = bob.encrypt_secret();
    let alice_guess = alice.decrypt_message(&bob_msg);
    assert!(bob.guess_secret(&alice_guess));
  }
}

fn mitm_chosen_g(g: BigUint, find_shared_key: impl Fn(&BigUint, &Client, &Client) -> BigUint) {
  // setup clients with generator 'g'
  let mut alice = Client::new(&g, b"alice");
  let mut bob = Client::new(&g, b"bob");
  alice.handshake(bob.public_key());
  bob.handshake(alice.public_key());

  // targets can still communicate without issue
  Client::share_secrets(&alice, &bob);

  // find shared key using properties of the insecure generator
  let s = find_shared_key(&g, &alice, &bob);
  let key = sha1::sha1(&s.to_bytes_be());

  // decrypt their messages
  let alice_msg = alice.encrypt_secret();
  let alice_secret = decrypt(Cipher::aes_128_cbc(), &key[..16], Some(&alice_msg.1), &alice_msg.0).unwrap();
  assert!(alice.guess_secret(&alice_secret));

  let bob_msg = bob.encrypt_secret();
  let bob_secret = decrypt(Cipher::aes_128_cbc(), &key[..16], Some(&bob_msg.1), &bob_msg.0).unwrap();
  assert!(bob.guess_secret(&bob_secret));
}

fn main() {
  mitm_chosen_g(1.to_biguint().unwrap(), |_,_,_| {
    // 1^x mod p = 1 for all x
    1.to_biguint().unwrap()
  });

  mitm_chosen_g((&*P).clone(), |_,_,_| {
    // p^x mod p = 0 for all x
    0.to_biguint().unwrap()
  });

  mitm_chosen_g(&*P - 1.to_biguint().unwrap(), |g, alice, bob| {
    /*
      (p-1) = -1 mod p
      => (-1)^x mod p = 1 if x even else (p-1)
      => public keys are 1 or p-1

      there are four possible combinations of public keys:
      (1,1)     | 1^x = 1 => s == 1
      (1,p-1)   | 1^x = 1 => s == 1
      (p-1,1)   | 1^x = 1 => s == 1
      (p-1,p-1) | p odd => (p-1)^(p-1) = (-1)^even = -1 mod p
     */
    if alice.public_key() == g && bob.public_key() == g {
      g.clone()
    } else {
      1.to_biguint().unwrap()
    }
  });
}
