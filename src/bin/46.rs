use num::{BigUint, One, Integer, Zero};
use num_bigint::ToBigUint;
use cryptopals_rs::{miller_rabin, b64};

const SECRET: &str = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";

fn gen_rsa_prime(e: &BigUint) -> BigUint {
  let one = BigUint::one();
  loop {
    let p = miller_rabin::rand_prime(1024);
    if (&p - &one).gcd(e).is_one() {
      return p
    }
  }
}

struct Oracle {
  n: BigUint,
  d: BigUint,
}

impl Oracle {
  fn new(e: &BigUint) -> Self {
    let p = gen_rsa_prime(e);
    let q = gen_rsa_prime(e);
    let n = &p * &q;
    let one = BigUint::one();
    let d = cryptopals_rs::modinv(e, &((&p - &one) * (&q - &one))).unwrap();
    Self { n, d }
  }

  fn public_key(&self) -> &BigUint { &self.n }

  fn get_ciphertext(&self) -> BigUint {
    let msg = b64::decode(SECRET);
    let m = BigUint::from_bytes_be(&msg);
    m.modpow(&3.to_biguint().unwrap(), &self.n)
  }

  fn even(&self, c: &BigUint) -> bool {
    c.modpow(&self.d, &self.n).is_even()
  }
}

fn main() {
  let e = 3.to_biguint().unwrap();
  let oracle = Oracle::new(&e);
  let n = oracle.public_key();
  let mut c = oracle.get_ciphertext();
  let two = 2.to_biguint().unwrap().modpow(&e, n);

  let (mut min, mut max) = (BigUint::zero(), n.clone());
  while &max - &min > BigUint::one() {
    c = (c * &two) % n;
    if oracle.even(&c) {
      max = (&max + &min) >> 1;
    } else {
      min = (&max + &min) >> 1;
    }
  }

  // bruteforce the last byte due to rounding errors
  let mut bytes = max.to_bytes_be();
  let b = (0..=255u8).find(|&b| {
    *bytes.last_mut().unwrap() = b;
    BigUint::from_bytes_be(&bytes).modpow(&e, n) == oracle.get_ciphertext()
  }).unwrap();
  *bytes.last_mut().unwrap() = b;

  let msg = String::from_utf8(bytes).unwrap();
  assert_eq!(msg.as_bytes(), b64::decode(SECRET));
  println!("{}", msg);
}
