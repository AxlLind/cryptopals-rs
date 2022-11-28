use num::{BigUint, Zero, Num};
use num_bigint::{RandBigInt, ToBigUint};
use cryptopals_rs::bn;

const MESSAGE: &[u8] = b"For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n";

fn int_hash(message: &[u8]) -> BigUint { BigUint::from_bytes_be(&cryptopals_rs::sha1::sha1(message)) }

fn dsa_sign(p: &BigUint, q: &BigUint, g: &BigUint, x: &BigUint, message: &[u8]) -> (BigUint, BigUint, BigUint) {
  let mut rng = rand::thread_rng();
  let h = int_hash(message);
  loop {
    let k = rng.gen_biguint_below(q);
    let r = g.modpow(&k, p) % q;
    if r.is_zero() {
      continue;
    }
    let s = (bn::modinv(&k, q).unwrap() * (&h + x * &r)) % q;
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
  let w = bn::modinv(s, q).unwrap();
  let u1 = (&h * &w) % q;
  let u2 = (r * &w) % q;
  let v = ((g.modpow(&u1, p) * y.modpow(&u2, p)) % p) % q;
  &v == r
}

fn extract_secret_key(q: &BigUint, r: &BigUint, s: &BigUint, k: &BigUint, message: &[u8]) -> BigUint {
  let h = int_hash(message);
  (((q + s * k) - h) * bn::modinv(r, q).unwrap()) % q
}

fn verify_protocol(p: &BigUint, q: &BigUint, g: &BigUint) {
  let mut rng = rand::thread_rng();
  let x = rng.gen_biguint_below(&q);
  let y = g.modpow(&x, &p);
  let message = b"hello world";
  let (r, s, k) = dsa_sign(&p, &q, &g, &x, message);
  assert!(dsa_verify(&p, &q, &g, &y, message, &r, &s));
  assert_eq!(extract_secret_key(&q, &r, &s, &k, message), x);
}

fn main() {
  let p = BigUint::from_str_radix("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16).unwrap();
  let q = BigUint::from_str_radix("f4f47f05794b256174bba6e9b396a7707e563c5b", 16).unwrap();
  let g = BigUint::from_str_radix("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16).unwrap();
  verify_protocol(&p, &q, &g);

  assert_eq!(int_hash(MESSAGE).to_str_radix(16), "d2d0714f014a9784047eaeccf956520045c45265");
  let y = BigUint::from_str_radix("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16).unwrap();
  let r = "548099063082341131477253921760299949438196259240".parse::<BigUint>().unwrap();
  let s = "857042759984254168557880549501802188789837994940".parse::<BigUint>().unwrap();
  assert!(dsa_verify(&p, &q, &g, &y, MESSAGE, &r, &s));

  let x = (0..=65536)
    .map(|k| extract_secret_key(&q, &r, &s, &k.to_biguint().unwrap(), MESSAGE))
    .find(|x| g.modpow(&x, &p) == y)
    .unwrap();
  assert_eq!(int_hash(x.to_str_radix(16).as_bytes()).to_str_radix(16), "954edd5e0afe5542a4adf012611a91912a3ec16");
}
