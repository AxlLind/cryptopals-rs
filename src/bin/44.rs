use num::{BigUint, Num};
use itertools::Itertools;
use cryptopals_rs::bn;

const INPUT: &str = include_str!("../../inputs/44.in");

fn int_hash(message: &[u8]) -> BigUint { BigUint::from_bytes_be(&cryptopals_rs::sha1::sha1(message)) }

fn extract_secret_key(q: &BigUint, r: &BigUint, s: &BigUint, k: &BigUint, message: &[u8]) -> BigUint {
  let h = int_hash(message);
  (((q + s * k) - h) * bn::modinv(r, q).unwrap()) % q
}

fn main() {
  let p = BigUint::from_str_radix("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16).unwrap();
  let q = BigUint::from_str_radix("f4f47f05794b256174bba6e9b396a7707e563c5b", 16).unwrap();
  let g = BigUint::from_str_radix("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16).unwrap();
  let y = BigUint::from_str_radix("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", 16).unwrap();

  let messages = INPUT.lines()
    .tuples()
    .map(|(msg, s, r, m)| (
      &msg[5..],
      s[3..].parse::<BigUint>().unwrap(),
      r[3..].parse::<BigUint>().unwrap(),
      BigUint::from_str_radix(&m[3..], 16).unwrap()
    ))
    .collect::<Vec<_>>();

  let x = messages.iter()
    .tuple_combinations()
    .map(|((msg1, s1, r1, m1), (_, s2, _, m2))| {
      let k = ((&q + m1 - m2) * bn::modinv(&(&q + s1 - s2), &q).unwrap()) % &q;
      extract_secret_key(&q, r1, s1, &k, msg1.as_bytes())
    })
    .find(|x| g.modpow(x, &p) == y)
    .unwrap();
  assert_eq!(int_hash(x.to_str_radix(16).as_bytes()).to_str_radix(16), "ca8f6f7c66fa362d40760d135b763eb8527d3d52");
}
