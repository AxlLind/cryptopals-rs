use itertools::Itertools;
use openssl::symm::{decrypt, Cipher};
use cryptopals_rs::b64;

const INPUT: &str = include_str!("../../inputs/07.in");
const KEY: &[u8] = b"YELLOW SUBMARINE";

fn main() {
  let bytes = b64::decode(&INPUT.lines().join(""));
  let plaintext = decrypt(Cipher::aes_128_ecb(), KEY, None, &bytes).unwrap();
  println!("{}", String::from_utf8(plaintext).unwrap())
}
