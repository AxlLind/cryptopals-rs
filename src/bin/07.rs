use itertools::Itertools;
use openssl::symm::{decrypt, Cipher};
use cryptopals_rs;

const INPUT: &str = include_str!("../../inputs/07.in");
const KEY: &[u8] = b"YELLOW SUBMARINE";

fn main() {
  let bytes = cryptopals_rs::base64_decode(&INPUT.lines().join(""));
  let plaintext = decrypt(Cipher::aes_128_ecb(), KEY, None, &bytes).unwrap();
  println!("{}", String::from_utf8(plaintext).unwrap())
}
