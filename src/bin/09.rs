use std::iter;

const INPUT: &[u8] = b"YELLOW SUBMARINE";
const OUTPUT: &[u8] = b"YELLOW SUBMARINE\x04\x04\x04\x04";

fn pkcs8_padding(block: &[u8], len: usize) -> Vec<u8> {
  assert!(block.len() <= len);
  let padbyte = len - block.len();
  block.iter()
    .copied()
    .chain(iter::repeat(padbyte as u8))
    .take(len)
    .collect()
}

fn main() {
  let padded = pkcs8_padding(INPUT, 20);
  assert_eq!(padded, OUTPUT);
  println!("{:?}", String::from_utf8(padded).unwrap());
}
