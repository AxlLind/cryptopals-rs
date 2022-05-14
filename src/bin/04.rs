use cryptopals_rs;

const INPUT: &str = include_str!("../../inputs/04.in");

fn crack_single_byte_xor(s: &str) -> (u64, Vec<u8>) {
  let bytes = cryptopals_rs::from_hex_str(s).unwrap();
  let decoded = (0u8..=255)
    .map(|key| bytes.iter().map(|&b| b^key).collect::<Vec<_>>())
    .max_by_key(|bytes| bytes.iter().map(cryptopals_rs::frequency_score).sum::<u64>())
    .unwrap();
  let score = decoded.iter().map(cryptopals_rs::frequency_score).sum::<u64>();
  (score, decoded)
}

fn main() {
  let decoded = INPUT.lines()
    .map(crack_single_byte_xor)
    .max_by_key(|(score,_)| *score)
    .map(|(_, decoded)| String::from_utf8(decoded).unwrap())
    .unwrap();
  println!("{:?}", decoded);
}
