use cryptopals_rs;

const INPUT: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

fn main() {
  let bytes = cryptopals_rs::from_hex_str(INPUT).unwrap();
  let decoded = (0u8..=255)
    .map(|key| bytes.iter().map(|&b| b^key).collect::<Vec<_>>())
    .max_by_key(|bytes| bytes.iter().copied().map(cryptopals_rs::frequency_score).sum::<u64>())
    .unwrap();
  println!("{:?}", String::from_utf8(decoded).unwrap());
}
