use cryptopals_rs;

const INPUT: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

// source: https://www3.nd.edu/~busiforc/handouts/cryptography/letterfrequencies.html
fn frequency_score(b: &u8) -> u64 {
  match (*b as char).to_ascii_uppercase() {
    ' ' => 20000,
    'E' => 12000,
    'T' => 9000,
    'A'|'I'|'N'|'O'|'S' => 8000,
    'H' => 6400,
    'R' => 6200,
    'D' => 4400,
    'L' => 4000,
    'U' => 3400,
    'C'|'M' => 3000,
    'F' => 2500,
    'W'|'Y' => 2000,
    'G'|'P' => 1700,
    'B' => 1600,
    'V' => 1200,
    'K' => 800,
    'Q' => 500,
    'J'|'X' => 400,
    'Z' => 200,
    _ => 0
  }
}


fn main() {
  let bytes = cryptopals_rs::from_hex_str(INPUT).unwrap();
  let decoded = (0u8..=255)
    .map(|key| bytes.iter().map(|&b| b^key).collect::<Vec<_>>())
    .max_by_key(|bytes| bytes.iter().map(frequency_score).sum::<u64>())
    .unwrap();
  println!("{:?}", String::from_utf8(decoded).unwrap());
}
