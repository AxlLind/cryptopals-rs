use cryptopals_rs::b64;
use itertools::Itertools;

const INPUT: &str = include_str!("../../inputs/06.in");

fn hamming_distance(s1: &[u8], s2: &[u8]) -> usize {
  s1.iter()
    .zip(s2)
    .map(|(b1,b2)| (b1^b2).count_ones() as usize)
    .sum()
}

fn find_key_size(s: &[u8]) -> usize {
  (2..=40).min_by_key(|size| {
    let blocks = [
      &s[size*0..size*1],
      &s[size*1..size*2],
      &s[size*2..size*3],
      &s[size*3..size*4],
    ];
    let avg_dist = blocks.iter()
      .tuple_combinations()
      .map(|(b1,b2)| hamming_distance(b1, b2))
      .sum::<usize>();
    avg_dist / size
  }).unwrap()
}

fn crack_single_byte_xor(bytes: &[u8]) -> u8 {
  (0u8..=255).max_by_key(|key| bytes.iter()
    .map(|&b| cryptopals_rs::frequency_score(b^key))
    .sum::<u64>()
  ).unwrap()
}

fn main() {
  assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37);

  let bytes = b64::decode(&INPUT.lines().join(""));
  let keysize = find_key_size(&bytes);

  let key = (0..keysize)
    .map(|i| {
      let transposed = (0..bytes.len() / keysize)
        .map(|n| bytes[n * keysize + i])
        .collect::<Vec<_>>();
      crack_single_byte_xor(&transposed)
    })
    .collect::<Vec<_>>();
  let decrypted = key.iter()
    .cycle()
    .zip(bytes)
    .map(|(k,b)| k^b)
    .collect::<Vec<_>>();
  println!("{}", String::from_utf8(decrypted).unwrap());
}
