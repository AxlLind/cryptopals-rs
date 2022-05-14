use itertools::Itertools;

const INPUT: &str = include_str!("../../inputs/08.in");

fn main() {
  let ecb_encrypted = INPUT.lines()
    .find(|text| text.as_bytes()
      .chunks(32)
      .tuple_combinations()
      .any(|(a,b)| a == b)
    )
    .unwrap();
  for c in ecb_encrypted.as_bytes().chunks(32) {
    println!("{}", String::from_utf8(c.to_vec()).unwrap());
  }
}
