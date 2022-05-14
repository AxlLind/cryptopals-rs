use cryptopals_rs;

const INPUT1: &str = "1c0111001f010100061a024b53535009181c";
const INPUT2: &str = "686974207468652062756c6c277320657965";
const OUTPUT: &str = "746865206b696420646f6e277420706c6179";

fn main() {
  let a = cryptopals_rs::from_hex_str(INPUT1).unwrap();
  let b = cryptopals_rs::from_hex_str(INPUT2).unwrap();
  let c = a.iter().zip(b).map(|(b1,b2)| b1^b2).collect::<Vec<_>>();
  let hex_str = cryptopals_rs::to_hex_str(&c);
  assert_eq!(hex_str, OUTPUT);
  println!("{}", hex_str);
}
