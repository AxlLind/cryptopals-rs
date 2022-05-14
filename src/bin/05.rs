use cryptopals_rs;

const INPUT: &[u8] = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
const OUTPUT: &str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

fn main() {
  let xored = b"ICE".iter()
    .cycle()
    .zip(INPUT)
    .map(|(k,b)| k^b)
    .collect::<Vec<_>>();
  let s = cryptopals_rs::to_hex_str(&xored);
  assert_eq!(s, OUTPUT);
  println!("{}", s);
}
