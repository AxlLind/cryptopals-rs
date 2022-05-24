use std::collections::HashSet;
use std::cmp::min;
use cryptopals_rs::b64;
use itertools::Itertools;

const INPUTS: &str = include_str!("../../inputs/20.in");

fn possible_xor_results(chars: &[u8]) -> Vec<Vec<(u8,u8)>> {
  let mut res = vec![Vec::new(); 256];
  for (&a,&b) in chars.iter().tuple_combinations() {
    res[(a^b) as usize].push((a,b))
  }
  res[0] = chars.iter().map(|&a| (a,a)).collect();
  res
}

fn main() {
  let possible_xor_pairs = possible_xor_results(b" abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
  let ciphertexts = INPUTS.lines().map(|c| b64::decode(c)).collect::<Vec<_>>();
  let max_len = ciphertexts.iter().map(|c| c.len()).max().unwrap();
  let mut byte_key_count = vec![vec![0; 256]; max_len];
  for (c1,c2) in ciphertexts.iter().tuple_combinations() {
    for i in 0..min(c1.len(), c2.len()) {
      let mut cipher_chars = HashSet::new();
      for (x,y) in &possible_xor_pairs[(c1[i] ^ c2[i]) as usize] {
        cipher_chars.insert(c1[i]^x);
        cipher_chars.insert(c1[i]^y);
      }
      for c in cipher_chars {
        byte_key_count[i][c as usize] += 1;
      }
    }
  }

  let key_guess = byte_key_count.iter()
    .map(|x| x.iter()
      .enumerate()
      .max_by_key(|&(_,c)| c)
      .map(|(i,_)| i as u8)
      .unwrap()
    )
    .collect::<Vec<_>>();

  for c in ciphertexts {
    let decrypted = c.iter()
      .zip(&key_guess)
      .map(|(&a,b)| (a^b) as char)
      .collect::<String>();
    println!("{}", decrypted);
  }
}
