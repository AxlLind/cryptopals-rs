use std::collections::HashSet;
use std::cmp::min;
use cryptopals_rs::b64;
use itertools::Itertools;

const INPUTS: [&str; 40] = [
  "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
  "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
  "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
  "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
  "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
  "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
  "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
  "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
  "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
  "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
  "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
  "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
  "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
  "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
  "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
  "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
  "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
  "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
  "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
  "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
  "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
  "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
  "U2hlIHJvZGUgdG8gaGFycmllcnM/",
  "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
  "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
  "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
  "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
  "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
  "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
  "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
  "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
  "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
  "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
  "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
  "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
  "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
  "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
  "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
  "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
  "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
];

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
  let ciphertexts = INPUTS.iter().map(|c| b64::decode(c)).collect::<Vec<_>>();
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
