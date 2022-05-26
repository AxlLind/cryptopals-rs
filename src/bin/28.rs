use openssl::rand::rand_bytes;
use cryptopals_rs::sha1;

struct Oracle {
  key: [u8; 16]
}

impl Oracle {
  fn new() -> Self {
    let mut key = [0; 16];
    rand_bytes(&mut key).unwrap();
    Self { key }
  }

  fn mac(&self, bytes: &[u8]) -> [u8; 20] {
    let input = self.key.iter()
      .chain(bytes)
      .copied()
      .collect::<Vec<_>>();
    sha1::sha1(&input)
  }

  fn verify_mac(&self, bytes: &[u8], mac: &[u8]) -> bool {
    let actual_mac = self.mac(bytes);
    actual_mac == mac
  }
}

fn main() {
  let oracle = Oracle::new();
  let mac = oracle.mac(b"YELLOW SUBMARINE");
  assert!(oracle.verify_mac(b"YELLOW SUBMARINE", &mac));
}
