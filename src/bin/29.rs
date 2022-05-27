use openssl::rand::rand_bytes;
use cryptopals_rs::sha1::{sha1, sha1_from_state, sha1_padding};

struct Oracle {
  key: Vec<u8>
}

impl Oracle {
  fn new() -> Self {
    let key_len = cryptopals_rs::rand_range(16, 512) as usize;
    let mut key = vec![0; key_len];
    rand_bytes(&mut key).unwrap();
    Self { key }
  }

  fn mac(&self, bytes: &[u8]) -> [u8; 20] {
    let input = self.key.iter()
      .chain(bytes)
      .copied()
      .collect::<Vec<_>>();
    sha1(&input)
  }

  fn verify(&self, bytes: &[u8], mac: &[u8]) -> bool {
    self.mac(bytes) == mac
  }
}

fn main() {
  let oracle = Oracle::new();

  let msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
  let mac = oracle.mac(msg);

  let target_state = [
    u32::from_be_bytes(mac[0..4].try_into().unwrap()),
    u32::from_be_bytes(mac[4..8].try_into().unwrap()),
    u32::from_be_bytes(mac[8..12].try_into().unwrap()),
    u32::from_be_bytes(mac[12..16].try_into().unwrap()),
    u32::from_be_bytes(mac[16..20].try_into().unwrap()),
  ];

  // brute force the length of the key
  let (target_msg, hacked_mac) = (0..2048)
    .map(|key_len| {
      let target_msg = msg.iter()
        .copied()
        .chain(sha1_padding(key_len + msg.len()))
        .chain(*b";admin=true")
        .collect::<Vec<_>>();
      let bytes_processed = key_len + target_msg.len() - b";admin=true".len();
      let hacked_mac = sha1_from_state(target_state, bytes_processed, b";admin=true");
      (target_msg, hacked_mac)
    })
    .find(|(target_msg, hacked_mac)| oracle.verify(target_msg, hacked_mac))
    .unwrap();
  assert!(oracle.verify(&target_msg, &hacked_mac));
}
