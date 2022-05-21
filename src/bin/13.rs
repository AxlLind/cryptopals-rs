use itertools::Itertools;
use openssl::rand::rand_bytes;
use cryptopals_rs::{aes_ecb_encrypt, aes_ecb_decrypt};

const TEST_STR: &str = "foo=bar&baz=qux&zap=zazzle";

struct Profile {
  props: Vec<(String, String)>
}

impl Profile {
  fn from_str(s: &str) -> Self {
    let props = s.split('&')
      .map(|prop| prop.split_once('=').unwrap())
      .map(|(k,v)| (k.to_owned(), v.to_owned()))
      .collect();
    Self { props }
  }

  fn encode(&self) -> String {
    self.props.iter()
      .map(|(k,v)| format!("{}={}", k, v))
      .join("&")
  }

  fn profile_for(email: &str) -> Self {
    if email.contains('=') || email.contains('&') {
      panic!("Invalid email!");
    }
    let props = vec![
      ("email".to_owned(), email.to_owned()),
      ("uid".to_owned(), "10".to_owned()),
      ("role".to_owned(), "user".to_owned()),
    ];
    Self { props }
  }

  fn get(&self, key: &str) -> Option<&str> {
    self.props.iter()
      .find(|(k,_)| k == key)
      .map(|(_,v)| v.as_str())
  }
}

struct Oracle {
  key: [u8; 16]
}

impl Oracle {
  fn new() -> Self {
    let mut key = [0;16];
    rand_bytes(&mut key).unwrap();
    Self { key }
  }

  fn encrypted_profile(&self, email: &str) -> Vec<u8> {
    let mut profile = Profile::profile_for(email).encode().into_bytes();
    cryptopals_rs::pkcs_pad(&mut profile);
    aes_ecb_encrypt(&profile, &self.key)
  }

  fn decrypt_profile(&self, bytes: &[u8]) -> Profile {
    let mut plaintext = aes_ecb_decrypt(&bytes, &self.key);
    assert!(cryptopals_rs::pkcs_depad(&mut plaintext));
    let s = String::from_utf8(plaintext).unwrap();
    Profile::from_str(&s)
  }
}

fn main() {
  assert_eq!(Profile::from_str(TEST_STR).encode(), TEST_STR);
  let oracle = Oracle::new();

  // we need the cipher text of the exact block 'admin'
  // this gets padded with zeros, so give the algorithm the following two blocks to encrypt:
  // email=lol@hax.se
  // admin<---pad--->
  let mut admin_block = b"admin".to_vec();
  cryptopals_rs::pkcs_pad(&mut admin_block);
  let exploit_email = &format!("lol@hax.se{}", String::from_utf8(admin_block).unwrap());
  let ciphertext = oracle.encrypted_profile(&exploit_email);

  // now we need a profile where the role value is at the start of a block:
  // email=lol@hackz.
  // com&uid=10&role=
  // user
  // then overwrite the 'user' block with the admin block\ and decrypt
  let mut target_text = oracle.encrypted_profile("lol@hackz.com");
  target_text[32..].copy_from_slice(&ciphertext[16..32]);
  let admin_profile = oracle.decrypt_profile(&target_text);
  assert_eq!(admin_profile.get("role"), Some("admin"));
  println!("{}", admin_profile.encode());
}
