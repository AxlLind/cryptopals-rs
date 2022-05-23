use cryptopals_rs::{aes_ecb_encrypt, b64};

const DECRYPT_TEST: &str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

fn aes_ctr(key: &[u8; 16], nonce: &[u8; 8], plaintext: &[u8]) -> Vec<u8> {
  let ctr_stream = (0u64..).flat_map(|counter| {
    let mut block = [0; 16];
    block[..8].copy_from_slice(nonce);
    block[8..].copy_from_slice(&counter.to_le_bytes());
    aes_ecb_encrypt(&block, key)
  });
  ctr_stream.zip(plaintext).map(|(a, &b)| a ^ b).collect()
}

fn main() {
  let ciphertext = b64::decode(DECRYPT_TEST);
  let plaintext = aes_ctr(b"YELLOW SUBMARINE", &[0; 8], &ciphertext);
  assert_eq!(aes_ctr(b"YELLOW SUBMARINE", &[0; 8], &plaintext), ciphertext);

  let s = String::from_utf8(plaintext).unwrap();
  assert_eq!(s, "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ");
  println!("{}", s);
}
