use cryptopals_rs::bn;
use num::BigUint;
use num_bigint::ToBigUint;

const SECRET_MESSAGE: &[u8] = b"super secret message to decrypt";

fn main() {
  let e = 3.to_biguint().unwrap();
  let n1 = bn::gen_rsa_prime(&e, 1024) * bn::gen_rsa_prime(&e, 1024);
  let n2 = bn::gen_rsa_prime(&e, 1024) * bn::gen_rsa_prime(&e, 1024);
  let n3 = bn::gen_rsa_prime(&e, 1024) * bn::gen_rsa_prime(&e, 1024);

  let m = BigUint::from_bytes_be(SECRET_MESSAGE);
  let c1 = m.modpow(&e, &n1);
  let c2 = m.modpow(&e, &n2);
  let c3 = m.modpow(&e, &n3);

  let result = bn::crt(&[c1, c2, c3], &[n1, n2, n3]).unwrap();
  assert_eq!(result.nth_root(3).to_bytes_be(), SECRET_MESSAGE);
}
