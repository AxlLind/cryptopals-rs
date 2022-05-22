use cryptopals_rs::mt19937::MT19937;

fn to_bitset(x: u32) -> [u8; 32]  {
  let mut bits = [0; 32];
  for i in 0..32 {
    bits[i] = ((x >> i) & 1) as u8;
  }
  bits
}

fn from_bitset(bits: &[u8; 32]) -> u32 {
  let mut x = 0;
  for i in 0..32 { x |= (bits[i] as u32) << i; }
  x
}

// need to invert the operation (negative s for >>):
// y = x ^ ((x << s) & m)
//
// each bit y_n is equal to the following:
// y_n =
//     | x_n ^ (x_(n+s) & m_n)  if n+s in [0, 31]
//     | x_n                    otherwise
//
// inverting this we get:
// x_n =
//     | y_n ^ (x_(n+s) & m_n)  if n+s in [0, 31]
//     | y_n                    otherwise
fn invert_tamper_operation(y: u32, left: bool, shift: usize, mask: u32) -> u32 {
  let mut y = to_bitset(y);
  let mut mask = to_bitset(mask);
  if left {
    y.reverse();
    mask.reverse();
  }

  let mut x = [0; 32];
  for i in 0..32 {
    x[i] = y[i] ^ if i < shift {0} else {mask[i] & x[i - shift]};
  }
  if left { x.reverse() }
  from_bitset(&x)
}

fn mt19937_untamper(mut x: u32) -> u32 {
  x = invert_tamper_operation(x, true, 18, !0);
  x = invert_tamper_operation(x, false, 15, 0xefc60000);
  x = invert_tamper_operation(x, false, 7, 0x9d2c5680);
  x = invert_tamper_operation(x, true, 11, !0);
  x
}

fn main() {
  let mut bytes = [0u8;4];
  openssl::rand::rand_bytes(&mut bytes).unwrap();
  let mut mt19937 = MT19937::from_seed(u32::from_be_bytes(bytes));

  let outputs = (0..624).map(|_| mt19937.gen()).collect::<Vec<_>>();
  let mut state = [0; 624];
  for i in 0..624 {
    state[i] = mt19937_untamper(outputs[i]);
  }

  let mut cloned = MT19937::from_state(state);
  for x in outputs {
    assert_eq!(cloned.gen(), x);
  }
  for _ in 0..10_000_000 {
    assert_eq!(cloned.gen(), mt19937.gen());
  }
}
