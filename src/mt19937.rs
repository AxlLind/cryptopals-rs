const N: usize = 624;
const LOWER_MASK: u32 = 0x7fffffff;

pub struct MT19937 {
  v: [u32; N],
  i: usize,
}

impl MT19937 {
  pub fn from_seed(seed: u32) -> Self {
    let mut v = [0; N];
    v[0] = seed;
    for i in 1..N {
      let x = v[i-1];
      v[i] = 1812433253 * (x ^ (x >> 30)) + i as u32;
    }
    Self { v, i: N }
  }

  pub fn from_state(state: [u32; N]) -> Self {
    Self { v: state, i: 0 }
  }

  pub fn gen(&mut self) -> u32 {
    if self.i >= N { self.twist() }

    let mut y = self.v[self.i];
    self.i += 1;

    y ^= y >> 11;
    y ^= (y << 7) & 0x9d2c5680;
    y ^= (y << 15) & 0xefc60000;
    y ^= y >> 18;
    y
  }

  fn twist(&mut self) {
    for i in 0..N {
      let x = (self.v[i] & !LOWER_MASK) | (self.v[(i + 1) % N] & LOWER_MASK);
      let t = if (x & 1) == 1 {0x9908b0df} else {0};
      self.v[i] = self.v[(i + 397) % N] ^ (x >> 1) ^ t;
    }
    self.i = 0;
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_cpp_standard() {
    // testcase from the c++ standard
    let mut mt19937 = MT19937::from_seed(5489);
    for _ in 0..9999 { mt19937.gen(); }
    assert_eq!(mt19937.gen(), 4123659995);
  }

  #[test]
  fn test_zero_seed() {
    // 100_000 outputs generated with c++ std::mt19937
    const EXPECTED: &str = include_str!("../inputs/mt19937_testdata.in");
    assert_eq!(EXPECTED.lines().count(), 100_000);

    let mut mt19937 = MT19937::from_seed(0);
    for line in EXPECTED.lines() {
      assert_eq!(mt19937.gen(), line.parse().unwrap());
    }
  }
}
