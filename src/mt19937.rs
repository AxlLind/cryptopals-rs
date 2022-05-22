const N: usize = 624;
const M: usize = 397;

pub struct MT19937 {
  v: [u32; N],
  i: usize,
}

impl MT19937 {
  pub fn from_seed(seed: u32) -> Self {
    let mut mt19937 = Self {
      v: [0; N],
      i: usize::MAX,
    };
    mt19937.reseed(seed);
    mt19937
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

  pub fn reseed(&mut self, seed: u32) {
    self.i = N;
    self.v[0] = seed;
    for i in 1..N {
      let x = self.v[i-1];
      self.v[i] = 1812433253 * (x ^ (x >> 30)) + i as u32;
    }
  }

  fn twist(&mut self) {
    const LOWER_MASK: u32 = 0x7fffffff;
    for i in 0..N {
      let x = (self.v[i] & !LOWER_MASK) | (self.v[(i+1) % N] & LOWER_MASK);
      let t = if (x & 1) == 1 {0x9908b0df} else {0};
      self.v[i] = self.v[(i+M) % N] ^ (x >> 1) ^ t;
    }
    self.i = 0;
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_cpp_standard() {
    let mut mt19937 = MT19937::from_seed(5489);
    for _ in 0..9999 { mt19937.gen(); }
    assert_eq!(mt19937.gen(), 4123659995);
  }

  #[test]
  fn test_zero_seed() {
    // generated with c++ std::mt19937
    const EXPECTED: [u32; 10] = [
      2357136044,
      2546248239,
      3071714933,
      3626093760,
      2588848963,
      3684848379,
      2340255427,
      3638918503,
      1819583497,
      2678185683,
    ];
    let mut mt19937 = MT19937::from_seed(0);
    for x in EXPECTED { assert_eq!(mt19937.gen(), x) }
  }
}
