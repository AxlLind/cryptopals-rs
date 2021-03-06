const N: usize = 624;
const M: usize = 397;

struct MT19937 {
  v: [u32; N],
  i: usize,
}

impl MT19937 {
  fn from_seed(seed: u32) -> Self {
    let mut mt19937 = Self {
      v: [0; N],
      i: usize::MAX,
    };
    mt19937.reseed(seed);
    mt19937
  }

  fn get(&mut self) -> u32 {
    if self.i >= N { self.twist() }

    let mut y = self.v[self.i];
    self.i += 1;

    y ^= y >> 11;
    y ^= (y << 7) & 0x9d2c5680;
    y ^= (y << 15) & 0xefc60000;
    y ^= y >> 18;
    y
  }

  fn reseed(&mut self, seed: u32) {
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

fn main() {
  // the c++ standard testcase
  let mut mt19937 = MT19937::from_seed(5489);
  for _ in 0..9999 { mt19937.get(); }
  assert_eq!(mt19937.get(), 4123659995);
}
