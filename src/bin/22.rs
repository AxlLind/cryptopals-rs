use cryptopals_rs::mt19937::MT19937;
use cryptopals_rs::rand_range;
use std::time::{SystemTime, UNIX_EPOCH};

fn unix_timestamp() -> u32 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs() as u32
}

struct Oracle {
  seed: u32
}

impl Oracle {
  fn new() -> Self {
    Self { seed: 0 }
  }

  fn run(&mut self) -> u32 {
    self.seed = unix_timestamp() + rand_range(40, 1000) as u32;
    MT19937::from_seed(self.seed).gen()
  }

  fn guess(&self, seed: u32) -> bool {
    self.seed == seed
  }
}

fn main() {
  let program_start = unix_timestamp();
  let mut oracle = Oracle::new();
  for _ in 0..10000 {
    let output = oracle.run();
    let seed = (program_start..)
      .find(|&seed| MT19937::from_seed(seed).gen() == output)
      .unwrap();
    assert!(oracle.guess(seed));
  }
}
