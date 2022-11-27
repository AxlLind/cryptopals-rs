# cryptopals-rs
[The Cryptopals Crypto Challenges](https://cryptopals.com/) is a set of crytography challenges aimed at practical examples of breaking badly implemented crypto.

This repo contains solutions to the challenges written in Rust.

# Usage
```bash
cargo run --release --bin 01               # replace 01 with the challenge to run
cargo run --release -p web_timing --bin 31 # for challenges 31 and 32
cargo test --release --lib                 # to run library tests
```

# Progress
This repo is a work in progress. Challenges solved so far:
- [x] [Set 1](https://cryptopals.com/sets/1) (1-8)
- [x] [Set 2](https://cryptopals.com/sets/2) (9-16)
- [x] [Set 3](https://cryptopals.com/sets/3) (17-24)
- [x] [Set 4](https://cryptopals.com/sets/4) (25-32)
- [x] [Set 5](https://cryptopals.com/sets/5) (33-40)
- [ ] [Set 6](https://cryptopals.com/sets/6) (41-48)
  - [x] Challenge 41
  - [x] Challenge 42
  - [x] Challenge 43
  - [ ] Challenge 44
  - [ ] Challenge 45
  - [ ] Challenge 46
  - [ ] Challenge 47
  - [ ] Challenge 48
- [ ] [Set 7](https://cryptopals.com/sets/7) (49-56)
- [ ] [Set 8](https://cryptopals.com/sets/8) (57-66)
