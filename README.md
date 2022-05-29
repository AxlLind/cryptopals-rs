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
- [ ] [Set 5](https://cryptopals.com/sets/5)
  - [x] Challenge 33
  - [x] Challenge 34
  - [x] Challenge 35
  - [ ] Challenge 36
  - [ ] Challenge 37
  - [ ] Challenge 38
  - [ ] Challenge 39
  - [ ] Challenge 40
- [ ] [Set 6](https://cryptopals.com/sets/6)
- [ ] [Set 7](https://cryptopals.com/sets/7)
- [ ] [Set 8](https://cryptopals.com/sets/8)
