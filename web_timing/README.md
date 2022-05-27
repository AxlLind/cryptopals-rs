# Web Timing Challenges
Challenges 31 and 32 require you to interact with a server over HTTP. This introduces a lot of heavy dependencies that take a while to build on first compilation. So as to not affect all other challenges, these have been separated into a sub-crate.

## Usage
```bash
cargo run --release -p web_timing_challenges --bin 31  # or 32
```
