# Web Timing Challenges
Challenges 31 and 32 require you to interact with a server over HTTP. This introduces a lot of heavy dependencies that take a while to build on first compilation. So as to not affect all other challenges, these have been separated into a sub-crate.

:warning: Both challenges take a while to complete:

| Challenge | Time   |
| --------- | ------ |
| 31        | 10m39s |
| 32        | 06m53s |

## Usage
```bash
cargo run --release -p web_timing --bin 31  # or 32
```
