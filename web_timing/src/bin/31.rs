use std::process::{Command, Stdio, Child};
use std::time::{Duration, Instant};
use reqwest::{self, StatusCode};
use rayon::prelude::*;

fn to_hex_str(bytes: &[u8]) -> String {
  bytes.iter()
    .flat_map(|&b| [b >> 4, b & 0b1111])
    .map(|b| match b {
      0..=9 => (b + b'0') as char,
      10..=16 => (b + b'a' - 10) as char,
      _ => unreachable!(),
    })
    .collect()
}

fn build_and_spawn_server() -> Child {
  println!("Building server...");
  let build_status = Command::new("cargo")
    .args(["build", "--quiet", "--release", "-p", "web_timing"])
    .status()
    .expect("failed to build web_timing");
  assert!(build_status.success());

  println!("Starting server...");
  Command::new("cargo")
    .args(["run", "--quiet", "--release", "-p", "web_timing", "--", "50"])
    .stdout(Stdio::null())
    .spawn()
    .expect("failed to build web_timing")
}

fn find_byte(mac: [u8; 20], i: usize) -> u8 {
  (0..=0xff).into_par_iter().max_by_key(|&b| {
    let mut mac = mac;
    mac[i] = b;
    let signature = to_hex_str(&mac);
    let url = format!("http://localhost:9000/test?file=a.txt&signature={}", signature);
    let now = Instant::now();
    reqwest::blocking::get(url).unwrap();
    now.elapsed().as_micros()
  }).unwrap()
}

fn main() {
  let mut server_process = build_and_spawn_server();
  std::thread::sleep(Duration::from_secs(2)); // wait for server to boot

  println!("Starting timing attack...");
  let mut signature = [0; 20];
  for i in 0..20 {
    signature[i] = find_byte(signature, i);
    println!("{:x}", signature[i]);
  }
  println!("{}", to_hex_str(&signature));

  let url = format!("http://localhost:9000/test?file=a.txt&signature={}", to_hex_str(&signature));
  assert_eq!(reqwest::blocking::get(url).unwrap().status(), StatusCode::OK);
  server_process.kill().unwrap();
}
