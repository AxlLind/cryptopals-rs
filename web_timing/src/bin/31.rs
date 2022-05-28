use std::time::{Duration, Instant};
use rayon::prelude::*;

fn find_byte(mac: [u8; 20], i: usize) -> u8 {
  (0..=0xff).into_par_iter().max_by_key(|&b| {
    let mut mac = mac;
    mac[i] = b;
    let signature = cryptopals_rs::to_hex_str(&mac);
    let url = format!("http://localhost:9000/test?file=secret.txt&signature={}", signature);
    let now = Instant::now();
    reqwest::blocking::get(url).unwrap();
    now.elapsed().as_micros()
  }).unwrap()
}

fn main() {
  // warning: this takes several minutes to run
  let mut server_process = web_timing::build_and_spawn_server(50);
  std::thread::sleep(Duration::from_secs(2)); // wait for server to boot

  println!("Starting timing attack...");
  let mut signature = [0; 20];
  for i in 0..20 {
    signature[i] = find_byte(signature, i);
    println!("{}={:02x}", i, signature[i]);
  }

  let url = format!("http://localhost:9000/test?file=secret.txt&signature={}", cryptopals_rs::to_hex_str(&signature));
  let res = reqwest::blocking::get(url).unwrap();
  assert_eq!(res.status(), reqwest::StatusCode::OK);
  println!("Found signature: {}", cryptopals_rs::to_hex_str(&signature));
  println!("Secret: {:?}", String::from_utf8(res.bytes().unwrap().to_vec()).unwrap());
  server_process.kill().unwrap();
}
