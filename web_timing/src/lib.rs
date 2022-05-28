use std::process::{Command, Stdio, Child};

pub fn build_and_spawn_server(sleep_ms: usize) -> Child {
  println!("Building server...");
  let build_status = Command::new("cargo")
    .args(["build", "--quiet", "--release", "-p", "web_timing"])
    .status()
    .expect("failed to build server");
  assert!(build_status.success());

  println!("Launching server...");
  Command::new("cargo")
    .args(["run", "--quiet", "--release", "-p", "web_timing", "--", &sleep_ms.to_string()])
    .stdout(Stdio::null())
    .spawn()
    .expect("failed to launch server")
}
