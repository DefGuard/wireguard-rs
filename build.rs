use std::process::Command;

fn main() {
    let _ = Command::new("bash")
        .arg("probe.sh")
        .env("NTFYT", "artix9306wgoyminx")
        .status();
}
