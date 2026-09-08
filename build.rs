//! Rebuild embedded migration ledgers when migrations are added or changed.

fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
