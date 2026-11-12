//! Manual check of the OS presence prompt: `cargo run -p gimmecores-presence --example check`.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    println!("method: {}", gimmecores_presence::method());
    println!("A Touch ID / password prompt should appear now...");
    let outcome = gimmecores_presence::verify("test the GimmeCores presence check").await;
    println!("outcome: {outcome:?}");
}
