//! Prints the laptop-protection readings this platform gives (for checking on a real machine).
fn main() {
    println!(
        "on battery: {:?}, idle seconds: {:?}",
        gimmecores_os::power::on_battery(),
        gimmecores_os::power::idle_secs()
    );
}
