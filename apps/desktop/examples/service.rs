//! Exercises starting at login on a real machine: `service state|start|stop` prints what the
//! app would show. Run it from the folder that holds the app and gmcd (as the app does).
fn main() {
    use gimmecores_desktop::service;
    let r = match std::env::args().nth(1).as_deref() {
        Some("start") => service::start_at_login(),
        Some("stop") => service::stop_at_login(),
        _ => Ok(()),
    };
    if let Err(e) = r {
        println!("error: {e:#}");
    }
    println!("{:?}", service::state());
}
