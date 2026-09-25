//! `yew-cli`: the developer's and the devnet tests' driver over `yew-core` (plan §6.3).
//! Commands (`status`, `address`, `balance`, `send-yec`, `sync`, …) arrive with Phases W1–W4.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("version") | None => println!(
            "yew-cli {} (yew-core {})",
            env!("CARGO_PKG_VERSION"),
            yew_core::VERSION
        ),
        Some(cmd) => {
            eprintln!("yew-cli: unknown command `{cmd}` (only `version` exists in Phase W0a)");
            std::process::exit(2);
        }
    }
}
