//! OwnChain CLI entry point.
//!
//! Scaffold only — prints project identity information. No blockchain
//! logic, mining, wallets, networking, or cryptography is implemented.

use std::process::ExitCode;

fn main() -> ExitCode {
    println!("{} {}", ownchain::name(), ownchain::VERSION);
    println!("status: scaffold only — see docs/protocol-v1.md (parameters: TBD)");
    ExitCode::SUCCESS
}
