//! OwnChain CLI entry point and node runner.
//!
//! Provides CLI subcommands:
//! - `init`: initialize a network-specific node data directory.
//! - `run`: start the node runtime.
//! - `status`: display local chain and runtime status.
//! - `peers`: display peer identity and bootstrap configuration.
//! - `chain`: display active chain height, tip ID, cumulative work, and state roots.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use libp2p::core::Multiaddr;
use tokio::sync::watch;

use ownchain::genesis::{genesis_block, DEVNET};
use ownchain::hash::{self, Hash};
use ownchain::node::{NodeConfig, NodeRuntime};
use ownchain::p2p::identity::{load_or_generate_identity, peer_id_from_keypair};
use ownchain::storage::{BlockStore, DATABASE_SCHEMA_VERSION};

#[derive(Parser, Debug)]
#[command(
    name = "ownchain",
    version = ownchain::VERSION,
    about = "OwnChain Node Runtime & Consensus Client"
)]
struct Cli {
    /// Active network name (e.g. "devnet").
    #[arg(long, global = true, default_value = DEVNET)]
    network: String,

    /// Node data directory (defaults to ~/.ownchain/<network>).
    #[arg(long, global = true)]
    datadir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize a network-specific node data directory with genesis.
    Init,

    /// Start the node runtime.
    Run {
        /// P2P multiaddress to listen on.
        #[arg(long, default_value = "/ip4/0.0.0.0/tcp/40333")]
        listen: String,

        /// Bootstrap peer multiaddresses to connect to (can specify multiple).
        #[arg(long = "peer")]
        peers: Vec<String>,
    },

    /// Display local chain and database status.
    Status,

    /// Display peer identity and network configuration.
    Peers,

    /// Display local active chain height, tip ID, cumulative work, and composite state roots.
    Chain,
}

fn resolve_datadir(cli_datadir: Option<PathBuf>, network: &str) -> PathBuf {
    if let Some(dir) = cli_datadir {
        dir
    } else {
        let base = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        base.join(".ownchain").join(network)
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let datadir = resolve_datadir(cli.datadir, &cli.network);
    let chain_id = hash::chain_id(&cli.network);

    match cli.command {
        Commands::Init => {
            println!(
                "Initializing OwnChain data directory at: {}",
                datadir.display()
            );
            if let Err(e) = fs::create_dir_all(&datadir) {
                eprintln!("Failed to create data directory: {e}");
                return ExitCode::FAILURE;
            }

            let key_path = datadir.join("node_key.dat");
            let keypair = match load_or_generate_identity(&key_path) {
                Ok(kp) => kp,
                Err(e) => {
                    eprintln!("Failed to initialize node identity: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let peer_id = peer_id_from_keypair(&keypair);

            let db_dir = datadir.join("db");
            if let Err(e) = fs::create_dir_all(&db_dir) {
                eprintln!("Failed to create database directory: {e}");
                return ExitCode::FAILURE;
            }

            let db_file = db_dir.join("blockchain.redb");
            let _store = match BlockStore::open(&db_file, chain_id) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to open blockchain storage: {e}");
                    return ExitCode::FAILURE;
                }
            };

            let genesis = genesis_block(chain_id);
            println!("OwnChain initialized successfully.");
            println!("  Network: {}", cli.network);
            println!("  Chain ID: {}", chain_id);
            println!("  Node Peer ID: {}", peer_id);
            println!("  Genesis Block ID: {}", genesis.block_id());
            println!(
                "  Genesis State Root: {}",
                genesis.header.orchard_commitment_root
            );
            println!("  Database Schema Version: {}", DATABASE_SCHEMA_VERSION);
            ExitCode::SUCCESS
        }

        Commands::Run { listen, peers } => {
            // Initialize logging
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                )
                .try_init();

            let listen_addr: Multiaddr = match listen.parse() {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("Invalid listen multiaddress '{listen}': {e}");
                    return ExitCode::FAILURE;
                }
            };

            let mut bootstrap_addrs = Vec::new();
            for p in peers {
                match p.parse::<Multiaddr>() {
                    Ok(a) => bootstrap_addrs.push(a),
                    Err(e) => {
                        eprintln!("Invalid bootstrap peer address '{p}': {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }

            let mut config = NodeConfig::default_devnet(datadir);
            config.network_name = cli.network;
            config.chain_id = chain_id;
            config.listen_addr = listen_addr;
            config.bootstrap_peers = bootstrap_addrs;

            let mut runtime = match NodeRuntime::init(config) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Failed to initialize node runtime: {e}");
                    return ExitCode::FAILURE;
                }
            };

            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                let _ = shutdown_tx.send(true);
            });

            runtime.run(Some(shutdown_rx)).await;
            ExitCode::SUCCESS
        }

        Commands::Status => {
            let db_file = datadir.join("db").join("blockchain.redb");
            if !db_file.exists() {
                eprintln!(
                    "No database found at {}. Run 'ownchain init' first.",
                    db_file.display()
                );
                return ExitCode::FAILURE;
            }

            let store = match BlockStore::open(&db_file, chain_id) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to open database: {e}");
                    return ExitCode::FAILURE;
                }
            };

            let (height, tip_id, work) = match store.get_tip() {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Failed to read chain tip: {e}");
                    return ExitCode::FAILURE;
                }
            };

            let key_path = datadir.join("node_key.dat");
            let peer_id_str = if key_path.exists() {
                match load_or_generate_identity(&key_path) {
                    Ok(kp) => peer_id_from_keypair(&kp).to_string(),
                    Err(_) => "corrupted key".to_string(),
                }
            } else {
                "not generated".to_string()
            };

            println!("OwnChain Node Status:");
            println!("  Network: {}", cli.network);
            println!("  Chain ID: {}", chain_id);
            println!("  Database: {}", db_file.display());
            println!("  Schema Version: {}", DATABASE_SCHEMA_VERSION);
            println!("  Node Peer ID: {}", peer_id_str);
            println!("  Active Tip Height: #{}", height);
            println!("  Active Tip Block ID: {}", tip_id);
            println!("  Cumulative Work: {:?}", work);
            ExitCode::SUCCESS
        }

        Commands::Peers => {
            let key_path = datadir.join("node_key.dat");
            if !key_path.exists() {
                eprintln!(
                    "No identity key found at {}. Run 'ownchain init' first.",
                    key_path.display()
                );
                return ExitCode::FAILURE;
            }

            let keypair = match load_or_generate_identity(&key_path) {
                Ok(kp) => kp,
                Err(e) => {
                    eprintln!("Failed to load identity key: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let peer_id = peer_id_from_keypair(&keypair);

            println!("OwnChain Peer Configuration:");
            println!("  Local Peer ID: {}", peer_id);
            println!("  Network: {}", cli.network);
            println!("  Chain ID: {}", chain_id);
            println!("  Identity Key Path: {}", key_path.display());
            ExitCode::SUCCESS
        }

        Commands::Chain => {
            let db_file = datadir.join("db").join("blockchain.redb");
            if !db_file.exists() {
                eprintln!(
                    "No database found at {}. Run 'ownchain init' first.",
                    db_file.display()
                );
                return ExitCode::FAILURE;
            }

            let store = match BlockStore::open(&db_file, chain_id) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to open database: {e}");
                    return ExitCode::FAILURE;
                }
            };

            let state = match store.reconstruct_chain_state() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to reconstruct chain state: {e}");
                    return ExitCode::FAILURE;
                }
            };

            let total_transparent: u128 = state.accounts().values().map(|a| a.balance).sum();

            println!("OwnChain Canonical Chain:");
            println!("  Network: {}", cli.network);
            println!("  Chain ID: {}", chain_id);
            println!("  Chain Height: #{}", state.tip_height().unwrap_or(0));
            println!(
                "  Tip Block ID: {}",
                state.tip_block_id().unwrap_or(Hash::ZERO)
            );
            println!("  Cumulative Work: {:?}", state.cumulative_work());
            println!("  Composite State Root: {}", state.composite_state_root());
            println!("  Total Transparent Balance: {} atoms", total_transparent);
            println!(
                "  Shielded Pool Balance: {} atoms",
                state.shielded_pool_balance()
            );
            println!(
                "  Cumulative Issuance: {} atoms",
                state.cumulative_issuance()
            );
            ExitCode::SUCCESS
        }
    }
}
