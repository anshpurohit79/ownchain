//! Node runtime configuration.

use std::path::PathBuf;

use libp2p::core::Multiaddr;

use crate::genesis::DEVNET;
use crate::hash::{self, Hash};
use crate::mempool::MempoolConfig;

/// Node runtime configuration parameters.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Data directory for blockchain storage and identity key.
    pub data_dir: PathBuf,
    /// Network name (e.g. "devnet").
    pub network_name: String,
    /// Network chain ID derived from `network_name`.
    pub chain_id: Hash,
    /// Multiaddress to listen on for P2P connections.
    pub listen_addr: Multiaddr,
    /// Operator-configured bootstrap peers.
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Maximum number of connected peers permitted.
    pub max_peers: usize,
    /// Configuration limits for the mempool.
    pub mempool_config: MempoolConfig,
}

impl NodeConfig {
    /// Constructs a default node configuration for devnet rooted at `data_dir`.
    pub fn default_devnet(data_dir: PathBuf) -> Self {
        let network_name = DEVNET.to_string();
        let chain_id = hash::chain_id(&network_name);
        let listen_addr: Multiaddr = "/ip4/0.0.0.0/tcp/40333".parse().expect("valid multiaddr");

        Self {
            data_dir,
            network_name,
            chain_id,
            listen_addr,
            bootstrap_peers: Vec::new(),
            max_peers: 50,
            mempool_config: MempoolConfig::default(),
        }
    }

    /// Path to the embedded database directory.
    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("db")
    }

    /// Path to the persistent node identity key file.
    pub fn identity_path(&self) -> PathBuf {
        self.data_dir.join("node_key.dat")
    }
}
