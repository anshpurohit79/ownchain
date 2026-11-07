//! Swarm network behaviour combining Gossipsub, Kademlia, RequestResponse, Identify and Ping.

use std::time::Duration;

use libp2p::gossipsub::{
    Behaviour as Gossipsub, ConfigBuilder as GossipsubConfigBuilder, MessageAuthenticity,
    ValidationMode,
};
use libp2p::identify::{Behaviour as Identify, Config as IdentifyConfig};
use libp2p::identity::Keypair;
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{Behaviour as Kademlia, Config as KadConfig};
use libp2p::ping::{Behaviour as Ping, Config as PingConfig};
use libp2p::request_response::{
    Behaviour as RequestResponse, Config as ReqRespConfig, ProtocolSupport,
};
use libp2p::swarm::NetworkBehaviour;
use libp2p::StreamProtocol;

use crate::p2p::protocol::{SyncCodec, SYNC_PROTOCOL_ID};

/// Combined network behaviour for OwnChain P2P node.
#[derive(NetworkBehaviour)]
pub struct OwnChainBehaviour {
    pub gossipsub: Gossipsub,
    pub kademlia: Kademlia<MemoryStore>,
    pub request_response: RequestResponse<SyncCodec>,
    pub identify: Identify,
    pub ping: Ping,
}

impl OwnChainBehaviour {
    /// Constructs a new combined behaviour.
    pub fn new(
        keypair: &Keypair,
        network_name: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let peer_id = keypair.public().to_peer_id();

        // 1. Gossipsub setup
        let gossipsub_config = GossipsubConfigBuilder::default()
            .validation_mode(ValidationMode::Permissive)
            .heartbeat_interval(Duration::from_millis(500))
            .max_transmit_size(2_100_000)
            .build()
            .map_err(|e| format!("gossipsub config error: {e}"))?;

        let gossipsub = Gossipsub::new(
            MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )?;

        // 2. Kademlia DHT setup
        let store = MemoryStore::new(peer_id);
        let kad_proto = format!("/ownchain/{}/kad/1", network_name);
        let kad_config = KadConfig::new(StreamProtocol::try_from_owned(kad_proto)?);
        let kademlia = Kademlia::with_config(peer_id, store, kad_config);

        // 3. RequestResponse setup
        let protocols = [(StreamProtocol::new(SYNC_PROTOCOL_ID), ProtocolSupport::Full)];
        let req_resp_config =
            ReqRespConfig::default().with_request_timeout(Duration::from_secs(10));
        let request_response = RequestResponse::with_codec(SyncCodec, protocols, req_resp_config);

        // 4. Identify setup
        let identify_config =
            IdentifyConfig::new(format!("/ownchain/{}/1", network_name), keypair.public())
                .with_agent_version(format!("ownchain/{}", crate::VERSION));
        let identify = Identify::new(identify_config);

        // 5. Ping setup
        let ping_config = PingConfig::new().with_interval(Duration::from_secs(15));
        let ping = Ping::new(ping_config);

        Ok(Self {
            gossipsub,
            kademlia,
            request_response,
            identify,
            ping,
        })
    }
}
