# OwnChain PR3 — P2P and Network Security Audit (Final Review)

**Original Branch Base:** `074c44a` (`origin/main`)<br/>
**Audited Source Snapshot:** `a10b88b` (HEAD of branch `hardening/p2p-security`)
*Note on Metadata:* This audit explicitly distinguishes the original branch base (`074c44a`) from the audited source snapshot (`a10b88b`), which incorporates prior initiative milestones:
- PR1 Merge Commit: `bfae338` (Consensus and reorganization hardening)
- PR2 Merge Commit: `a10b88b` (Mempool and transaction security hardening)

**Audit Scope:** Peer-to-peer transport, peer identity & registry, message framing, handshake, gossipsub, request/response chain synchronization, and network actor integration.<br/>
**Mode:** READ-ONLY Deep Adversarial Source Audit.

---

## 1. Executive Summary

This comprehensive security audit evaluated OwnChain's P2P networking subsystem (`src/p2p/`), runtime coordination actor (`src/node/runtime.rs`), networking configuration (`src/node/config.rs`), node runner entrypoint (`src/main.rs`), and related protocol specifications (`docs/protocol-v1.md` §8).

Following independent audit review against source snapshot `a10b88b`, findings have been rigorously verified, calibrated against libp2p 0.54 mechanics, categorized, and documented.

### Verified Findings Count:
- **Critical:** 0 (no unauthenticated remote code execution or PoW bypass identified).
- **High:** 3
  1. `SEC-P2P-002`: Gossipsub `validate_messages` disabled and automatic forwarding of unvalidated messages.
  2. `SEC-P2P-003`: Unverified peer-advertised cumulative-work claims starve active synchronization slot.
  3. `SEC-P2P-004`: Sync worker ingests disconnected blocks as orphans, falsely reporting sync success.
- **Medium:** 7
  1. `SEC-P2P-001`: Outbound handshake timeout ignored, causing temporary peer-slot occupation.
  2. `SEC-P2P-005`: Unchecked arithmetic in `SyncRequest::GetHeaders` (conditional panic in debug/test profiles).
  3. `SEC-P2P-006` *(Suspected)*: Dual-channel actor wait cycle between `NetworkService` and `NodeRuntime`.
  4. `SEC-P2P-007`: Transaction gossip rebroadcast loop causes redundant origin publications.
  5. `SEC-P2P-010`: Synchronous full-block storage reads and deserialization during `GetHeaders`.
  6. `SEC-P2P-011`: Pre-validation orphan admission and multi-peer recovery fanout DoS.
  7. `SEC-P2P-012`: Missing limit on concurrent connections per peer or IP address.
- **Low:** 6
  1. `SEC-P2P-009`: Malleable clamping of collection lengths in sync wire payloads (parser ambiguity).
  2. `SEC-P2P-013`: Unfiltered self-advertised listen address injection into Kademlia DHT.
  3. `SEC-P2P-014`: `decode_frame_slice` accepts non-canonical frames with trailing bytes.
  4. `SEC-P2P-015`: Eager heap buffer allocation before payload read in `SyncCodec`.
  5. `SEC-P2P-016`: Permissive lossy UTF-8 conversion in handshake and error strings.
  6. `SEC-P2P-018`: Identity key file permissions subject to process umask on Unix.
- **Informational:** 2
  1. `SEC-P2P-019`: Absence of peer scoring, rate limiting, and banning infrastructure.
  2. `SEC-P2P-020`: Absence of inbound vs. outbound peer slot reservation.
- **Implementation Observations:** 1
  1. `OBS-P2P-001` *(formerly SEC-P2P-008)*: Batch size difference between header requests (500) and block requests (64).

---

## 2. Independent Review Notes

In accordance with independent audit review, the following calibrations and adjustments were integrated:
1. **SEC-P2P-001 (Outbound Handshake Cleanup):**
   - Retained missing `OutboundFailure` cleanup finding.
   - Corrected Ping keepalive mechanics: `PingConfig::new()` initializes with `keep_alive = false` by default in libp2p 0.54. Ping streams do not keep the connection alive against the Swarm's 60-second idle connection timeout (`src/p2p/network.rs:424`).
   - Peer-slot occupation is temporary (up to 60s) unless sustained by continuous reconnection. Reassessed severity from High to **Medium**.
2. **SEC-P2P-002 (Gossipsub Message Validation):**
   - Clarified that `ValidationMode::Permissive` allows messages with missing author, sequence number, or signature, while validating present fields.
   - Identified that `validate_messages()` is the separate application-level validation toggle (defaults to `false` in libp2p, not enabled in current code).
   - Clarified that setting `ValidationMode::Strict` alone does NOT halt automatic message forwarding—it only validates envelope authenticity. True gating requires enabling `validate_messages(true)` and explicitly calling `report_message_validation_result`.
   - Documented that `NetworkEvent` must preserve Gossipsub `message_id` and `propagation_source` to permit reporting validation outcomes.
3. **SEC-P2P-003 (Unverified Cumulative-Work Claims):**
   - Corrected terminology: replaced "unauthenticated handshake claims" with "unverified peer-advertised cumulative-work claims", noting transport identities are authenticated via Noise Ed25519.
   - Documented the exact starvation loop: 500ms `sync_interval.tick()`, singular `active_sync` slot, absence of peer failure cooldown/backoff, and repeat selection of the highest-work peer.
   - Consolidated repeated handshake metadata updates (former `SEC-P2P-017`) into this finding.
4. **SEC-P2P-004 (Orphan Ingestion & False Sync Success):**
   - Confirmed as High severity. Documented that orphan blocks return `Ok(BlockProcessingOutcome::Ignored)`, `ApplyBlockBatch` treats `Ok` as complete batch success, and `run_sync_worker` increments `current_h += num_blocks` based on response block count.
   - Expanded regression tests to cover disconnected blocks, empty headers, empty blocks, mismatched block IDs, zero active tip advancement, and truthful failure reporting.
5. **SEC-P2P-005 (`GetHeaders` Arithmetic Overflow):**
   - Retained the unchecked addition finding (`start_height + count as u64`).
   - Distinguished debug/test profile panic from normal release-profile unsigned wrapping (which yields an empty range without panicking). Reassessed severity to **Medium (Conditional)**.
6. **SEC-P2P-006 (Dual-Channel Deadlock):**
   - Retained as **Suspected**. Detailed the event-channel (500) and command-channel (500) wait cycle. Not labeled confirmed merely from source inspection pending an adversarial reproduction test.
7. **SEC-P2P-007 (Transaction Gossip Rebroadcast Loop):**
   - Distinguished $O(N)$ redundant origin publications from potentially $O(N^2)$ aggregate message deliveries across the network topology. Avoided asserting an unmeasured exact multiplier.
8. **SEC-P2P-008 Reclassified to Implementation Observation (`OBS-P2P-001`):**
   - Traced `current_h` tracking: while `GetHeaders` fetches 500 headers and `GetBlocks` requests 64 blocks, `current_h` advances by 64, and the next loop iteration queries headers starting at `current_h + 64`. Removed as a security vulnerability and recorded as an implementation batching observation.
9. **SEC-P2P-009 Downgraded to Low / Robustness:**
   - Detailed parser clamping: wire count $> \text{MAX}$ is clamped to $\text{MAX}$; if payload size matches the clamped count, it parses without error. Downgraded to **Low** as no practical exploit beyond parser ambiguity and non-canonical encoding exists.
10. **SEC-P2P-010 Qualified:**
    - Qualified the "1 GB worst-case estimate": consensus maximum block size is 2,000,000 bytes, but real blocks scale with transaction volume. Scaled impact description to actual stored block sizes.
11. **SEC-P2P-011 (Missing-Parent Recovery & Cheap Orphan DoS):**
    - Corrected cumulative request accounting: 101 requests maximum per attempt, 3 total attempts per parent-recovery lifecycle, and 303 requests maximum per lifecycle.
    - Clarified that 16 is the maximum concurrent recovery workers limit, NOT a global limit on all recovery lifecycles; 4,848 represents only the cumulative request count for 16 complete lifecycles, not a global maximum.
    - Documented that the waiting recovery queue can dispatch additional lifecycles as active workers finish, and the 100-orphan pool limit does not establish a fixed lifetime request ceiling because FIFO eviction allows fresh recovery work over time.
    - Stated explicitly that cumulative network work can exceed 4,848 requests over time under sustained attack.
    - Retained Medium severity based on the distinction between bounded concurrency and potentially repeated cumulative work, combined with the pre-validation orphan check vulnerability.
12. **SEC-P2P-013 Recalibrated:**
    - Corrected "unauthenticated arbitrary routing-table injection". Noted that `Identify` listen addresses are tied to the peer's authenticated `PeerId`. Reassessed as lack of address-filtering policy for self-advertised listen addresses (downgraded to **Low**).
13. **SEC-P2P-014 Recalibrated:**
    - Removed unsupported claim that trailing bytes specifically bypass Gossipsub deduplication. Limited finding to non-canonical framing acceptance (downgraded to **Low**).
14. **SEC-P2P-018 Qualified:**
    - Clarified that `0644` permissions on Unix are subject to process umask (e.g. umask `022`), not universal. Separated Windows discretionary ACL behavior.

---

## 3. Scope and Methodology

### 3.1 Scope
The audit inspected the complete execution paths across:
- **Core P2P Transport & Network Modules:**
  - `src/p2p/handshake.rs`: Protocol handshake payloads, serialization, compatibility verification.
  - `src/p2p/identity.rs`: Keypair generation, persistence, and PeerId derivation.
  - `src/p2p/framing.rs`: 4-byte LE framing, slice decoding, length bounds.
  - `src/p2p/protocol.rs`: Request/Response codec (`SyncCodec`), wire tags, serialization.
  - `src/p2p/network.rs`: `NetworkService`, `PeerRegistry`, Swarm event loop, actor channels.
  - `src/p2p/behaviour.rs`: `OwnChainBehaviour` combining Gossipsub, Kademlia, RequestResponse, Identify, Ping.
  - `src/p2p/mod.rs`: Public re-exports.
- **Node Runtime and Chain Storage Integration:**
  - `src/node/runtime.rs`: P2P event handling (`handle_network_event`), sync worker (`run_sync_worker`), missing parent recovery (`fetch_parent_block`), orphan pool (`add_orphan`), and sync request handling (`handle_sync_request`).
  - `src/node/config.rs`: Node networking configurations, limits, listen addresses.
  - `src/main.rs`: CLI commands for P2P initialization and node operation.
  - `docs/protocol-v1.md`: Section 8 ("Network / transport") and Section 10 ("Genesis and bootstrapping").
  - Test suites: `tests/node_runtime_e2e.rs` and unit tests in `src/p2p/`.

### 3.2 Methodology
For every finding:
1. Traced execution flow from raw network transport bytes to runtime state.
2. Verified trust boundaries between remote peers and internal actors.
3. Evaluated exact validation mechanics and protocol invariants.
4. Modeled realistic adversarial input and interaction sequences.
5. Assessed severity based on practical impact and operational constraints.
6. Formulated minimal regression test specifications.

---

## 4. Architecture and Trust-Boundary Overview

```
+-----------------------------------------------------------------------------------+
|                              UNTRUSTED NETWORK                                   |
|   Remote Peers (Inbound / Outbound TCP, Gossipsub mesh, Kademlia DHT neighbors)   |
+-----------------------------------------------------------------------------------+
                                         |
                                         | TCP / Noise (Ed25519) / Yamux
                                         v
+-----------------------------------------------------------------------------------+
| [TRUST BOUNDARY 1] Transport & Swarm Layer: NetworkService & libp2p Swarm         |
| - Identity: Noise Ed25519 keypair authenticated at transport handshake            |
| - Framing: 4-byte LE length prefix (max 2,100,000 bytes)                          |
| - Application Handshake: Mandatory initial exchange over /ownchain/sync/1         |
| - Subprotocols: Gossipsub (blocks/txs), ReqResp (sync), Kademlia DHT, Ping       |
| - Peer State: PeerRegistry (max 50 unique peers, multi-connection deduplication)  |
+-----------------------------------------------------------------------------------+
                                         |
                                         | MPSC Event Channel (NetworkEvent, cap 500)
                                         v
+-----------------------------------------------------------------------------------+
| [TRUST BOUNDARY 2] Consensus & Runtime Layer: NodeRuntime Actor                   |
| - Chain State & Storage: Redb BlockStore, Active Chain, Side Branches            |
| - Mempool: Transaction validation, admission, gossip broadcast                    |
| - Synchronization: Singular ActiveSync worker, 500ms sync selection loop          |
| - Orphan Pool: 100 blocks / 5MB bounded cache with FIFO eviction                 |
| - Missing Parent Recovery: Background async tasks (max 16 concurrent)             |
+-----------------------------------------------------------------------------------+
```

---

## 5. Findings Table

| Finding ID | Severity | Status | Classification | Audit Dimension | Title | Primary File and Line |
|---|---|---|---|---|---|---|
| `SEC-P2P-001` | **Medium** | **Fixed** | Confirmed | F-01, F-04, F-07 | Outbound Handshake Timeout Ignored, Causing Temporary Peer Slot Occupation | [`src/p2p/network.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs) |
| `SEC-P2P-002` | **High** | **Fixed** | Confirmed | F-05 | Gossipsub `validate_messages` Disabled and Automatic Forwarding of Unvalidated Messages | [`src/p2p/behaviour.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/behaviour.rs), [`src/p2p/network.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs) |
| `SEC-P2P-003` | **High** | **Fixed** | Confirmed | F-01, F-06, F-07 | Unverified Peer-Advertised Cumulative-Work Claims Starve Active Synchronization Slot | [`src/node/runtime.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs), [`src/p2p/network.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs) |
| `SEC-P2P-004` | **High** | **Fixed** | Confirmed | F-06 | Sync Worker Ingests Disconnected Blocks as Orphans, Falsely Reporting Success | [`src/node/runtime.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs) |
| `SEC-P2P-005` | **Medium** | **Fixed** | Confirmed (Cond.) | F-03, F-07 | Unchecked Arithmetic in `SyncRequest::GetHeaders` (Conditional Panic in Debug/Test) | [`src/node/runtime.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs) |
| `SEC-P2P-006` | **Medium** | **Mitigated** | Suspected | F-07 | Dual-Channel Actor Deadlock Between `NetworkService` and `NodeRuntime` | [`src/p2p/network.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs) |
| `SEC-P2P-007` | **Medium** | **Fixed** | Confirmed | F-05 | Transaction Gossip Rebroadcast Loop Causes Redundant Origin Publications | [`src/node/runtime.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs) |
| `SEC-P2P-009` | **Low** | **Fixed** | Confirmed | F-02, F-03 | Malleable Clamping of Collection Lengths in Sync Wire Payloads | [`src/p2p/protocol.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/protocol.rs) |
| `SEC-P2P-010` | **Medium** | **Partially fixed** | Confirmed | F-03, F-07 | Synchronous Full-Block Storage Reads and Deserialization in `GetHeaders` | [`src/node/runtime.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs), [`src/storage/mod.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/storage/mod.rs) |
| `SEC-P2P-011` | **Medium** | **Deferred / Open** | Confirmed | F-06, F-07 | Pre-Validation Orphan Admission and Multi-Peer Recovery Fanout DoS | [`src/node/runtime.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs) |
| `SEC-P2P-012` | **Medium** | **Open** | Confirmed | F-04, F-07 | Missing Limit on Concurrent Connections Per Peer or IP Address | [`src/p2p/network.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs) |
| `SEC-P2P-013` | **Low** | **Open** | Confirmed | F-04 | Unfiltered Self-Advertised Listen Address Injection into Kademlia DHT | [`src/p2p/network.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs) |
| `SEC-P2P-014` | **Low** | **Fixed** | Confirmed | F-02, F-05 | `decode_frame_slice` Accepts Non-Canonical Frames with Trailing Bytes | [`src/p2p/framing.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/framing.rs), [`src/p2p/network.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs) |
| `SEC-P2P-015` | **Low** | **Open** | Confirmed | F-02, F-07 | Eager Heap Buffer Allocation Before Payload Read in `SyncCodec` | [`src/p2p/protocol.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/protocol.rs) |
| `SEC-P2P-016` | **Low** | **Open** | Confirmed | F-01 | Permissive Lossy UTF-8 Conversion in Handshake and Error Strings | [`src/p2p/handshake.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/handshake.rs) |
| `SEC-P2P-018` | **Low** | **Open** | Confirmed | F-01 | Identity Key File Permissions Subject to Process Umask on Unix | [`src/p2p/identity.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/identity.rs) |
| `SEC-P2P-019` | **Info** | **Open** | Informational | F-04, F-05 | Complete Absence of Peer Scoring, Rate Limiting, and Banning Infrastructure | [`src/p2p/behaviour.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/behaviour.rs) |
| `SEC-P2P-020` | **Info** | **Open** | Informational | F-04 | Absence of Inbound vs. Outbound Peer Slot Reservation | [`src/p2p/network.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs) |
| `OBS-P2P-001` | **N/A** | **Fixed** | Implementation Obs. | F-03, F-06 | Batch Size Difference Between Header Requests (500) and Block Requests (64) | [`src/node/runtime.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs) |

---

## 6. Detailed Findings and Evidence

### SEC-P2P-001: Outbound Handshake Timeout Ignored, Causing Temporary Peer Slot Occupation
- **Severity:** Medium
- **Classification:** Confirmed
- **Audit Dimensions:** F-01 (Handshake and peer identity), F-04 (Peer management), F-07 (Denial of service)
- **Primary Locations:**
  - [`src/p2p/network.rs:648-656`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs#L648-L656)
  - [`src/p2p/network.rs:793-799`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs#L793-L799)
- **Description:**
  When a transport connection is established, `SwarmEvent::ConnectionEstablished` inserts the peer into `PeerRegistry` with `handshake: None` and transmits an outbound handshake request:
  ```rust
  let local_hs = self.current_handshake();
  let _ = self
      .swarm
      .behaviour_mut()
      .request_response
      .send_request(&peer_id, SyncRequest::Handshake(local_hs));
  ```
  The returned `OutboundRequestId` is discarded. If the remote peer drops or ignores the handshake, libp2p fires `ReqRespEvent::OutboundFailure` after the 10-second request timeout. In lines 793-799:
  ```rust
  ReqRespEvent::OutboundFailure { request_id, error, .. } => {
      if let Some(sender) = self.pending_sync_requests.remove(&request_id) {
          let _ = sender.send(Err(format!("outbound request failed: {error:?}")));
      }
  }
  ```
  Because the handshake `request_id` was not saved, this event is ignored and `request_disconnect` is never invoked.
  However, in `src/p2p/behaviour.rs:72`, `PingConfig::new()` initializes ping with default `keep_alive = false`. Ping streams do not reset the Swarm's 60-second idle connection timeout (`src/p2p/network.rs:424`). Consequently, inactive connections will be terminated after 60 seconds. Slot occupation is therefore temporary (lasting up to 60s per connection) unless sustained through repeated connections or stream activity.
- **Attack Scenario:**
  An attacker establishes 50 concurrent connections and drops handshake requests. For up to 60 seconds, all 50 slots in `PeerRegistry` are occupied with unhandshaked peers, causing legitimate inbound peers to be rejected with `RejectedMaxPeers`. To sustain the denial of service, the attacker must repeatedly reconnect.
- **Remediation:**
  1. Record outbound handshake request IDs in a tracking map: `pending_handshake_requests: HashMap<OutboundRequestId, PeerId>`.
  2. On `ReqRespEvent::OutboundFailure`, if `request_id` matches a pending handshake, call `self.request_disconnect(peer_id).await` immediately (after 10s) rather than waiting 60s for the idle timeout.
- **Regression Test Specification:**
  Connect a mock peer that completes Noise but drops the `/ownchain/sync/1` handshake request. Verify that upon request timeout (10s), `NetworkService` calls disconnect immediately and clears the peer from `PeerRegistry` without waiting 60s.
- **Implementation Status:** Fixed.
- **Hardening Details:**
  1. `NetworkService` maintains `pending_handshake_requests: HashMap<OutboundRequestId, (PeerId, Instant)>`. When an outbound handshake request fails (`ReqRespEvent::OutboundFailure`), the service disconnects the unresponsive peer immediately and removes it from `PeerRegistry` rather than waiting for the 60-second idle timeout.
  2. In `handle_inbound_response`, incoming responses to outbound handshake requests are strictly validated. If a peer replies with a non-handshake response (e.g. `SyncResponse::Error`, `Headers`, or `Blocks`), the node treats it as a protocol violation, disconnects the peer immediately, and cleans up tracking without misrouting to `pending_sync_requests`.

---

### SEC-P2P-002: Gossipsub `validate_messages` Disabled and Automatic Forwarding of Unvalidated Messages
- **Severity:** High
- **Classification:** Confirmed
- **Audit Dimensions:** F-05 (Gossip security)
- **Primary Location:**
  - [`src/p2p/behaviour.rs:41-51`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/behaviour.rs#L41-L51)
- **Description:**
  In `OwnChainBehaviour::new`:
  ```rust
  let gossipsub_config = GossipsubConfigBuilder::default()
      .validation_mode(ValidationMode::Permissive)
      .heartbeat_interval(Duration::from_millis(500))
      .max_transmit_size(2_100_000)
      .build()
      .map_err(|e| format!("gossipsub config error: {e}"))?;
  ```
  In libp2p Gossipsub:
  1. `ValidationMode::Permissive` allows messages with missing author, sequence number, or signature, while validating present fields.
  2. `validate_messages()` is the separate application-level validation toggle. Its default is `false`, and the current code does not enable it. When `validate_messages()` is false, Gossipsub immediately forwards messages to mesh peers without waiting for application validation.
  3. Setting `ValidationMode::Strict` alone does NOT halt automatic message forwarding—it only validates envelope authenticity. True gating requires enabling `validate_messages(true)` and explicitly calling `report_message_validation_result`.
  4. Crucially, the application validation pipeline does not yet exist. In `src/p2p/network.rs:721-726`, `GossipsubEvent::Message` discards `message_id` and `propagation_source`. The event path delivers only the deserialized block/transaction to `NodeRuntime`, making it impossible to report validation outcomes back to Gossipsub.
- **Attack Scenario:**
  An attacker injects 2MB blocks with invalid proof-of-work or conflicting state roots into `/ownchain/<network>/blocks/v1`. Honest nodes automatically forward these blocks to all mesh peers before `NodeRuntime` ever checks PoW, amplifying malicious traffic across the entire network.
- **Remediation:**
  1. Configure Gossipsub with strict authenticity and enable message validation:
     ```rust
     let gossipsub_config = GossipsubConfigBuilder::default()
         .validation_mode(ValidationMode::Strict)
         .validate_messages(true)
         .build()?;
     ```
  2. Preserve `message_id` and `propagation_source` (the forwarding `PeerId`) in `NetworkEvent::BlockReceived` / `TransactionReceived`.
  3. Implement an explicit validation lifecycle in `NodeRuntime` / `NetworkService`: perform preliminary structural/consensus validation (header PoW, transaction signature check) and invoke `gossipsub.report_message_validation_result(&msg_id, &propagation_source, MessageAcceptance::Accept)` or `MessageAcceptance::Reject`.
- **Regression Test Specification:**
  Connect two peers to a test node. Publish an invalid block frame (invalid PoW) to Gossipsub from peer A. Assert that peer B does not receive the relayed message from the test node.
- **Implementation Status:** Fixed.
- **Hardening Details:**
  1. Configured Gossipsub with `ValidationMode::Strict` and `validate_messages(true)` in `src/p2p/behaviour.rs`.
  2. Preserved `message_id` and `propagation_source` in `NetworkEvent::BlockReceived` and `TransactionReceived`.
  3. Separated pending validation token TTL (`PENDING_GOSSIP_TTL` = 8s) from in-flight payload processing lock (`IN_FLIGHT_PAYLOAD_TTL` = 30s) in `src/p2p/network.rs`.
  4. Implemented `in_flight_payloads: HashMap<Hash, InFlightPayloadEntry>` and `in_flight_by_msg_id: HashMap<MessageId, (Hash, u64)>` to track payload processing ownership independently of libp2p validation tokens. Duplicate messages arriving while validation is in flight are immediately dropped with `MessageAcceptance::Ignore` without spawning duplicate runtime validation.
  5. Monotonic Generation Tracking on Payload Locks: Added `generation: u64` counter to `InFlightPayloadEntry`. When late validation results arrive via `ReportGossipValidation`, generation matching is strictly enforced; a stale validation outcome from a timed-out token cannot release or corrupt an in-flight lock held by a newer validation generation.
  6. Token sweep expires tokens to prevent libp2p memory leaks but retains payload ownership until validation completes or the 30s payload timeout elapses. Late validation completions cleanly release payload locks.
  7. Mempool admission classifies `AlreadyOnChain` as `(MessageAcceptance::Ignore, true)` to deduplicate already-confirmed transactions, while keeping transient errors (`MempoolFull`, `Internal`) retryable (`seen = false`).

---

### SEC-P2P-003: Unverified Peer-Advertised Cumulative-Work Claims Starve Active Synchronization Slot
- **Severity:** High
- **Classification:** Confirmed
- **Audit Dimensions:** F-01 (Handshake and peer identity), F-06 (Synchronization security), F-07 (Denial of service)
- **Primary Locations:**
  - [`src/node/runtime.rs:1410-1420`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs#L1410-L1420)
  - [`src/node/runtime.rs:1465-1485`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs#L1465-L1485)
  - [`src/node/runtime.rs:1512-1530`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs#L1512-L1530)
  - [`src/p2p/network.rs:814-849`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs#L814-L849), [`192-200`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs#L192-L200)
- **Description:**
  Peer identity is authenticated at the transport level via Noise Ed25519 keypairs. However, the peer's advertised `cumulative_work`, `tip_height`, and `tip_block_id` fields are completely unverified by `HandshakeMessage::verify_compatibility`.
  In `NodeRuntime::run`:
  1. `let mut sync_interval = tokio::time::interval(Duration::from_millis(500));` ticks every 500ms, invoking `self.check_sync().await`.
  2. `check_sync` iterates through all connected peers and selects `best_peer` based strictly on `hs.cumulative_work > best_work`.
  3. `self.start_sync(peer_id, peer_height, None)` enforces a strict single-worker concurrency limit: only ONE active synchronization worker can exist for the entire node (`self.active_sync`). Any concurrent sync requests are rejected with `"Sync already in progress"`.
  4. When sync with a malicious peer fails (e.g. peer stalls, disconnects, or returns invalid headers), `active_sync` is dropped, but NO peer-specific failure cooldown or backoff is recorded.
  5. On the next 500ms tick, `check_sync` re-scans connected peers. Because the attacker peer is still connected and still advertises the highest work, it is selected again immediately.
  6. Furthermore, `handle_inbound_request` permits connected peers to repeatedly send unsolicited `SyncRequest::Handshake` messages ([`src/p2p/network.rs:814-849`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs#L814-L849)), updating `PeerInfo.handshake` in `PeerRegistry` dynamically without reconnecting, allowing an attacker to continually manipulate its advertised work.
- **Attack Scenario:**
  An attacker connects and advertises `cumulative_work = U256::MAX`. The node launches sync with the attacker, rejecting honest peers. When the sync worker aborts due to stall or error, the 500ms `check_sync` loop immediately re-selects the attacker, creating an infinite starvation loop that permanently blinds the node to honest consensus tips.
- **Remediation:**
  1. Implement a peer sync cooldown/backoff map (`sync_failure_cooldowns: HashMap<PeerId, Instant>`) that prevents re-selecting a failed peer for a designated duration (e.g. 60 seconds).
  2. Disconnect and penalize peers that advertise higher cumulative work but fail to produce valid connecting headers.
  3. Reject repeated unsolicited `SyncRequest::Handshake` requests on already-handshaked connections.
- **Regression Test Specification:**
  Connect mock peer A claiming `cumulative_work: U256::MAX` that fails `GetHeaders`, alongside honest peer B claiming valid work. Assert that after peer A's sync fails, peer A is placed on cooldown, and the next 500ms `check_sync` tick selects peer B.
- **Implementation Status:** Fixed.
- **Hardening Details:**
  1. Enforced peer quarantine and backoff registry in `NodeRuntime` with exponential escalation for repeat offenders (`INITIAL_PENALTY_SECS` = 30s up to `MAX_PENALTY_SECS` = 600s).
  2. Hardened peer selection (`select_sync_peer`): verifies stored peer-tip claims against local storage before initiating sync, demoting peers whose advertised tip has already been surpassed or equaled by verified local chain height.
  3. Initial Handshake Ordering Race Resolution & Inbound Handshake Tracking: `NetworkService` maintains `inbound_handshake_processed: HashSet<PeerId>` to decouple tracking of the peer's initial inbound `SyncRequest::Handshake` from the general verified-handshake state in `PeerRegistry` (`is_handshake_done`). Because both peers send outbound handshakes concurrently on connection establishment, our outbound handshake response may arrive and populate `PeerRegistry` before the peer's initial inbound request arrives. On the first inbound handshake request, `handle_inbound_request` verifies protocol/chain/genesis compatibility, marks the peer in `inbound_handshake_processed`, preserves any already-established handshake metadata without overwriting, and sends `SyncResponse::Handshake(local_handshake)`. Subsequent unsolicited inbound handshake requests from that peer are rejected with `SyncResponse::Error("handshake already established")` without modifying established claims. The tracking state is cleanly removed when the peer is disconnected (or fully removed upon closing the final transport connection in multi-connection configurations).
  4. Failover Verification: Verified end-to-end in `tests/node_runtime_e2e.rs::test_real_p2p_sync_liar_high_work_fails_over_and_survives_reconnect`, where a malicious peer advertising `U256::MAX` cumulative work fails header delivery, is cooled down with `TransientOrTimeout`, fails over to an honest peer with height 4, synchronizes the chain, and remains synchronized even after the liar reconnects or attempts handshake updates.
  5. Canonical-Chain AlreadySynchronized Verification: In `evaluate_active_sync_outcome`, when a peer claims a lower tip height than the local tip (`claim.tip_height < local_tip_height`), the runtime verifies that the advertised block ID is present on the active canonical chain via `self.storage.get_header_by_height(claim.tip_height)`. Known side-branch blocks do not qualify as canonical prefixes and are rejected with `SyncFailureClass::FalseAdvertisedWorkClaim`, ensuring dishonest or divergent peers cannot receive false `AlreadySynchronized` success. Furthermore, in `run_sync_worker`, peer header responses at the claimed tip height must match the advertised tip block ID, returning `SyncWorkerError::FalseAdvertisedClaim` on discrepancy.
  6. Manual Sync Target-Height Reconciliation and Genesis Verification: In the `NodeCommand::SyncWithPeer` handling path and `start_sync_internal`, caller-provided `peer_tip_height` values are authoritatively reconciled against `advertised_claim.tip_height` from the authenticated peer handshake. Stale or mismatched heights supplied by callers cannot induce premature completion, incorrect synchronization targets, or unjust peer penalties. For genesis-only peers (height 0), `run_sync_worker` explicitly verifies that advertised tip block IDs match the canonical genesis block ID (`snapshot.get_block_id(0)`), penalizing peers that advertise non-canonical genesis tips with `FalseAdvertisedWorkClaim` while granting verified `AlreadySynchronized` success to honest genesis-only peers.

---

### SEC-P2P-004: Sync Worker Ingests Disconnected Blocks as Orphans, Falsely Reporting Success
- **Severity:** High
- **Classification:** Confirmed
- **Audit Dimensions:** F-06 (Synchronization security)
- **Primary Locations:**
  - [`src/node/runtime.rs:2108-2163`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs#L2108-L2163)
  - [`src/node/runtime.rs:1644-1650`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs#L1644-L1650)
  - [`src/node/runtime.rs:2400-2413`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs#L2400-L2413)
- **Description:**
  During synchronization, `run_sync_worker` downloads headers and requests full blocks via `GetBlocks`.
  When blocks arrive, `ApplyBlockBatch` sends them to `NodeRuntime::handle_inbound_block`.
  In `handle_inbound_block`:
  ```rust
  if !self.has_block(&parent_id) {
      self.add_orphan(block_id, *block, source_peer);
      self.trigger_missing_parent_recovery(parent_id, block_id, source_peer);
      return Ok((BlockProcessingOutcome::Ignored, Vec::new()));
  }
  ```
  When a block's parent is missing, it is admitted into the orphan pool and returns `Ok((BlockProcessingOutcome::Ignored, ...))`.
  In `handle_sync_message`:
  ```rust
  let mut result = Ok(());
  for block in blocks {
      if let Err(e) = self.handle_inbound_block(peer_id, Box::new(block)).await {
          result = Err(e);
          break;
      }
  }
  let _ = respond_to.send(result);
  ```
  Because `handle_inbound_block` returned `Ok(...)`, `ApplyBlockBatch` considers the batch successful (`result = Ok(())`).
  In `run_sync_worker`:
  ```rust
  let num_blocks = blocks.len() as u64;
  ...
  ack_rx.await??;
  current_h += num_blocks;
  ```
  The sync worker increments `current_h` by `num_blocks`, continues to the end of the loop, and completes with `Ok(())`.
  The sync operation reports successful completion (`SyncTaskResult { result: Ok(()) }`), even though ZERO blocks extended the chain.
- **Attack Scenario:**
  A peer delivers disconnected blocks with unknown parents. The node caches them as orphans, advances its sync height counter, and marks sync complete. The node's active chain tip remains completely unadvanced while reporting successful synchronization.
- **Remediation:**
  In `handle_sync_message` / `ApplyBlockBatch`, require that all synced blocks strictly extend the chain (either active tip or stored branch). If an inbound block during sync is an orphan (`BlockProcessingOutcome::Ignored`), fail the batch with `Err("synced block has missing parent")` and terminate the sync operation.
- **Regression Test Specifications:**
  1. *Unknown-parent orphan block:* Deliver a block with an unknown parent hash during sync; assert batch returns `Err`, sync worker aborts, and active tip is unchanged.
  2. *Empty headers response before tip:* Return empty headers response before `peer_tip_height`; assert sync detects premature termination and reports failure.
  3. *Empty blocks response:* Return empty blocks response for requested headers; assert sync fails immediately rather than advancing `current_h`.
  4. *Mismatched returned block IDs:* Return blocks whose hashes do not match requested header IDs; assert batch fails validation and aborts.
  5. *Truthful progress assertion:* Assert sync never reports `Ok(())` unless blocks were durably applied to active chain or validated stored branch.
- **Implementation Status:** Fixed.
- **Hardening Details:**
  1. Eliminated false sync success: `handle_sync_message` in `src/node/runtime.rs` strictly pre-screens block parentage against local storage (`has_block(&parent_id)`).
  2. If a block is an orphan, it is rejected immediately with `SyncBatchError::DisconnectedOrphan`. Sync blocks are NEVER passed to the generic orphan pool (`self.orphan_blocks`) and NEVER trigger missing parent recovery.
  3. Updated `RuntimeSyncMessage::ApplyBlockBatch` to return a strongly-typed `SyncBatchReceipt` (`blocks_processed`, `active_blocks_persisted`, `side_blocks_persisted`, `already_known_duplicates`, `reached_advertised_tip`, `status`).
  4. Sync worker (`run_sync_worker`) returns `Result<SyncWorkerSuccess, SyncWorkerError>`: advances its cursor `current_h` only by `receipt.blocks_processed`. On batch error or missing blocks, it terminates immediately and propagates typed errors.
  5. Manual sync notifier (`active_op.notifier`) receives `Ok(())` ONLY IF `evaluate_active_sync_outcome` confirms `SyncOutcomeEvaluation::VerifiedSuccess`. Stalls, incomplete progress, and orphan rejections receive descriptive error strings, eliminating false-success reporting.
  6. Rigorous Header Response & Ancestor Discovery Validation: Fast-path and binary search header responses are strictly validated: empty responses return `Incomplete`, multiple headers, wrong height, or wrong chain ID return `ConsensusInvalid`. Transport failures do not trigger fallback to binary search.
  7. Strict Block Response & Cursor Validation: `blocks.len() > headers.len()` returns `ConsensusInvalid`. For each block at position $i$, `block.header.block_id() == block_ids[i]`, `&block.header == &headers[i]`, and `block.header.height == expected_height` are verified. Short block responses are strictly bounded as valid contiguous prefixes, and the worker cursor advances ONLY by `receipt.blocks_processed`. Reordered bodies, unrequested bodies, and missing middle blocks return `ConsensusInvalid`.
  8. Verified Completion States & Unified Absolute Deadline: Arithmetic overflow safety is enforced across `mid`, `min_h - 1`, and cursor increments. Work budgets (`MAX_SYNC_BLOCKS = 10_000`, `MAX_SYNC_ROUND_TRIPS = 500`, `SYNC_TIMEOUT = 60s`) prevent unbounded work. The sync worker enforces a single non-resetting absolute operation deadline (`tokio::time::Instant::now() + timeout_duration`) wrapping all 6 awaited operations (`GetHeaders` fast-path, binary-search, batch headers, `GetBlocks`, `ApplyBlockBatch` send, and batch acknowledgement receive) via `tokio::time::timeout_at(deadline, ...)`. Operation stalls or chained delays terminate with `BudgetExhausted` when the overall deadline expires, preventing unbounded peer time consumption.
  9. Cooperative Cancellation and Late Batch Acknowledgement Handling: When the absolute sync operation deadline expires while awaiting local block batch acknowledgement on `ack_rx`, the worker atomically sets `cancel_flag = true` and returns `SyncWorkerError::BudgetExhausted`. On the runtime actor loop, `handle_sync_message` checks `cancel_flag` prior to and during block processing; if set, the late batch is dropped immediately with `SyncBatchError::StaleOperation` and zero blocks are persisted. In `evaluate_active_sync_outcome`, `BudgetExhausted` caused by local dispatch or batch acknowledgement delay evaluates to `SyncOutcomeEvaluation::LocalFaultNoPeerPenalty`, ensuring honest peers are not penalized for slow local processing while guaranteeing cancelled sync operations do not cause contradictory progress accounting or delayed state mutation.

---

### SEC-P2P-005: Unchecked Arithmetic in `SyncRequest::GetHeaders` (Conditional Panic in Debug/Test)
- **Severity:** Medium
- **Classification:** Confirmed (Conditional)
- **Audit Dimensions:** F-03 (Request/response protocol), F-07 (Denial of service)
- **Primary Location:**
  - [`src/node/runtime.rs:2281-2285`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs#L2281-L2285)
- **Description:**
  In `NodeRuntime::handle_sync_request`:
  ```rust
  SyncRequest::GetHeaders { start_height, max_count } => {
      let count = (max_count as usize).min(MAX_HEADERS_PER_RESPONSE);
      let mut headers = Vec::with_capacity(count);
      for h in start_height..(start_height + count as u64) {
  ```
  If a peer sends `start_height = u64::MAX - 10` and `max_count = 500`:
  - In **debug and test profiles** (and release profiles configured with `overflow-checks = true`), `start_height + count as u64` panics on overflow, crashing the `NodeRuntime` actor loop.
  - In **standard release profile** without overflow checks, the addition wraps around to `499`. The range `u64::MAX..499` is an empty range (`start > end`), causing the loop to execute 0 times and return an empty `Headers(vec![])` response without panicking.
  Thus, exploitability as a remote crash is conditional on build configuration.
- **Remediation:**
  Use saturating addition:
  ```rust
  let end_height = start_height.saturating_add(count as u64);
  for h in start_height..end_height {
  ```
- **Regression Test Specification:**
  Pass `SyncRequest::GetHeaders { start_height: u64::MAX, max_count: 500 }` to `handle_sync_request`. Assert that it does not panic in debug mode and returns `SyncResponse::Headers(vec![])`.
- **Implementation Status:** Fixed.
- **Hardening Details:**
  Replaced `start_height + count as u64` in `handle_sync_request` with `start_height.saturating_add(count as u64)`, preventing arithmetic overflow panics in debug/test profiles.

---

### SEC-P2P-006: Dual-Channel Actor Deadlock Between `NetworkService` and `NodeRuntime`
- **Severity:** Medium
- **Classification:** Suspected
- **Audit Dimensions:** F-07 (Denial of service)
- **Primary Locations:**
  - [`src/p2p/network.rs:745-766`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs#L745-L766), [`868-874`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs#L868-L874)
  - [`src/node/runtime.rs:2249`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs#L2249), [`2263`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs#L2263)
- **Description:**
  `NetworkService` sends events to `NodeRuntime` over `event_tx` (bound: 500).
  `NodeRuntime` sends commands to `NetworkService` over `command_tx` (bound: 500).
  Wait cycle hypothesis:
  1. `NetworkService` handles incoming swarm messages and awaits `self.event_tx.send(...).await`.
  2. If `event_tx` fills (e.g. during a flood of transactions or sync requests while the runtime is performing PoW/state verification), `NetworkService` blocks, pausing `swarm.select_next_some()`.
  3. While `NetworkService` is blocked, it cannot drain `command_rx`.
  4. If `NodeRuntime` concurrently attempts to send commands via `self.command_tx.send(...).await` (such as `send_sync_response` or `broadcast_transaction`) when `command_tx` is full, `NodeRuntime` blocks awaiting capacity in `command_tx`.
  5. Both actors await each other.
  This issue is marked **Suspected** because deadlock requires concurrent saturation of both 500-slot channels, which has not yet been reproduced under integration testing.
- **Remediation:**
  Use non-blocking `try_send` for bulk gossip events (`BlockReceived`, `TransactionReceived`), dropping or buffering events outside the actor loop when channels are saturated.
- **Regression Test Specification:**
  Saturate `event_tx` with 500 mock events while filling `command_tx` with 500 commands. Verify that `NetworkService` and `NodeRuntime` do not deadlock.
- **Implementation Status:** Mitigated.
- **Hardening Details:**
  `NetworkService::handle_inbound_request` uses non-blocking `try_send` for `SyncRequestReceived`. If the runtime event queue is saturated, it immediately replies to the requester with `SyncResponse::Error("node busy")`, preventing the network actor loop from blocking on full event channels. However, peer lifecycle events still use bounded sends, preserving residual architectural uncertainty under extreme saturation. Dual-channel refactoring remains part of future network milestones.

---

### SEC-P2P-007: Transaction Gossip Rebroadcast Loop Causes Redundant Origin Publications
- **Severity:** Medium
- **Classification:** Confirmed
- **Audit Dimensions:** F-05 (Gossip security)
- **Primary Locations:**
  - [`src/node/runtime.rs:2243-2250`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs#L2243-L2250)
  - [`src/p2p/network.rs:558-570`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs#L558-L570)
- **Description:**
  When a transaction is received from Gossipsub:
  1. Gossipsub already relays the message to mesh neighbors.
  2. `NetworkEvent::TransactionReceived` is delivered to `NodeRuntime`.
  3. Upon mempool admission, `NodeRuntime` executes:
     `let _ = self.network_handle.broadcast_transaction(transaction).await;`
  4. `NetworkService` signs and publishes a brand new Gossipsub message containing the identical transaction.
  5. Across a network of $N$ nodes, each peer acts as an independent publisher for the same transaction, generating $O(N)$ redundant origin publications. Depending on mesh topology and degree $D$, this produces widespread duplicate deliveries across the network.
- **Remediation:**
  Only call `broadcast_transaction` for transactions submitted locally via RPC/CLI, not for transactions received via gossip.
- **Regression Test Specification:**
  Verify that when `NetworkEvent::TransactionReceived` is processed, `network_handle.broadcast_transaction` is NOT invoked.
- **Implementation Status:** Fixed.
- **Hardening Details:**
  `NodeRuntime` distinguishes local vs. remote transaction origins: transactions admitted via gossip are NOT rebroadcast back to the network, eliminating redundant origin publications.

---

### SEC-P2P-009: Malleable Clamping of Collection Lengths in Sync Wire Payloads
- **Severity:** Low
- **Classification:** Confirmed
- **Audit Dimensions:** F-02 (Frame decoding), F-03 (Request/response protocol)
- **Primary Locations:**
  - [`src/p2p/protocol.rs:165-173`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/protocol.rs#L165-L173)
  - [`src/p2p/protocol.rs:323-331`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/protocol.rs#L323-L331)
  - [`src/p2p/protocol.rs:348-377`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/protocol.rs#L348-L377)
- **Description:**
  In `SyncResponse::from_bytes` for `TAG_RESP_HEADERS`:
  ```rust
  let count = u32::from_le_bytes(bytes[1..5].try_into().unwrap()) as usize;
  let count = count.min(MAX_HEADERS_PER_RESPONSE);
  let expected = 5 + count * HEADER_LEN;
  if bytes.len() != expected { ... }
  ```
  If a wire message claims `count = 1000` but provides 500 headers (`bytes.len() == 5 + 500 * HEADER_LEN`), `count.min(500)` clamps the count to 500, matching `bytes.len()`. The parser accepts a non-canonical wire message claiming 1000 items. Identical clamping exists in `SyncRequest::GetBlocks` and `SyncResponse::Blocks`.
  Because payload length is strictly checked against the clamped count, this does not allow memory corruption or buffer overflows; impact is limited to parser ambiguity and non-canonical encoding acceptance.
- **Remediation:**
  Reject messages where wire count exceeds protocol maximums:
  ```rust
  let raw_count = u32::from_le_bytes(bytes[1..5].try_into().unwrap()) as usize;
  if raw_count > MAX_HEADERS_PER_RESPONSE {
      return Err(io::Error::new(io::ErrorKind::InvalidData, "header count exceeds limit"));
  }
  ```
- **Regression Test Specification:**
  Pass a payload with count prefix `1000` and 500 headers to `SyncResponse::from_bytes`. Assert that it returns `Err(io::ErrorKind::InvalidData)`.
- **Implementation Status:** Fixed.
- **Hardening Details:**
  Removed malleable clamping in `SyncCodec` and `protocol.rs`; incoming collection lengths exceeding protocol limits (`MAX_HEADERS_PER_RESPONSE`, `MAX_BLOCKS_PER_RESPONSE`) are strictly rejected with `io::ErrorKind::InvalidData`.

---

### SEC-P2P-010: Synchronous Full-Block Storage Reads and Deserialization in `GetHeaders`
- **Severity:** Medium
- **Classification:** Confirmed
- **Audit Dimensions:** F-03 (Request/response protocol), F-07 (Denial of service)
- **Primary Location:**
  - [`src/node/runtime.rs:2277-2291`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs#L2277-L2291)
  - [`src/storage/mod.rs`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/storage/mod.rs)
- **Description:**
  When serving `SyncRequest::GetHeaders { start_height, max_count }`:
  Previously, `get_block_by_height(h)` read full canonical blocks from redb and deserialized all transactions and proofs just to extract the 170-byte header.
  The maximum consensus block size is 2,000,000 bytes. In the theoretical worst-case of 500 full blocks, this would read and deserialize up to 1 GB of data. On an active network with typical block sizes, reading hundreds of full blocks still imposed heavy synchronous I/O and CPU deserialization directly on the single-threaded `NodeRuntime` actor loop, blocking consensus and block processing.
- **Remediation:**
  Extract headers directly from raw storage bytes without deserializing full blocks, and store headers in a dedicated `TABLE_HEADERS` redb table for lightweight $O(1)$ retrieval.
- **Regression Test Specification:**
  Verify that serving `GetHeaders` does not invoke full block deserialization.
- **Implementation Status:** Partially fixed.
- **Hardening Details:**
  Implemented `Storage::get_header_by_height(&self, height: u64) -> Result<Option<Header>, StorageError>` in `src/storage/mod.rs`. This method looks up the raw block bytes in `TABLE_BLOCKS` and extracts the canonical 170-byte `Header` directly (`&raw[..HEADER_LEN]`), bypassing full block/transaction/witness deserialization entirely. `NodeRuntime::handle_sync_request` now calls `self.storage.get_header_by_height(h)`. Dedicated `TABLE_HEADERS` table extraction is scheduled alongside database index optimizations.

---

### SEC-P2P-011: Pre-Validation Orphan Admission and Multi-Peer Recovery Fanout DoS
- **Severity:** Medium
- **Classification:** Confirmed
- **Audit Dimensions:** F-06 (Synchronization security), F-07 (Denial of service)
- **Primary Locations:**
  - [`src/node/runtime.rs:2395-2413`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs#L2395-L2413)
  - [`src/node/runtime.rs:757-821`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs#L757-L821)
  - [`src/node/runtime.rs:852-857`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs#L852-L857)
- **Description:**
  In `NodeRuntime::process_single_block`:
  ```rust
  let parent_exists = parent_id.is_zero()
      || self.storage.has_block(&parent_id)...;
  if !parent_exists {
      self.add_orphan(block_id, *block, source_peer);
      self.trigger_missing_parent_recovery(parent_id, block_id, source_peer);
      return Ok((BlockProcessingOutcome::Ignored, Vec::new()));
  }
  ```
  Crucially, missing-parent checks occur **before** proof-of-work, difficulty, or consensus validation! An attacker can generate completely unmined blocks with zero proof of work and random parent hashes. The node accepts them as orphans and triggers missing-parent recovery.
  In `fetch_parent_block` and `trigger_missing_parent_recovery`, network query accounting proceeds as follows:
  1. *Per-attempt request bound:* 101 requests maximum per recovery attempt. Within each attempt, the recovery worker issues 1 request to `source_peer` with `GetBlocks`. If that fails, it queries up to `max_peers` (default 50 in `DEFAULT_MAX_PEERS`, configurable in `NodeConfig`) with `GetBlocks`, and then loops through all connected peers again with `GetMissingParent`. This yields at most $1 + 50 + 50 = 101$ sequential requests per attempt.
  2. *Lifecycle attempt bound:* 3 total attempts per parent-recovery lifecycle (`attempts` starts at 1, and recovery is capped at `attempts >= MAX_PARENT_RETRIES` where `MAX_PARENT_RETRIES = 3`).
  3. *Lifecycle request bound:* 303 requests maximum per lifecycle ($3 \times 101 = 303$ sequential requests).
  4. *Concurrent worker ceiling vs. global limit:* 16 is the maximum number of recovery workers operating concurrently (`in_flight_recovery_count() >= 16`), NOT a global limit on all recovery lifecycles.
  5. *Cumulative request count for 16 lifecycles:* Therefore, 4,848 ($16 \times 303$) is only the cumulative request count for 16 complete lifecycles, not a global maximum.
  6. *Queue dispatch mechanism:* The waiting recovery queue (`self.waiting_recoveries`) can dispatch additional lifecycles as active workers finish.
  7. *Orphan pool bounds do not establish a fixed lifetime limit:* The orphan pool limits retained orphan blocks to 100 (`MAX_ORPHAN_BLOCKS`), but this does not establish a fixed lifetime request limit because new recovery work can be triggered over time (FIFO eviction continually discards older orphans to admit fresh blocks).
  8. *Sustained cumulative work:* Cumulative network work can exceed 4,848 requests over time under sustained attack as new unmined blocks arrive and waiting lifecycles are processed.
  9. *Timeout impact:* With a 3-second timeout per request, each attempt can occupy a worker for up to 303 seconds, and a full 3-attempt lifecycle can take up to 909 seconds (excluding backoff intervals).
  Medium severity is retained based on the critical distinction between bounded concurrency (at most 16 recovery workers operating concurrently, with each worker issuing requests sequentially) and potentially repeated cumulative work over time, enabled by cheap pre-validation orphan admission.
- **Attack Scenario:**
  An attacker floods cheap unmined blocks with fake parent hashes over Gossipsub. All 16 concurrent recovery worker slots are continuously occupied, and the node continually dispatches cycles of up to 303 requests per orphan, bombarding connected peers with thousands of redundant queries over time.
- **Remediation:**
  1. Validate header proof of work, difficulty target, and timestamp *before* admitting any block to the orphan pool or triggering missing parent recovery.
  2. Only query `source_peer` for missing parents; do not poll all connected peers for unverified orphan blocks.
- **Regression Test Specification:**
  Deliver an orphan block with invalid/zero proof of work. Verify that:
  1. The block is rejected immediately without admission to `orphan_blocks`.
  2. `trigger_missing_parent_recovery` is NOT invoked.
  3. No outbound `GetBlocks` or `GetMissingParent` requests are generated.
- **Implementation Status:** Deferred / Open (Scheduled for Milestone 4).
- **Hardening Details:**
  *Critical Architectural Distinction:* Synchronization-specific orphan block ingestion was completely eliminated and hardened under `SEC-P2P-004` (inbound batch sync blocks are strictly pre-screened against local storage; orphans fail immediately via `SyncBatchError::DisconnectedOrphan`, are NEVER admitted to `orphan_blocks`, and NEVER trigger missing-parent recovery). However, gossipsub pre-validation orphan admission in `process_single_block` and multi-peer recovery fanout remain open and are explicitly scheduled for Milestone 4 hardening.

---

### SEC-P2P-012: Missing Limit on Concurrent Connections Per Peer or IP Address
- **Severity:** Medium
- **Classification:** Confirmed
- **Audit Dimensions:** F-04 (Peer management), F-07 (Denial of service)
- **Primary Locations:**
  - [`src/p2p/network.rs:127-132`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs#L127-L132)
  - [`src/p2p/network.rs:657-664`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs#L657-L664)
- **Description:**
  `PeerRegistry::handle_connection_established` deduplicates by `PeerId` and returns `ConnectionAction::ExistingPeer` for additional connections from an already-registered peer.
  However, there is no limit on the number of simultaneous transport connections established by the same `PeerId` or from the same remote IP address, allowing socket and file descriptor exhaustion.
- **Remediation:**
  Enforce a hard limit on connections per `PeerId` (max 1-2) and per remote IP address (max 3).
- **Regression Test Specification:**
  Verify that opening a second concurrent connection from the same peer is rejected.

---

### SEC-P2P-013: Unfiltered Self-Advertised Listen Address Injection into Kademlia DHT
- **Severity:** Low
- **Classification:** Confirmed
- **Audit Dimensions:** F-04 (Peer management)
- **Primary Locations:**
  - [`src/p2p/network.rs:640-643`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs#L640-L643)
  - [`src/p2p/network.rs:692-701`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs#L692-L701)
- **Description:**
  Addresses received in `Identify` events are added to Kademlia via `kademlia.add_address(&peer_id, addr)`. These addresses are associated with the peer's Noise-authenticated `PeerId`.
  However, the node performs no filtering on self-advertised listen addresses. A peer can advertise loopback (`127.0.0.1`), private subnets (RFC 1918), or victim IPs as its own listen addresses, polluting DHT routing tables.
- **Remediation:**
  Filter addresses before adding to Kademlia: reject loopback, unspecified, and private IP addresses on public networks.
- **Regression Test Specification:**
  Feed an `Identify` event with loopback and private IPs and assert that Kademlia filters them out.

---

### SEC-P2P-014: `decode_frame_slice` Accepts Non-Canonical Frames with Trailing Bytes
- **Severity:** Low
- **Classification:** Confirmed
- **Audit Dimensions:** F-02 (Frame decoding), F-05 (Gossip security)
- **Primary Locations:**
  - [`src/p2p/framing.rs:102-127`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/framing.rs#L102-L127)
  - [`src/p2p/network.rs:739-768`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs#L739-L768)
- **Description:**
  `decode_frame_slice` returns `Ok((payload, remaining))`. In `handle_gossip_message`, the remaining unconsumed bytes are ignored.
  OwnChain's application layer in `NetworkService::mark_seen` hashes the parsed `block_id` or `tx_id`. Gossipsub calculates its internal message ID from topic and payload. The confirmed issue is acceptance of non-canonical wire frames with trailing garbage.
- **Remediation:**
  Verify that `remaining.is_empty()` when decoding gossip frames.
- **Regression Test Specification:**
  Pass a frame with trailing garbage to `handle_gossip_message` and verify it is rejected.
- **Implementation Status:** Fixed.
- **Hardening Details:**
  Added `decode_frame_slice_exact` in `src/p2p/framing.rs` that returns `FramingError::TrailingBytes { remaining }` if unconsumed bytes exist after decoding the framed payload. Integrated across gossip block/transaction handling in `src/p2p/network.rs`, rejecting non-canonical frames with `MessageAcceptance::Reject`.

---

### SEC-P2P-015: Eager Heap Buffer Allocation Before Payload Read in `SyncCodec`
- **Severity:** Low
- **Classification:** Confirmed
- **Audit Dimensions:** F-02 (Frame decoding), F-07 (Denial of service)
- **Primary Locations:**
  - [`src/p2p/protocol.rs:428-439`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/protocol.rs#L428-L439)
  - [`src/p2p/protocol.rs:450-461`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/protocol.rs#L450-L461)
- **Description:**
  `SyncCodec::read_request` and `read_response` read a 4-byte length prefix and immediately allocate `vec![0u8; len]` (up to 2.1MB) before reading payload bytes. A slowloris attacker opening multiple streams with 2.1MB prefixes can pin heap memory.
- **Remediation:**
  Read data in bounded chunks into a growable buffer.
- **Regression Test Specification:**
  Send a 4-byte length prefix without following bytes; verify resource caps on stream reads.

---

### SEC-P2P-016: Permissive Lossy UTF-8 Conversion in Handshake and Error Strings
- **Severity:** Low
- **Classification:** Confirmed
- **Audit Dimensions:** F-01 (Handshake and peer identity)
- **Primary Locations:**
  - [`src/p2p/handshake.rs:153`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/handshake.rs#L153)
  - [`src/p2p/protocol.rs:403`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/protocol.rs#L403)
- **Description:**
  `String::from_utf8_lossy` permits non-printable ASCII and ANSI escape sequences in `software_version` and error messages, creating terminal log injection risks.
- **Remediation:**
  Validate that string fields contain only printable ASCII/UTF-8 characters.

---

### SEC-P2P-018: Identity Key File Permissions Subject to Process Umask on Unix
- **Severity:** Low
- **Classification:** Confirmed
- **Audit Dimensions:** F-01 (Handshake and peer identity)
- **Primary Location:**
  - [`src/p2p/identity.rs:58`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/identity.rs#L58)
- **Description:**
  In `load_or_generate_identity`:
  `fs::write(p, encoded)?;`
  On Unix-like systems, `fs::write` creates files with permissions subject to the process umask. For example, under a standard umask of `022`, the key file is created with mode `0644` (world-readable on multi-user systems). On Windows, NTFS discretionary ACLs inherited from the user directory govern access.
- **Remediation:**
  Explicitly set mode `0600` on Unix systems via `std::os::unix::fs::PermissionsExt`.

---

### SEC-P2P-019: Complete Absence of Peer Scoring, Rate Limiting, and Banning Infrastructure
- **Severity:** Informational
- **Classification:** Informational
- **Audit Dimensions:** F-04, F-05
- **Primary Locations:**
  - [`src/p2p/behaviour.rs:40-52`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/behaviour.rs#L40-L52)
  - [`src/p2p/network.rs:807-876`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs#L807-L876)
- **Description:**
  There is currently no peer reputation, gossipsub peer scoring, request rate limiting, or IP banning framework in OwnChain.

---

### SEC-P2P-020: Absence of Inbound vs. Outbound Peer Slot Reservation
- **Severity:** Informational
- **Classification:** Informational
- **Audit Dimensions:** F-04
- **Primary Locations:**
  - [`src/p2p/network.rs:65-77`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/network.rs#L65-L77)
  - [`src/node/config.rs:24-25`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/config.rs#L24-L25)
- **Description:**
  All 50 peer slots are shared indiscriminately. Inbound floods can consume all slots, preventing outbound connections to bootstrap peers.

---

### OBS-P2P-001: Batch Size Difference Between Header Requests (500) and Block Requests (64)
- **Severity:** N/A (Implementation Observation, formerly `SEC-P2P-008`)
- **Classification:** Implementation Observation
- **Audit Dimensions:** F-03, F-06
- **Primary Locations:**
  - [`src/node/runtime.rs:2110-2135`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/node/runtime.rs#L2110-L2135)
  - [`src/p2p/protocol.rs:103-107`](file:///c:/Users/anshp/OneDrive/ownchain-v1/src/p2p/protocol.rs#L103-L107)
- **Description:**
  In `run_sync_worker`:
  1. `GetHeaders` requests up to 500 headers (`MAX_HEADERS_PER_RESPONSE`).
  2. `GetBlocks` truncates the request to 64 block IDs (`MAX_BLOCKS_PER_RESPONSE`).
  3. The worker applies the received blocks and increments `current_h += num_blocks` (e.g. 64).
  4. On the next iteration of `while current_h <= peer_tip_height`, it requests `GetHeaders` starting at the new `current_h`.
  The height pointer remains fully synchronized across batches. This is an implementation batching inefficiency rather than a desynchronization vulnerability.
- **Implementation Status:** Fixed.
- **Hardening Details:**
  `run_sync_worker` in `src/node/runtime.rs` now synchronizes batch sizes explicitly (`SYNC_BATCH_SIZE = MAX_BLOCKS_PER_RESPONSE as u32` = 64), harmonizing header downloads and block downloads to matching 64-item chunks.

---

## 7. Areas Where No Vulnerability Was Found

1. **Cryptographic Identity Authenticity:**
   `src/p2p/identity.rs` properly generates standard Ed25519 keypairs via libp2p. Identity keys are strictly isolated from consensus wallet keys. Peer IDs cannot forge signatures or claim ownership of blockchain accounts.
2. **Maximum Frame Length Enforcement:**
   `src/p2p/framing.rs` strictly enforces `MAX_FRAME_LENGTH` (2,100,000 bytes) prior to buffer allocation.
3. **Canonical Little-Endian Integer Encoding:**
   All integer lengths, heights, and tags are serialized explicitly in little-endian byte order (`to_le_bytes` / `from_le_bytes`), preventing host-architecture endianness mismatches.
4. **Peer Registry Deduplication:**
   `PeerRegistry` reliably indexes unique peers by `PeerId`. Duplicate transport connections preserve verified handshake state and original connection timestamps.
5. **Connection Closure Lifecycle Invariants:**
   `PeerRegistry::handle_connection_closed` properly checks `num_established == 0` before removing peers, preventing premature eviction while secondary connections remain active.
6. **Cross-Network Replay Protection:**
   `HandshakeMessage::verify_compatibility` rigorously checks `chain_id` and `genesis_hash`, rejecting cross-network connections between devnet, testnet, or foreign blockchains.
7. **Bounded Orphan Block Memory:**
   `src/node/runtime.rs` strictly enforces `MAX_ORPHAN_BLOCKS` (100) and `MAX_ORPHAN_BYTES` (5MB) with FIFO eviction, preventing unbounded memory growth from orphan blocks.
8. **Memory Safety and Concurrency:**
   Rust's ownership and borrow checker guarantee that transport buffers, stream decoders, and event channels are free from buffer overflows, use-after-free, and data races.

---

## 8. Validation Status

To ensure complete empirical transparency, this audit strictly distinguishes tests actually executed from proposed regression tests and static review deductions:

### 8.1 Tests Actually Executed and Observed
- **Codebase Formatting Check:**
  - Command: `cargo fmt --all -- --check`
  - Observed Result: **Clean; exit code 0**.
- **Compiler & Clippy Static Analysis:**
  - Command: `cargo clippy --all-targets --all-features -- -D warnings`
  - Observed Result: **Clean; zero warnings; exit code 0**.
- **Complete Library Unit Test Suite:**
  - Command: `cargo test --lib`
  - Observed Result: **178 passed; 0 failed; 0 ignored** (finished cleanly in 21.68s).
  - Scope: Complete cryptographic primitives, redb storage engines, direct raw header extraction (`get_header_by_height`), consensus validation, mining difficulty, transaction signatures, mempool deduplication, P2P framing exactness, network peer registry, in-flight payload lifecycle with generation tracking and RAII `ValidationExecutionGuard`, handshake protection, wire length bounds validation, sync worker header and block validation, contiguous prefix cursor advancement with terminal-height boundary handling, budget clamping and exhaustion handling, and runtime actor state transitions.
- **Gossipsub Validation End-to-End Suite:**
  - Command: `cargo test --test gossipsub_validation_e2e`
  - Observed Result: **4 passed; 0 failed; 0 ignored** (finished in 25.57s).
  - Scope: Full integration test of libp2p Gossipsub `ValidationMode::Strict` and `validate_messages(true)`. Verifies invalid blocks and transactions are rejected and blocked from network relay, while valid blocks and transactions are accepted and propagated across mesh topologies.
- **Node Runtime End-to-End Suite:**
  - Command: `cargo test --test node_runtime_e2e`
  - Observed Result: **31 passed; 0 failed; 0 ignored** (finished in 28.23s).
  - Scope: P2P handshake exchange, incompatible chain ID rejection, multi-node gossip propagation, liar failover and reconnect survival (`test_real_p2p_sync_liar_high_work_fails_over_and_survives_reconnect`), orphan block cascades, side-branch re-evaluation, fork choice tie-breaks, competing branch synchronization, sync worker orphan rejection, sync batch failures, empty header/block rejection, mismatched block ID rejection, and overflow safety.
- **Comprehensive All-Targets Test Suite:**
  - Command: `cargo test --all-targets`
  - Observed Result: **507 passed; 0 failed; 0 ignored** across 20 compilation and test targets (finished cleanly; exit code 0).
  - Target Breakdown:
    - `unittests src/lib.rs`: 178 passed (finished in 169.77s)
    - `unittests src/main.rs`: 0 passed (finished in 0.00s)
    - `tests/auth_repair.rs`: 28 passed (finished in 26.81s)
    - `tests/cross_pool_e2e.rs`: 7 passed (finished in 116.41s)
    - `tests/cross_pool_golden.rs`: 7 passed (finished in 0.13s)
    - `tests/cross_pool_poc.rs`: 2 passed (finished in 56.25s)
    - `tests/cross_pool_stateful.rs`: 19 passed (finished in 138.02s)
    - `tests/cross_pool_stateless.rs`: 7 passed (finished in 124.11s)
    - `tests/cross_pool_type7.rs`: 23 passed (finished in 107.59s)
    - `tests/difficulty.rs`: 22 passed (finished in 0.00s)
    - `tests/fork_choice_tie_break.rs`: 4 passed (finished in 14.02s)
    - `tests/golden_vectors.rs`: 37 passed (finished in 0.03s)
    - `tests/gossipsub_validation_e2e.rs`: 4 passed (finished in 24.55s)
    - `tests/node_runtime_e2e.rs`: 31 passed (finished in 27.45s)
    - `tests/orchard_compat.rs`: 17 passed (finished in 43.92s)
    - `tests/orchard_tree_parity.rs`: 7 passed (finished in 40.40s)
    - `tests/randomx.rs`: 9 passed (finished in 4.28s)
    - `tests/reorganize_atomicity.rs`: 3 passed (finished in 13.00s)
    - `tests/stateful_hybrid.rs`: 35 passed (finished in 29.55s)
    - `tests/validation.rs`: 67 passed (finished in 40.41s)

### 8.2 Implemented Regression Test Inventory
The following regression tests have been implemented, verified, and integrated into the test suite:
- **`SEC-P2P-001` (Outbound Handshake Request Tracking & Prompt Disconnect on Timeout / Invalid Response):**
  - `src/p2p/network.rs::test_outbound_handshake_timeout_disconnects_peer_promptly`: Proves that outbound handshake request IDs are tracked in `pending_handshake_requests`, and upon request-response timeout (10s), the unresponsive peer is disconnected and evicted from the registry immediately (in ~10.04s) without waiting for the 60-second idle connection timeout.
  - `src/p2p/network.rs::test_outbound_handshake_invalid_response_disconnects_peer_promptly`: Proves that when a remote peer returns an unexpected non-handshake response (e.g. `SyncResponse::Error`) to an outbound handshake request, the node detects a protocol violation, disconnects the peer immediately, and cleans up handshake tracking without routing to sync request channels.
- **`SEC-P2P-002` (Gossipsub Validation & Lifecycle Hardening):**
  - `tests/gossipsub_validation_e2e.rs::test_gossipsub_invalid_block_rejected_and_not_propagated`: Proves unmined/invalid blocks are rejected by runtime and never relayed by Gossipsub.
  - `tests/gossipsub_validation_e2e.rs::test_gossipsub_invalid_transaction_rejected`: Proves malformed/invalid transactions are rejected and blocked from relay.
  - `tests/gossipsub_validation_e2e.rs::test_gossipsub_valid_block_accepted_and_propagated`: Proves valid blocks are accepted and forwarded to mesh peers.
  - `tests/gossipsub_validation_e2e.rs::test_gossipsub_valid_transaction_accepted`: Proves valid transactions are accepted and forwarded.
  - `src/p2p/network.rs::test_gossip_inflight_ownership_survives_token_ttl_expiry_and_rejects_duplicate`: Proves payload ownership lock outlives 8s token expiry, dropping duplicate incoming messages with `MessageAcceptance::Ignore` without restarting validation.
  - `src/p2p/network.rs::test_gossip_inflight_payload_timeout_and_legitimate_retry`: Proves ownership lock cleanly expires after 30s timeout, permitting legitimate re-validation.
  - `src/p2p/network.rs::test_gossip_inflight_late_stale_result_after_timeout_does_not_corrupt_new_generation`: Proves stale validation results from expired tokens cannot release or corrupt in-flight locks owned by newer generations.
  - `src/p2p/network.rs::test_gossip_lost_event_sweeps_ownership`: Proves that when a gossip event is dropped/lost before runtime validation starts, its `ValidationExecutionGuard` is dropped immediately, resetting `is_active = false`, and `sweep_stale_pending_gossip` reclaims the in-flight entry and sweeps stale `in_flight_by_msg_id` mappings regardless of `active_token == None`. Verifies that pending_gossip, in_flight_payloads, and in_flight_by_msg_id are all empty, a retry with a new generation succeeds, and stale results from previous generations cannot release or corrupt newer generation locks.
  - `src/p2p/network.rs::test_gossip_production_timeout_releases_guard`: Proves that when production gossip validation directly awaits `tokio::time::timeout(GOSSIP_VALIDATION_TIMEOUT, ...)` and times out, the cancelled future drops `_guard = execution_guard`, resetting `is_active = false` and enabling subsequent payload retry.
  - `src/node/runtime.rs::test_mempool_confirmed_tx_deduplicated_in_seen_cache`: Proves `AlreadyOnChain` transactions are cached as seen, while transient failures (`MempoolFull`, `Internal`) remain retryable.
- **`SEC-P2P-003` (Peer Handshake & Failover Hardening):**
  - `src/p2p/network.rs::test_handshake_rejects_repeated_unsolicited_handshake_request`: Proves `PeerRegistry::update_handshake` rejects attempts to overwrite established handshake metadata on an already-verified peer.
  - `src/p2p/network.rs::test_handshake_lifecycle_ordering_a_outbound_response_first`: Proves that when an outbound handshake response arrives before the peer's initial inbound handshake request, the inbound request is accepted with `SyncResponse::Handshake`, the peer is not disconnected, and established handshake metadata is not overwritten.
  - `src/p2p/network.rs::test_handshake_lifecycle_ordering_b_inbound_request_first`: Proves that when the peer's initial inbound handshake request arrives before our outbound handshake response, the peer remains handshaked and connected, and duplicate response processing does not corrupt metadata.
  - `src/p2p/network.rs::test_handshake_lifecycle_rejects_repeated_unsolicited_inbound_request`: Proves that after initial handshake completion, any subsequent unsolicited inbound handshake request with altered tip metadata is rejected with `SyncResponse::Error("handshake already established")` while established metadata remains unchanged.
  - `src/node/runtime.rs::test_sync_already_synchronized_verified_local_storage_match`: Proves peer claiming current tip returns `AlreadySynchronized` after verifying local tip in storage.
  - `src/node/runtime.rs::test_verified_already_synchronized_full_lifecycle`: Proves the full end-to-end already-synchronized lifecycle with verified manual sync preconditions (unconnected peer, unhandshaked peer, incompatible chain ID, and incompatible genesis hash are all rejected), verified local storage and advertised claim match, exercising `run_sync_worker`, `handle_sync_task_success`, and manual completion notifier receiving `Ok(())` with zero new persisted blocks and zero peer penalty.
  - `src/node/runtime.rs::test_already_synchronized_side_branch_claim_rejected_and_penalized`: Proves that a peer advertising a lower-height block from an off-canonical side branch cannot achieve `AlreadySynchronized` or manual `Ok(())` (it is penalized with `FalseAdvertisedWorkClaim`), that an inconsistent header response at claimed tip height is rejected by `run_sync_worker` with `FalseAdvertisedClaim`, and that legitimate canonical-chain claims succeed with manual `Ok(())`.
  - `src/node/runtime.rs::test_select_sync_peer_penalizes_repeat_offender`: Proves failing sync peers are placed on exponential backoff and alternate peers are selected.
  - `src/node/runtime.rs::test_manual_sync_reconciles_caller_height_mismatch_with_authenticated_handshake`: Proves caller-supplied manual sync height differing from authenticated handshake advertised claim is authoritatively reconciled to `advertised_claim.tip_height`, preventing premature completion, incorrect synchronization, and peer penalty.
  - `src/node/runtime.rs::test_manual_sync_genesis_only_peer_valid`: Proves peer advertising height 0 and valid canonical genesis block ID against a longer local chain G -> A1 -> A2 succeeds as verified `AlreadySynchronized` with caller receiving `Ok(())` and zero peer penalty.
  - `src/node/runtime.rs::test_manual_sync_genesis_only_peer_invalid`: Proves peer advertising height 0 with a non-canonical genesis tip block ID is rejected with `SyncWorkerError::FalseAdvertisedClaim`, caller receives error, peer is penalized with `FalseAdvertisedWorkClaim`, and no false no-op success occurs.
  - `tests/node_runtime_e2e.rs::test_real_p2p_sync_liar_high_work_fails_over_and_survives_reconnect`: Proves malicious peer advertising `U256::MAX` work fails, is cooled down with `TransientOrTimeout`, fails over to an honest peer with valid blocks, completes sync, and reconnecting liar cannot disrupt sync.
- **`SEC-P2P-004` (Elimination of False Sync Success, Response Validation & Cursor Semantics):**
  - `src/node/runtime.rs::test_sync_batch_orphan_rejected_never_enters_orphan_pool_and_fails_batch`: Proves disconnected orphan blocks fail the batch immediately with `SyncBatchError::DisconnectedOrphan`, never enter `orphan_blocks`, never trigger missing-parent recovery, and stop cursor advancement.
  - `src/node/runtime.rs::test_sync_notifier_never_receives_success_on_incomplete_or_penalized_outcome`: Proves manual sync notifier receives an error rather than `Ok(())` on incomplete progress or peer failure.
  - `src/node/runtime.rs::test_handle_sync_request_get_blocks_breaks_on_missing_block`: Proves `GetBlocks` terminates immediately on missing block to preserve contiguous prefix semantics.
  - `src/node/runtime.rs::test_sync_worker_fast_path_empty_headers_returns_incomplete`: Proves fast-path empty headers return `Incomplete` error.
  - `src/node/runtime.rs::test_sync_worker_fast_path_multiple_headers_returns_consensus_invalid`: Proves fast-path multiple headers return `ConsensusInvalid`.
  - `src/node/runtime.rs::test_sync_worker_fast_path_wrong_height_returns_consensus_invalid`: Proves fast-path header with mismatched height returns `ConsensusInvalid`.
  - `src/node/runtime.rs::test_sync_worker_fast_path_wrong_chain_id_returns_consensus_invalid`: Proves fast-path header with mismatched chain ID returns `ConsensusInvalid`.
  - `src/node/runtime.rs::test_sync_worker_transport_failure_does_not_trigger_fallback`: Proves transport errors on fast path return `TransientOrProtocol` immediately without triggering fallback to binary search.
  - `src/node/runtime.rs::test_sync_worker_binary_search_malformed_response_returns_consensus_invalid`: Proves malformed binary search header query returns `ConsensusInvalid`.
  - `src/node/runtime.rs::test_sync_worker_rejects_wrong_first_header_height`: Proves batch header query returning wrong first height is rejected with `ConsensusInvalid`.
  - `src/node/runtime.rs::test_sync_worker_rejects_incorrect_chain_id`: Proves batch header with invalid chain ID is rejected with `ConsensusInvalid`.
  - `src/node/runtime.rs::test_sync_worker_rejects_broken_parent_linkage`: Proves batch headers with broken parent chain are rejected with `ConsensusInvalid`.
  - `src/node/runtime.rs::test_sync_worker_rejects_response_count_exceeding_request`: Proves header response exceeding requested count is rejected with `ConsensusInvalid`.
  - `src/node/runtime.rs::test_sync_worker_rejects_reordered_headers`: Proves reordered headers in batch response are rejected with `ConsensusInvalid`.
  - `src/node/runtime.rs::test_sync_worker_rejects_block_response_exceeding_requested_count`: Proves block response count exceeding requested headers is rejected with `ConsensusInvalid`.
  - `src/node/runtime.rs::test_sync_worker_rejects_reordered_block_bodies`: Proves block bodies returned out of order are rejected with `ConsensusInvalid`.
  - `src/node/runtime.rs::test_sync_worker_rejects_unrequested_block_body`: Proves unrequested block body is rejected with `ConsensusInvalid`.
  - `src/node/runtime.rs::test_sync_worker_rejects_missing_middle_block`: Proves skipped/missing middle block in body response is rejected with `ConsensusInvalid`.
  - `src/node/runtime.rs::test_sync_worker_rejects_body_with_mismatching_header`: Proves block body whose header does not match validated header is rejected with `ConsensusInvalid`.
  - `src/node/runtime.rs::test_sync_worker_accepts_short_contiguous_prefix_and_advances_cursor`: Proves short block response is accepted strictly as a valid contiguous prefix, advances cursor by `receipt.blocks_processed`, and continues sync.
  - `src/node/runtime.rs::test_sync_terminal_height_short_prefix_and_manual_completion`: Proves that when synchronizing to `peer_tip = u64::MAX`, a short block prefix ending at `u64::MAX - 1` advances cursor to `u64::MAX` without premature loop break, requests and processes block `u64::MAX`, and reaches `VerifiedSuccess` only after the true terminal block is processed.
  - `src/node/runtime.rs::test_sync_budget_clamping_and_duplicate_exhaustion`: Proves that sync request counts are clamped to `MAX_SYNC_BLOCKS.saturating_sub(total_bodies_processed)`, duplicate bodies increment `total_bodies_processed`, and exceeding `MAX_SYNC_BLOCKS` (5000) terminates with `SyncWorkerError::BudgetExhausted` without false success.
  - `src/node/runtime.rs::test_sync_budget_exhaustion_never_produces_success`: Proves work-budget exhaustion (round trips or timeout) is penalized and never reports success.
  - `src/node/runtime.rs::test_sync_worker_absolute_deadline_enforcement_on_stalled_request`: Proves that an unresponsive network request during sync aborts when the overall absolute operation deadline is reached with `SyncWorkerError::BudgetExhausted`.
  - `src/node/runtime.rs::test_sync_worker_absolute_deadline_enforcement_on_stalled_batch_ack`: Proves that an unacknowledged block batch channel send or ack response aborts when the absolute deadline expires with `SyncWorkerError::BudgetExhausted`.
  - `src/node/runtime.rs::test_late_batch_ack_at_deadline_does_not_persist_or_penalize_peer`: Proves that when the absolute sync deadline expires awaiting local batch acknowledgement, the worker sets `cancel_flag = true`, runtime drops the late batch without persisting blocks, the outcome evaluates to `LocalFaultNoPeerPenalty`, and the peer is not penalized for local delay.
  - `tests/node_runtime_e2e.rs::test_sync_worker_orphan_rejected_fails_gracefully`: Proves end-to-end sync fails when peer delivers orphan block.
  - `tests/node_runtime_e2e.rs::test_sync_worker_empty_blocks_fails`: Proves sync fails if peer returns empty block response.
  - `tests/node_runtime_e2e.rs::test_sync_worker_empty_headers_fails`: Proves sync fails if peer returns empty header response before tip.
  - `tests/node_runtime_e2e.rs::test_sync_worker_mismatched_block_ids_fails`: Proves sync fails if block IDs do not match header hashes.
- **`SEC-P2P-005` (Arithmetic Overflow Safety):**
  - `tests/node_runtime_e2e.rs::test_sync_request_get_headers_overflow_safety`: Proves `GetHeaders` with `u64::MAX` does not panic and returns empty headers.
- **`SEC-P2P-009` (Strict Wire Length Bounds & Elimination of Malleable Clamping):**
  - `src/p2p/protocol.rs::test_reject_oversized_counts_and_malleable_clamping`: Proves counts exceeding protocol maximums return `io::ErrorKind::InvalidData`.
  - `src/p2p/protocol.rs::test_truncated_wire_messages`: Proves truncated wire messages return unexpected EOF errors.
- **`SEC-P2P-010` (Direct Raw Header Extraction in Storage):**
  - `src/storage/mod.rs::test_capture_canonical_chain_snapshot`: Proves `get_header_by_height` extracts the 170-byte header directly from raw block bytes without full block/transaction deserialization.
- **`SEC-P2P-014` (Exact Framing & Trailing Garbage Rejection):**
  - `src/p2p/framing.rs::test_decode_frame_slice_exact_rejects_trailing_bytes`: Proves valid message with trailing bytes fails decoding with `FramingError::TrailingBytes`.

### 8.3 Remaining Open / Backlog Items
The following items remain open for subsequent milestones:
- `SEC-P2P-011`: Gossipsub pre-validation orphan check in `process_single_block` and multi-peer recovery fanout (Milestone 4).
- `SEC-P2P-012`: Transport-level concurrent connection limits per peer/IP.
- `SEC-P2P-013`: Kademlia DHT address filtering for self-advertised listen addresses.
- `SEC-P2P-015`: Streaming payload allocation bounds in `SyncCodec`.
- `SEC-P2P-016`: Strict printable character validation in handshake/error strings.
- `SEC-P2P-018`: Restrictive file permissions (`0600`) for node identity keyfile on Unix.
- `SEC-P2P-019`: Gossipsub peer scoring and IP rate-limiting/banning infrastructure.
- `SEC-P2P-020`: Inbound vs. outbound peer slot reservations.

---

## 9. Remediation Roadmap & Backlog Reconciliation

*Note on Status:* The roadmap below documents the historical remediation phases formulated during the initial audit along with their current verified delivery status.

### Phase 1: High-Priority PR3 Security Hardening (**DELIVERED & VERIFIED**)
1. **Reject Orphan Blocks During Chain Sync (`SEC-P2P-004`):** **FIXED**
   `ApplyBlockBatch` immediately returns `SyncBatchError::DisconnectedOrphan` when an incoming block during sync has a missing parent, completely isolating synchronization from the orphan pool.
2. **Sync Worker Peer Cooldown on Failure (`SEC-P2P-003`):** **FIXED**
   Peer sync failure cooldown tracking with exponential backoff; unsolicited repeated handshakes rejected with error response.
3. **Gossipsub Validation Lifecycle (`SEC-P2P-002`):** **FIXED**
   `validate_messages(true)` enabled, `ValidationMode::Strict` configured, generation-tracked in-flight locks with RAII `ValidationExecutionGuard` integrated into runtime validation timeout future, and explicit application reporting of message validation results.
4. **Saturating Arithmetic in `GetHeaders` (`SEC-P2P-005`):** **FIXED**
   Replaced `start_height + count as u64` with `start_height.saturating_add(...)`.
5. **Immediate Outbound Handshake Disconnect on Timeout (`SEC-P2P-001`):** **FIXED**
   Outbound handshake request IDs tracked and disconnected immediately on timeout.

### Phase 2: Gossip, Framing & Transport Robustness (**DELIVERED & VERIFIED**)
6. **Eliminate Transaction Gossip Rebroadcast Loop (`SEC-P2P-007`):** **FIXED**
   Transactions received from Gossipsub are admitted to mempool without re-publishing to Gossipsub.
7. **Strict Bounds Validation on Length Counts (`SEC-P2P-009`):** **FIXED**
   Replaced malleable `.min(...)` clamping with strict bound checks returning `InvalidData`.
8. **Non-Blocking Actor Event Dispatch (`SEC-P2P-006`):** **MITIGATED**
   Network actor uses `try_send` for bulk gossip events to mitigate dual-channel deadlocks.
9. **Gossip Trailing Bytes Verification (`SEC-P2P-014`):** **FIXED**
   `decode_frame_slice` rejects non-canonical frames with trailing bytes.

### Phase 3: Partial Hardening & Open Backlog
10. **Direct Raw Header Extraction in Storage (`SEC-P2P-010`):** **PARTIALLY FIXED**
    `get_header_by_height` extracts the 170-byte header directly from raw block bytes without full block/transaction deserialization. Dedicated header index table deferred.
11. **Validate Proof of Work Before Orphan Admission & Restrict Missing-Parent Query Fanout (`SEC-P2P-011`):** **OPEN / BACKLOG (Milestone 4)**
    Pre-validation PoW check for normal Gossipsub orphan admission in `process_single_block` and single-peer parent recovery fanout. Note: during sync, `SEC-P2P-004` already eliminates orphan admission entirely.
12. **Transport-Level Connection Limits Per IP (`SEC-P2P-012`):** **OPEN / BACKLOG**
    Cap simultaneous transport connections from identical IP addresses.
13. **Sanitize Kademlia Listen Addresses (`SEC-P2P-013`):** **OPEN / BACKLOG**
    Drop loopback/private addresses from `Identify`.
14. **Streaming Payload Allocation Bounds in `SyncCodec` (`SEC-P2P-015`):** **OPEN / BACKLOG**
    Defer buffer allocation until header size is validated.
15. **Strict Printable Character Validation in Handshake (`SEC-P2P-016`):** **OPEN / BACKLOG**
    Reject non-UTF-8 or non-printable ASCII characters in protocol handshake fields.
16. **Harden Identity Key File Permissions (`SEC-P2P-018`):** **OPEN / BACKLOG**
    Set restrictive `0600` permissions on Unix.
17. **Peer Scoring & Banning Infrastructure (`SEC-P2P-019`):** **OPEN / BACKLOG**
    Comprehensive libp2p peer scoring parameters and persistent peer banning.
18. **Inbound vs. Outbound Peer Slot Reservation (`SEC-P2P-020`):** **OPEN / BACKLOG**
    Reserve distinct connection slots for outbound dials vs. inbound connections.
