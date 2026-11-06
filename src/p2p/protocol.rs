//! Request/Response blockchain synchronization protocol messages and codec.
//!
//! Defined in `docs/protocol-v1.md` §8 and M1-I specification:
//! Bounded request/response protocol for headers, blocks, and status.

use std::io;

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use libp2p::StreamProtocol;

use crate::block::Block;
use crate::difficulty::U256;
use crate::hash::Hash;
use crate::header::{Header, HEADER_LEN};
use crate::p2p::framing::{encode_frame, MAX_FRAME_LENGTH};
use crate::p2p::handshake::HandshakeMessage;

/// Protocol identifier for the synchronization request/response subprotocol.
pub const SYNC_PROTOCOL_ID: &str = "/ownchain/sync/1";

/// Maximum number of headers returned in a single response.
pub const MAX_HEADERS_PER_RESPONSE: usize = 500;

/// Maximum number of blocks requested or returned in a single batch.
pub const MAX_BLOCKS_PER_RESPONSE: usize = 64;

/// Request messages sent across the synchronization protocol.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SyncRequest {
    /// Initial application handshake sent on peer connection.
    Handshake(HandshakeMessage),
    /// Requests the peer's current active chain tip status.
    GetStatus,
    /// Requests a range of block headers starting at `start_height`, up to `max_count`.
    GetHeaders { start_height: u64, max_count: u32 },
    /// Requests a batch of specific blocks by block ID.
    GetBlocks { block_ids: Vec<Hash> },
    /// Requests a block at a specific canonical height.
    GetBlockByHeight { height: u64 },
    /// Requests the parent block of a known block ID (missing-parent recovery).
    GetMissingParent { child_block_id: Hash },
}

/// Response messages received across the synchronization protocol.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SyncResponse {
    /// Handshake response returning local node handshake information.
    Handshake(HandshakeMessage),
    /// Local chain status response.
    Status {
        tip_height: u64,
        tip_block_id: Hash,
        cumulative_work: U256,
    },
    /// Range of block headers.
    Headers(Vec<Header>),
    /// Batch of full canonical blocks.
    Blocks(Vec<Block>),
    /// Requested block or header was not found.
    NotFound,
    /// Protocol or request error.
    Error(String),
}

// Wire message tags
const TAG_REQ_HANDSHAKE: u8 = 0;
const TAG_REQ_GET_STATUS: u8 = 1;
const TAG_REQ_GET_HEADERS: u8 = 2;
const TAG_REQ_GET_BLOCKS: u8 = 3;
const TAG_REQ_GET_BLOCK_BY_HEIGHT: u8 = 4;
const TAG_REQ_GET_MISSING_PARENT: u8 = 5;

const TAG_RESP_HANDSHAKE: u8 = 9;
const TAG_RESP_STATUS: u8 = 10;
const TAG_RESP_HEADERS: u8 = 11;
const TAG_RESP_BLOCKS: u8 = 12;
const TAG_RESP_NOT_FOUND: u8 = 13;
const TAG_RESP_ERROR: u8 = 14;

impl SyncRequest {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            SyncRequest::Handshake(msg) => {
                out.push(TAG_REQ_HANDSHAKE);
                out.extend_from_slice(&msg.to_bytes());
            }
            SyncRequest::GetStatus => {
                out.push(TAG_REQ_GET_STATUS);
            }
            SyncRequest::GetHeaders {
                start_height,
                max_count,
            } => {
                out.push(TAG_REQ_GET_HEADERS);
                out.extend_from_slice(&start_height.to_le_bytes());
                out.extend_from_slice(&max_count.to_le_bytes());
            }
            SyncRequest::GetBlocks { block_ids } => {
                out.push(TAG_REQ_GET_BLOCKS);
                let count = block_ids.len().min(MAX_BLOCKS_PER_RESPONSE) as u32;
                out.extend_from_slice(&count.to_le_bytes());
                for id in block_ids.iter().take(count as usize) {
                    out.extend_from_slice(id.as_bytes());
                }
            }
            SyncRequest::GetBlockByHeight { height } => {
                out.push(TAG_REQ_GET_BLOCK_BY_HEIGHT);
                out.extend_from_slice(&height.to_le_bytes());
            }
            SyncRequest::GetMissingParent { child_block_id } => {
                out.push(TAG_REQ_GET_MISSING_PARENT);
                out.extend_from_slice(child_block_id.as_bytes());
            }
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "empty request",
            ));
        }

        match bytes[0] {
            TAG_REQ_HANDSHAKE => {
                let msg = HandshakeMessage::from_bytes(&bytes[1..])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                Ok(SyncRequest::Handshake(msg))
            }
            TAG_REQ_GET_STATUS => {
                if bytes.len() != 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing bytes in GetStatus",
                    ));
                }
                Ok(SyncRequest::GetStatus)
            }
            TAG_REQ_GET_HEADERS => {
                if bytes.len() != 1 + 8 + 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid GetHeaders message length",
                    ));
                }
                let start_height = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
                let max_count = u32::from_le_bytes(bytes[9..13].try_into().unwrap());
                Ok(SyncRequest::GetHeaders {
                    start_height,
                    max_count: max_count.min(MAX_HEADERS_PER_RESPONSE as u32),
                })
            }
            TAG_REQ_GET_BLOCKS => {
                if bytes.len() < 5 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated GetBlocks count",
                    ));
                }
                let count = u32::from_le_bytes(bytes[1..5].try_into().unwrap()) as usize;
                let count = count.min(MAX_BLOCKS_PER_RESPONSE);
                let expected = 5 + count * 32;
                if bytes.len() != expected {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid GetBlocks message length",
                    ));
                }
                let mut ids = Vec::with_capacity(count);
                for i in 0..count {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&bytes[5 + i * 32..5 + (i + 1) * 32]);
                    ids.push(Hash::new(id));
                }
                Ok(SyncRequest::GetBlocks { block_ids: ids })
            }
            TAG_REQ_GET_BLOCK_BY_HEIGHT => {
                if bytes.len() != 9 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid GetBlockByHeight length",
                    ));
                }
                let height = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
                Ok(SyncRequest::GetBlockByHeight { height })
            }
            TAG_REQ_GET_MISSING_PARENT => {
                if bytes.len() != 33 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid GetMissingParent length",
                    ));
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes[1..33]);
                Ok(SyncRequest::GetMissingParent {
                    child_block_id: Hash::new(id),
                })
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown sync request tag: {other}"),
            )),
        }
    }
}

impl SyncResponse {
    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            SyncResponse::Handshake(msg) => {
                out.push(TAG_RESP_HANDSHAKE);
                out.extend_from_slice(&msg.to_bytes());
            }
            SyncResponse::Status {
                tip_height,
                tip_block_id,
                cumulative_work,
            } => {
                out.push(TAG_RESP_STATUS);
                out.extend_from_slice(&tip_height.to_le_bytes());
                out.extend_from_slice(tip_block_id.as_bytes());
                out.extend_from_slice(&cumulative_work.to_le_bytes());
            }
            SyncResponse::Headers(headers) => {
                out.push(TAG_RESP_HEADERS);
                let count = headers.len().min(MAX_HEADERS_PER_RESPONSE) as u32;
                out.extend_from_slice(&count.to_le_bytes());
                for h in headers.iter().take(count as usize) {
                    out.extend_from_slice(&h.to_bytes());
                }
            }
            SyncResponse::Blocks(blocks) => {
                out.push(TAG_RESP_BLOCKS);
                let mut serialized_blocks = Vec::new();
                let mut total_size = 5; // 1 byte tag + 4 bytes count
                for b in blocks.iter().take(MAX_BLOCKS_PER_RESPONSE) {
                    let b_bytes = b
                        .to_bytes()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    let entry_len = 4 + b_bytes.len();
                    if total_size + entry_len > MAX_FRAME_LENGTH {
                        if serialized_blocks.is_empty() {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "single block size {entry_len} exceeds max frame length {MAX_FRAME_LENGTH}"
                                ),
                            ));
                        }
                        break;
                    }
                    total_size += entry_len;
                    serialized_blocks.push(b_bytes);
                }
                let count = serialized_blocks.len() as u32;
                out.extend_from_slice(&count.to_le_bytes());
                for b_bytes in serialized_blocks {
                    let b_len = b_bytes.len() as u32;
                    out.extend_from_slice(&b_len.to_le_bytes());
                    out.extend_from_slice(&b_bytes);
                }
            }
            SyncResponse::NotFound => {
                out.push(TAG_RESP_NOT_FOUND);
            }
            SyncResponse::Error(msg) => {
                out.push(TAG_RESP_ERROR);
                let m_bytes = msg.as_bytes();
                let m_len = m_bytes.len().min(512) as u16;
                out.extend_from_slice(&m_len.to_le_bytes());
                out.extend_from_slice(&m_bytes[..m_len as usize]);
            }
        }
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "empty response",
            ));
        }

        match bytes[0] {
            TAG_RESP_HANDSHAKE => {
                let msg = HandshakeMessage::from_bytes(&bytes[1..])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                Ok(SyncResponse::Handshake(msg))
            }
            TAG_RESP_STATUS => {
                if bytes.len() != 1 + 8 + 32 + 32 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid status response length",
                    ));
                }
                let tip_height = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes[9..41]);
                let mut work_bytes = [0u8; 32];
                work_bytes.copy_from_slice(&bytes[41..73]);
                Ok(SyncResponse::Status {
                    tip_height,
                    tip_block_id: Hash::new(id),
                    cumulative_work: U256::from_le_bytes(work_bytes),
                })
            }
            TAG_RESP_HEADERS => {
                if bytes.len() < 5 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated headers count",
                    ));
                }
                let count = u32::from_le_bytes(bytes[1..5].try_into().unwrap()) as usize;
                let count = count.min(MAX_HEADERS_PER_RESPONSE);
                let expected = 5 + count * HEADER_LEN;
                if bytes.len() != expected {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid headers response length",
                    ));
                }
                let mut headers = Vec::with_capacity(count);
                for i in 0..count {
                    let start = 5 + i * HEADER_LEN;
                    let h = Header::from_bytes(&bytes[start..start + HEADER_LEN])
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    headers.push(h);
                }
                Ok(SyncResponse::Headers(headers))
            }
            TAG_RESP_BLOCKS => {
                if bytes.len() < 5 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated blocks count",
                    ));
                }
                let count = u32::from_le_bytes(bytes[1..5].try_into().unwrap()) as usize;
                let count = count.min(MAX_BLOCKS_PER_RESPONSE);
                let mut o = 5;
                let mut blocks = Vec::with_capacity(count);
                for _ in 0..count {
                    if bytes.len() < o + 4 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated block length",
                        ));
                    }
                    let b_len = u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap()) as usize;
                    o += 4;
                    if bytes.len() < o + b_len {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated block payload",
                        ));
                    }
                    let block = Block::from_bytes(&bytes[o..o + b_len])
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    blocks.push(block);
                    o += b_len;
                }
                if o != bytes.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing bytes in blocks response",
                    ));
                }
                Ok(SyncResponse::Blocks(blocks))
            }
            TAG_RESP_NOT_FOUND => {
                if bytes.len() != 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing bytes in not found response",
                    ));
                }
                Ok(SyncResponse::NotFound)
            }
            TAG_RESP_ERROR => {
                if bytes.len() < 3 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated error length",
                    ));
                }
                let m_len = u16::from_le_bytes(bytes[1..3].try_into().unwrap()) as usize;
                if bytes.len() != 3 + m_len {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid error message response length",
                    ));
                }
                let msg = String::from_utf8_lossy(&bytes[3..3 + m_len]).to_string();
                Ok(SyncResponse::Error(msg))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown sync response tag: {other}"),
            )),
        }
    }
}

/// Libp2p RequestResponse Codec for OwnChain sync protocol.
#[derive(Clone, Default)]
pub struct SyncCodec;

#[async_trait]
impl Codec for SyncCodec {
    type Protocol = StreamProtocol;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut prefix = [0u8; 4];
        io.read_exact(&mut prefix).await?;
        let len = u32::from_le_bytes(prefix) as usize;
        if len > MAX_FRAME_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame length {len} exceeds {MAX_FRAME_LENGTH}"),
            ));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        SyncRequest::from_bytes(&buf)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut prefix = [0u8; 4];
        io.read_exact(&mut prefix).await?;
        let len = u32::from_le_bytes(prefix) as usize;
        if len > MAX_FRAME_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame length {len} exceeds {MAX_FRAME_LENGTH}"),
            ));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        SyncResponse::from_bytes(&buf)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let payload = req.to_bytes();
        let framed = encode_frame(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        io.write_all(&framed).await?;
        io.flush().await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let payload = resp.to_bytes()?;
        let framed = encode_frame(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        io.write_all(&framed).await?;
        io.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_request_round_trip() {
        let req1 = SyncRequest::GetStatus;
        let bytes1 = req1.to_bytes();
        assert_eq!(SyncRequest::from_bytes(&bytes1).unwrap(), req1);

        let req2 = SyncRequest::GetHeaders {
            start_height: 100,
            max_count: 50,
        };
        let bytes2 = req2.to_bytes();
        assert_eq!(SyncRequest::from_bytes(&bytes2).unwrap(), req2);

        let req3 = SyncRequest::GetBlocks {
            block_ids: vec![Hash::new([1u8; 32]), Hash::new([2u8; 32])],
        };
        let bytes3 = req3.to_bytes();
        assert_eq!(SyncRequest::from_bytes(&bytes3).unwrap(), req3);

        let req4 = SyncRequest::GetBlockByHeight { height: 12345 };
        let bytes4 = req4.to_bytes();
        assert_eq!(SyncRequest::from_bytes(&bytes4).unwrap(), req4);

        let req5 = SyncRequest::GetMissingParent {
            child_block_id: Hash::new([9u8; 32]),
        };
        let bytes5 = req5.to_bytes();
        assert_eq!(SyncRequest::from_bytes(&bytes5).unwrap(), req5);
    }

    #[test]
    fn test_sync_response_round_trip() {
        let resp1 = SyncResponse::Status {
            tip_height: 42,
            tip_block_id: Hash::new([7u8; 32]),
            cumulative_work: U256::from_u128(999),
        };
        let bytes1 = resp1.to_bytes().unwrap();
        assert_eq!(SyncResponse::from_bytes(&bytes1).unwrap(), resp1);

        let resp2 = SyncResponse::NotFound;
        let bytes2 = resp2.to_bytes().unwrap();
        assert_eq!(SyncResponse::from_bytes(&bytes2).unwrap(), resp2);

        let resp3 = SyncResponse::Error("test error".into());
        let bytes3 = resp3.to_bytes().unwrap();
        assert_eq!(SyncResponse::from_bytes(&bytes3).unwrap(), resp3);
    }

    #[test]
    fn test_reject_trailing_bytes_on_requests_and_responses() {
        // Trailing bytes on GetStatus
        let mut bad_status_req = SyncRequest::GetStatus.to_bytes();
        bad_status_req.push(0xff);
        assert!(SyncRequest::from_bytes(&bad_status_req).is_err());

        // Trailing bytes on GetHeaders
        let mut bad_headers_req = SyncRequest::GetHeaders {
            start_height: 1,
            max_count: 10,
        }
        .to_bytes();
        bad_headers_req.push(0x00);
        assert!(SyncRequest::from_bytes(&bad_headers_req).is_err());

        // Trailing bytes on NotFound
        let mut bad_not_found = SyncResponse::NotFound.to_bytes().unwrap();
        bad_not_found.push(0x01);
        assert!(SyncResponse::from_bytes(&bad_not_found).is_err());

        // Trailing bytes on Status response
        let mut bad_status_resp = SyncResponse::Status {
            tip_height: 1,
            tip_block_id: Hash::ZERO,
            cumulative_work: U256::zero(),
        }
        .to_bytes()
        .unwrap();
        bad_status_resp.push(0x00);
        assert!(SyncResponse::from_bytes(&bad_status_resp).is_err());
    }

    #[test]
    fn test_byte_aware_block_batching() {
        use crate::genesis::genesis_block;
        use crate::hash::chain_id;

        let cid = chain_id("devnet");
        let gen = genesis_block(cid);

        // A response with many blocks must not exceed MAX_FRAME_LENGTH
        let many_blocks = vec![gen; 100];
        let resp = SyncResponse::Blocks(many_blocks);
        let bytes = resp.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_FRAME_LENGTH);

        let decoded = SyncResponse::from_bytes(&bytes).unwrap();
        if let SyncResponse::Blocks(b_list) = decoded {
            assert!(!b_list.is_empty());
            assert!(b_list.len() <= MAX_BLOCKS_PER_RESPONSE);
        } else {
            panic!("expected SyncResponse::Blocks");
        }
    }
}
