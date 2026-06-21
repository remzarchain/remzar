// src/network/p2p_006_reqresp.rs

use crate::network::p2p_003_behaviour::OutEvent;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::{
    blockchain::{block_002_blocks::Block, mempool::MemPool, transaction_001_tx::Transaction},
    storage::rocksdb_005_manager::RockDBManager,
};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{
    PeerId,
    request_response::{
        Behaviour, Codec, Config, Event, Message, OutboundRequestId, ProtocolSupport,
    },
    swarm::SwarmEvent,
};
use postcard::{take_from_bytes, to_stdvec};
use std::{convert::TryFrom, iter, time::Duration};

/* ─── helper types ─────────────────────────────────────────────── */
pub type Hash = [u8; 64];

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum BlockTxRequest {
    GetBlock {
        #[serde(with = "crate::utility::helper::serde_u8_array_64")]
        hash: Hash,
    },
    GetTx {
        #[serde(with = "crate::utility::helper::serde_u8_array_64")]
        hash: Hash,
    },
    GetBlockByIndex {
        index: u64,
    },
    GetBatchByIndex {
        index: u64,
    },
    GetBatchByHash {
        #[serde(with = "crate::utility::helper::serde_u8_array_64")]
        hash: Hash,
    },
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum BlockTxResponse {
    BlockData(Box<Block>),
    BatchData(Vec<u8>),
    TxData(Box<Transaction>),
    NotFound,
}

/* ─── defensive wire caps (no crypto impact) ───────────────────── */

/// Maximum allowed request/response payload size (bytes) for this protocol.
const BLOCKTX_MAX_WIRE_BYTES: usize = 2 * 1024 * 1024;

#[inline(always)]
fn consensus_max_bytes() -> usize {
    usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).unwrap_or(usize::MAX)
}

#[inline(always)]
fn ensure_within_consensus_cap(label: &str, n: usize) -> std::io::Result<()> {
    let cap = consensus_max_bytes();
    if n > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{label} exceeds MAX_BLOCK_SIZE: {n} bytes (cap {cap})"),
        ));
    }
    Ok(())
}

/* ─── libp2p codec ─────────────────────────────────────────────── */

#[derive(Clone, Debug, Default)]
pub struct BlockTxProtocol;

impl AsRef<str> for BlockTxProtocol {
    fn as_ref(&self) -> &str {
        "/remzar/blocktx/1.0.0"
    }
}

#[derive(Clone, Default)]
pub struct BlockTxCodec;

impl Codec for BlockTxCodec {
    type Protocol = BlockTxProtocol;
    type Request = BlockTxRequest;
    type Response = BlockTxResponse;

    /* --- read --- */

    fn read_request<'a, 'b, 'c, 'd, R>(
        &'a mut self,
        _p: &'b Self::Protocol,
        io: &'c mut R,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = std::io::Result<Self::Request>> + Send + 'd>>
    where
        R: AsyncRead + Unpin + Send + 'd,
        'a: 'd,
        'b: 'd,
        'c: 'd,
    {
        boxed_read(io)
    }

    fn read_response<'a, 'b, 'c, 'd, R>(
        &'a mut self,
        _p: &'b Self::Protocol,
        io: &'c mut R,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = std::io::Result<Self::Response>> + Send + 'd>>
    where
        R: AsyncRead + Unpin + Send + 'd,
        'a: 'd,
        'b: 'd,
        'c: 'd,
    {
        boxed_read(io)
    }

    /* --- write --- */

    fn write_request<'a, 'b, 'c, 'd, W>(
        &'a mut self,
        _p: &'b Self::Protocol,
        io: &'c mut W,
        req: Self::Request,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = std::io::Result<()>> + Send + 'd>>
    where
        W: AsyncWrite + Unpin + Send + 'd,
        'a: 'd,
        'b: 'd,
        'c: 'd,
    {
        boxed_write(io, req)
    }

    fn write_response<'a, 'b, 'c, 'd, W>(
        &'a mut self,
        _p: &'b Self::Protocol,
        io: &'c mut W,
        rsp: Self::Response,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = std::io::Result<()>> + Send + 'd>>
    where
        W: AsyncWrite + Unpin + Send + 'd,
        'a: 'd,
        'b: 'd,
        'c: 'd,
    {
        boxed_write(io, rsp)
    }
}

/* ─── Behaviour builder ───────────────────────────────────────── */

pub type BlockTxExchange = Behaviour<BlockTxCodec>;

pub fn build_blocktx_exchange() -> BlockTxExchange {
    let cfg = Config::default().with_request_timeout(Duration::from_secs(8));
    Behaviour::with_codec(
        BlockTxCodec,
        iter::once((BlockTxProtocol, ProtocolSupport::Full)),
        cfg,
    )
}

/* ─── Event handler ───────────────────────────────────────────── */

pub fn handle_blocktx_event(
    rr: &mut BlockTxExchange,
    event: Event<BlockTxRequest, BlockTxResponse>,
    storage: &RockDBManager,
    mempool: &MemPool,
) {
    _ = handle_blocktx_event_checked(rr, event, storage, mempool);
}

/// Checked variant: same logic, but returns `std::io::Result<()>`-style errors
pub fn handle_blocktx_event_checked(
    rr: &mut BlockTxExchange,
    event: Event<BlockTxRequest, BlockTxResponse>,
    storage: &RockDBManager,
    mempool: &MemPool,
) -> std::io::Result<()> {
    tracing::debug!(
        "[BLOCKTX] handle_blocktx_event called. Incoming event: {:?}",
        event
    );

    if let Event::Message {
        message: Message::Request {
            request, channel, ..
        },
        ..
    } = event
    {
        tracing::debug!(
            "[BLOCKTX] Received Request: {:?} on channel {:?}",
            request,
            channel
        );

        let resp = match request {
            BlockTxRequest::GetBlock { hash } => {
                tracing::debug!("[BLOCKTX] BlockTxRequest::GetBlock for hash {:?}", hash);
                match storage.get_block_by_hash(&hash) {
                    Some(ref b) => {
                        if let Ok(bytes) = b.serialize_for_storage() {
                            if let Err(e) = ensure_within_consensus_cap(
                                "serve BlockData (canonical)",
                                bytes.len(),
                            ) {
                                tracing::debug!(
                                    "[BLOCKTX] REFUSING oversized block for hash {:?}: {:?}",
                                    hash,
                                    e
                                );
                                BlockTxResponse::NotFound
                            } else {
                                tracing::debug!("[BLOCKTX] Block found for hash {:?}", hash);
                                BlockTxResponse::BlockData(Box::new(b.clone()))
                            }
                        } else {
                            tracing::debug!(
                                "[BLOCKTX] REFUSING block that fails canonical serialization for hash {:?}",
                                hash
                            );
                            BlockTxResponse::NotFound
                        }
                    }
                    None => {
                        tracing::debug!("[BLOCKTX] Block NOT found for hash {:?}", hash);
                        BlockTxResponse::NotFound
                    }
                }
            }
            BlockTxRequest::GetTx { hash } => {
                tracing::debug!("[BLOCKTX] BlockTxRequest::GetTx for hash {:?}", hash);
                match mempool.get_transaction(&hash) {
                    Ok(Some(ref tx)) => {
                        tracing::debug!("[BLOCKTX] Transaction found for hash {:?}", hash);
                        BlockTxResponse::TxData(Box::new(tx.clone()))
                    }
                    Ok(None) => {
                        tracing::debug!("[BLOCKTX] Transaction NOT found for hash {:?}", hash);
                        BlockTxResponse::NotFound
                    }
                    Err(e) => {
                        tracing::debug!(
                            "[BLOCKTX] Error fetching transaction for hash {:?}: {:?}",
                            hash,
                            e
                        );
                        BlockTxResponse::NotFound
                    }
                }
            }
            BlockTxRequest::GetBatchByIndex { index } => {
                tracing::debug!(
                    "[BLOCKTX] BlockTxRequest::GetBatchByIndex for index {}",
                    index
                );
                match storage.get_batch_bytes_by_index(index) {
                    Ok(Some(data)) => {
                        if let Err(e) = ensure_within_consensus_cap(
                            "serve BatchData (canonical bytes)",
                            data.len(),
                        ) {
                            tracing::debug!(
                                "[BLOCKTX] REFUSING oversized batch bytes for index {}: {:?}",
                                index,
                                e
                            );
                            BlockTxResponse::NotFound
                        } else {
                            tracing::debug!("[BLOCKTX] Batch bytes found for index {}", index);
                            BlockTxResponse::BatchData(data)
                        }
                    }
                    Ok(None) => {
                        tracing::debug!("[BLOCKTX] No batch bytes found for index {}", index);
                        BlockTxResponse::NotFound
                    }
                    Err(e) => {
                        tracing::debug!(
                            "[BLOCKTX] ERROR: Failed to get batch bytes for index {}: {:?}",
                            index,
                            e
                        );
                        BlockTxResponse::NotFound
                    }
                }
            }
            BlockTxRequest::GetBatchByHash { hash } => {
                tracing::debug!(
                    "[BLOCKTX] BlockTxRequest::GetBatchByHash for hash {:?}",
                    hash
                );
                match storage.get_batch_by_block_hash(&hash) {
                    Ok(Some(data)) => {
                        if let Err(e) =
                            ensure_within_consensus_cap("serve BatchData (by hash)", data.len())
                        {
                            tracing::debug!(
                                "[BLOCKTX] REFUSING oversized batch bytes for hash {:?}: {:?}",
                                hash,
                                e
                            );
                            BlockTxResponse::NotFound
                        } else {
                            tracing::debug!("[BLOCKTX] Batch bytes found for hash {:?}", hash);
                            BlockTxResponse::BatchData(data)
                        }
                    }
                    Ok(None) => {
                        tracing::debug!("[BLOCKTX] No batch bytes found for hash {:?}", hash);
                        BlockTxResponse::NotFound
                    }
                    Err(e) => {
                        tracing::debug!(
                            "[BLOCKTX] ERROR: Failed to get batch bytes for hash {:?}: {:?}",
                            hash,
                            e
                        );
                        BlockTxResponse::NotFound
                    }
                }
            }
            BlockTxRequest::GetBlockByIndex { index } => {
                tracing::debug!(
                    "[BLOCKTX] BlockTxRequest::GetBlockByIndex for index {}",
                    index
                );
                match storage.get_block_hash_by_index(index) {
                    Ok(hash) => {
                        tracing::debug!("[BLOCKTX] Got block hash for index {}: {:?}", index, hash);
                        match storage.get_block_by_hash(&hash) {
                            Some(ref b) => {
                                if let Ok(bytes) = b.serialize_for_storage() {
                                    if let Err(e) = ensure_within_consensus_cap(
                                        "serve BlockData (canonical)",
                                        bytes.len(),
                                    ) {
                                        tracing::debug!(
                                            "[BLOCKTX] REFUSING oversized block for index {}: {:?}",
                                            index,
                                            e
                                        );
                                        BlockTxResponse::NotFound
                                    } else {
                                        tracing::debug!(
                                            "[BLOCKTX] Block found by hash for index {}",
                                            index
                                        );
                                        BlockTxResponse::BlockData(Box::new(b.clone()))
                                    }
                                } else {
                                    tracing::debug!(
                                        "[BLOCKTX] REFUSING block that fails canonical serialization for index {}",
                                        index
                                    );
                                    BlockTxResponse::NotFound
                                }
                            }
                            None => {
                                tracing::debug!(
                                    "[BLOCKTX] Block not found by hash for index {}, trying bytes",
                                    index
                                );
                                match storage.get_block_bytes_by_index(index) {
                                    Ok(Some(bytes)) => {
                                        if let Err(e) = ensure_within_consensus_cap(
                                            "serve Block bytes (stored)",
                                            bytes.len(),
                                        ) {
                                            tracing::debug!(
                                                "[BLOCKTX] REFUSING oversized stored block bytes at index {}: {:?}",
                                                index,
                                                e
                                            );
                                            BlockTxResponse::NotFound
                                        } else {
                                            tracing::debug!(
                                                "[BLOCKTX] Got block bytes for index {}, attempting deserialization",
                                                index
                                            );
                                            match Block::deserialize_from_storage(&bytes) {
                                                Ok(ref block) => {
                                                    if let Ok(cb) = block.serialize_for_storage() {
                                                        if let Err(e) = ensure_within_consensus_cap(
                                                            "serve BlockData (canonical)",
                                                            cb.len(),
                                                        ) {
                                                            tracing::debug!(
                                                                "[BLOCKTX] REFUSING oversized decoded block at index {}: {:?}",
                                                                index,
                                                                e
                                                            );
                                                            BlockTxResponse::NotFound
                                                        } else {
                                                            tracing::debug!(
                                                                "[BLOCKTX] Block deserialized for index {}",
                                                                index
                                                            );
                                                            if !storage.has_block_by_hash(
                                                                &block.block_hash,
                                                            ) {
                                                                tracing::debug!(
                                                                    "[BLOCKTX] Block not indexed by hash. Indexing now..."
                                                                );
                                                                _ = storage.index_block_by_hash(
                                                                    &block.block_hash,
                                                                    &bytes,
                                                                );
                                                            }
                                                            BlockTxResponse::BlockData(Box::new(
                                                                block.clone(),
                                                            ))
                                                        }
                                                    } else {
                                                        tracing::debug!(
                                                            "[BLOCKTX] REFUSING decoded block that fails canonical serialization at index {}",
                                                            index
                                                        );
                                                        BlockTxResponse::NotFound
                                                    }
                                                }
                                                Err(e) => {
                                                    tracing::debug!(
                                                        "[BLOCKTX] ERROR: Failed to deserialize block at index {}: {:?}",
                                                        index,
                                                        e
                                                    );
                                                    BlockTxResponse::NotFound
                                                }
                                            }
                                        }
                                    }
                                    Ok(None) => {
                                        tracing::debug!(
                                            "[BLOCKTX] No block bytes found for index {}",
                                            index
                                        );
                                        BlockTxResponse::NotFound
                                    }
                                    Err(e) => {
                                        tracing::debug!(
                                            "[BLOCKTX] ERROR: Failed to get block bytes for index {}: {:?}",
                                            index,
                                            e
                                        );
                                        BlockTxResponse::NotFound
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            "[BLOCKTX] ERROR: Failed to get block hash for index {}: {:?}",
                            index,
                            e
                        );
                        BlockTxResponse::NotFound
                    }
                }
            }
        };

        tracing::debug!("[BLOCKTX] Sending response on channel {:?}", channel);
        let send_result = rr.send_response(channel, resp);
        tracing::debug!("[BLOCKTX] send_response result: {:?}", send_result);
        Ok(())
    } else {
        tracing::debug!(
            "[BLOCKTX] Incoming event is NOT a Message::Request, ignoring: {:?}",
            event
        );
        tracing::debug!("[BLOCKTX] handle_blocktx_event exiting.");
        Ok(())
    }
}

/* ─── varint helpers  ──────────────────────────────── */

fn boxed_read<'d, M, T>(
    io: &'d mut T,
) -> std::pin::Pin<Box<dyn futures::Future<Output = std::io::Result<M>> + Send + 'd>>
where
    M: serde::de::DeserializeOwned + Send + 'd,
    T: AsyncRead + Unpin + Send + 'd,
{
    Box::pin(async move {
        let len_u32 = read_varint_u32(io).await?;

        let len_usize = usize::try_from(len_u32).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "length conversion overflow",
            )
        })?;

        if len_usize > BLOCKTX_MAX_WIRE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "wire message too large: {} bytes (max {})",
                    len_usize, BLOCKTX_MAX_WIRE_BYTES
                ),
            ));
        }

        let mut buf = vec![0u8; len_usize];
        io.read_exact(&mut buf).await?;

        let (msg, remaining): (M, &[u8]) = take_from_bytes(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        if !remaining.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "wire message has trailing bytes after postcard payload: {} bytes",
                    remaining.len()
                ),
            ));
        }

        Ok(msg)
    })
}

fn boxed_write<'d, M, T>(
    io: &'d mut T,
    msg: M,
) -> std::pin::Pin<Box<dyn futures::Future<Output = std::io::Result<()>> + Send + 'd>>
where
    M: serde::Serialize + Send + 'd,
    T: AsyncWrite + Unpin + Send + 'd,
{
    Box::pin(async move {
        let data =
            to_stdvec(&msg).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        if data.len() > BLOCKTX_MAX_WIRE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "wire message too large to send: {} bytes (max {})",
                    data.len(),
                    BLOCKTX_MAX_WIRE_BYTES
                ),
            ));
        }

        let len_u32 = u32::try_from(data.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "length conversion overflow",
            )
        })?;

        write_varint_u32(io, len_u32).await?;
        io.write_all(&data).await?;
        io.flush().await
    })
}

async fn read_varint_u32<R>(r: &mut R) -> std::io::Result<u32>
where
    R: AsyncRead + Unpin,
{
    let (mut v, mut s) = (0u32, 0u32);
    let mut b = [0u8; 1];
    loop {
        r.read_exact(&mut b).await?;
        let byte = b[0];
        v |= u32::from(byte & 0x7F) << s;
        if byte & 0x80 == 0 {
            return Ok(v);
        }
        s = s.saturating_add(7);
        if s >= 32 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
    }
}

async fn write_varint_u32<W>(w: &mut W, mut val: u32) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut b = [0u8; 1];
    loop {
        b[0] = (val & 0x7F) as u8;
        val >>= 7;
        if val == 0 {
            w.write_all(&b).await?;
            return Ok(());
        }
        b[0] |= 0x80;
        w.write_all(&b).await?;
    }
}

/* ─── helper for selective response matching  ───────── */

pub fn match_blocktx_response(
    peer: &PeerId,
    req_id: OutboundRequestId,
    event: SwarmEvent<OutEvent>,
) -> Option<BlockTxResponse> {
    if let SwarmEvent::Behaviour(OutEvent::BlockTx(ev)) = event {
        match *ev {
            Event::Message {
                peer: event_peer,
                message:
                    Message::Response {
                        request_id,
                        response,
                        ..
                    },
                ..
            } if &event_peer == peer && request_id == req_id => {
                match &response {
                    BlockTxResponse::BatchData(data)
                        if ensure_within_consensus_cap(
                            "recv BatchData (canonical bytes)",
                            data.len(),
                        )
                        .is_err() =>
                    {
                        return None;
                    }
                    BlockTxResponse::BlockData(b) => {
                        if let Ok(bytes) = b.serialize_for_storage() {
                            if ensure_within_consensus_cap(
                                "recv BlockData (canonical)",
                                bytes.len(),
                            )
                            .is_err()
                            {
                                return None;
                            }
                        } else {
                            return None;
                        }
                    }
                    _ => {}
                }
                return Some(response);
            }
            _ => {}
        }
    }
    None
}
