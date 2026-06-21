#![no_main]

use futures::executor::block_on;
use futures::io::Cursor;
use libfuzzer_sys::fuzz_target;
use libp2p::request_response::Codec;
use libp2p::{swarm::SwarmEvent, PeerId};

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const MAX_BLOCK_SIZE: u64 = 2 * 1024 * 1024;
            pub const MIN_BLOCK_SIZE: u64 = 64;
        }
    }

    pub mod helper {
        use serde::de::{Error as DeError, SeqAccess, Visitor};
        use serde::ser::SerializeTuple;
        use serde::{Deserializer, Serializer};
        use std::fmt;

        pub mod serde_u8_array_64 {
            use super::*;

            pub fn serialize<S>(arr: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut tup = serializer.serialize_tuple(64)?;
                for b in arr.iter() {
                    tup.serialize_element(b)?;
                }
                tup.end()
            }

            pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
            where
                D: Deserializer<'de>,
            {
                struct Arr64Visitor;

                impl<'de> Visitor<'de> for Arr64Visitor {
                    type Value = [u8; 64];

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, "a 64-byte array")
                    }

                    fn visit_seq<A>(self, mut seq: A) -> Result<[u8; 64], A::Error>
                    where
                        A: SeqAccess<'de>,
                    {
                        let mut out = [0u8; 64];

                        for (i, slot) in out.iter_mut().enumerate() {
                            *slot = seq
                                .next_element::<u8>()?
                                .ok_or_else(|| DeError::invalid_length(i, &self))?;
                        }

                        if let Some(_extra) = seq.next_element::<u8>()? {
                            return Err(DeError::invalid_length(65, &self));
                        }

                        Ok(out)
                    }
                }

                deserializer.deserialize_tuple(64, Arr64Visitor)
            }
        }
    }
}

mod blockchain {
    pub mod block_002_blocks {
        use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
        use crate::utility::helper::serde_u8_array_64;
        use serde::{Deserialize, Serialize};
        use std::io;

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct Block {
            #[serde(with = "serde_u8_array_64")]
            pub block_hash: [u8; 64],
            pub index: u64,
            pub payload: Vec<u8>,
        }

        impl Block {
            pub fn new(block_hash: [u8; 64], index: u64, payload: Vec<u8>) -> Self {
                Self {
                    block_hash,
                    index,
                    payload,
                }
            }

            pub fn serialize_for_storage(&self) -> io::Result<Vec<u8>> {
                let bytes = postcard::to_stdvec(self).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("serialize block: {e}"))
                })?;

                let cap = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).unwrap_or(usize::MAX);
                if bytes.len() > cap {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("serialized block exceeds MAX_BLOCK_SIZE: {} > {cap}", bytes.len()),
                    ));
                }

                Ok(bytes)
            }

            pub fn deserialize_from_storage(data: &[u8]) -> io::Result<Self> {
                let min = usize::try_from(GlobalConfiguration::MIN_BLOCK_SIZE).unwrap_or(usize::MAX);
                let cap = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).unwrap_or(usize::MAX);

                if data.len() < min {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("stored block below MIN_BLOCK_SIZE: {} < {min}", data.len()),
                    ));
                }

                if data.len() > cap {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("stored block exceeds MAX_BLOCK_SIZE: {} > {cap}", data.len()),
                    ));
                }

                postcard::from_bytes(data).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("deserialize block: {e}"))
                })
            }
        }
    }

    pub mod transaction_001_tx {
        use crate::utility::helper::serde_u8_array_64;
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct Transaction {
            #[serde(with = "serde_u8_array_64")]
            pub tx_hash: [u8; 64],
            pub amount: u64,
            pub payload: Vec<u8>,
        }

        impl Transaction {
            pub fn new(tx_hash: [u8; 64], amount: u64, payload: Vec<u8>) -> Self {
                Self {
                    tx_hash,
                    amount,
                    payload,
                }
            }
        }
    }

    pub mod mempool {
        use crate::blockchain::transaction_001_tx::Transaction;
        use std::collections::BTreeMap;
        use std::io;
        use std::sync::{Arc, Mutex};

        #[derive(Debug, Clone, Default)]
        pub struct MemPool {
            inner: Arc<Mutex<BTreeMap<[u8; 64], Transaction>>>,
        }

        impl MemPool {
            pub fn new_for_fuzz() -> Self {
                Self::default()
            }

            pub fn insert_transaction(&self, hash: [u8; 64], tx: Transaction) {
                if let Ok(mut guard) = self.inner.lock() {
                    guard.insert(hash, tx);
                }
            }

            pub fn get_transaction(&self, hash: &[u8; 64]) -> io::Result<Option<Transaction>> {
                self.inner
                    .lock()
                    .map(|guard| guard.get(hash).cloned())
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "mempool mutex poisoned"))
            }
        }
    }
}

mod storage {
    pub mod rocksdb_005_manager {
        use crate::blockchain::block_002_blocks::Block;
        use std::collections::BTreeMap;
        use std::io;
        use std::sync::{Arc, Mutex};

        #[derive(Debug, Clone, Default)]
        pub struct RockDBManager {
            inner: Arc<Mutex<MockStorage>>,
        }

        #[derive(Debug, Clone, Default)]
        struct MockStorage {
            blocks_by_hash: BTreeMap<[u8; 64], Block>,
            block_hash_by_index: BTreeMap<u64, [u8; 64]>,
            block_bytes_by_index: BTreeMap<u64, Vec<u8>>,
            batch_bytes_by_index: BTreeMap<u64, Vec<u8>>,
            batch_bytes_by_hash: BTreeMap<[u8; 64], Vec<u8>>,
        }

        impl RockDBManager {
            pub fn new_for_fuzz() -> Self {
                Self::default()
            }

            pub fn insert_block(&self, block: Block) {
                if let Ok(mut guard) = self.inner.lock() {
                    let hash = block.block_hash;
                    let index = block.index;
                    if let Ok(bytes) = block.serialize_for_storage() {
                        guard.block_bytes_by_index.insert(index, bytes);
                    }
                    guard.block_hash_by_index.insert(index, hash);
                    guard.blocks_by_hash.insert(hash, block);
                }
            }

            pub fn insert_block_bytes_by_index(&self, index: u64, bytes: Vec<u8>) {
                if let Ok(mut guard) = self.inner.lock() {
                    guard.block_bytes_by_index.insert(index, bytes);
                }
            }

            pub fn insert_block_hash_by_index(&self, index: u64, hash: [u8; 64]) {
                if let Ok(mut guard) = self.inner.lock() {
                    guard.block_hash_by_index.insert(index, hash);
                }
            }

            pub fn insert_batch_by_index(&self, index: u64, data: Vec<u8>) {
                if let Ok(mut guard) = self.inner.lock() {
                    guard.batch_bytes_by_index.insert(index, data);
                }
            }

            pub fn insert_batch_by_hash(&self, hash: [u8; 64], data: Vec<u8>) {
                if let Ok(mut guard) = self.inner.lock() {
                    guard.batch_bytes_by_hash.insert(hash, data);
                }
            }

            pub fn get_block_by_hash(&self, hash: &[u8; 64]) -> Option<Block> {
                self.inner
                    .lock()
                    .ok()
                    .and_then(|guard| guard.blocks_by_hash.get(hash).cloned())
            }

            pub fn get_batch_bytes_by_index(&self, index: u64) -> io::Result<Option<Vec<u8>>> {
                self.inner
                    .lock()
                    .map(|guard| guard.batch_bytes_by_index.get(&index).cloned())
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "storage mutex poisoned"))
            }

            pub fn get_batch_by_block_hash(&self, hash: &[u8; 64]) -> io::Result<Option<Vec<u8>>> {
                self.inner
                    .lock()
                    .map(|guard| guard.batch_bytes_by_hash.get(hash).cloned())
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "storage mutex poisoned"))
            }

            pub fn get_block_hash_by_index(&self, index: u64) -> io::Result<[u8; 64]> {
                self.inner
                    .lock()
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "storage mutex poisoned"))?
                    .block_hash_by_index
                    .get(&index)
                    .copied()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "block hash not found"))
            }

            pub fn get_block_bytes_by_index(&self, index: u64) -> io::Result<Option<Vec<u8>>> {
                self.inner
                    .lock()
                    .map(|guard| guard.block_bytes_by_index.get(&index).cloned())
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "storage mutex poisoned"))
            }

            pub fn has_block_by_hash(&self, hash: &[u8; 64]) -> bool {
                self.inner
                    .lock()
                    .map(|guard| guard.blocks_by_hash.contains_key(hash))
                    .unwrap_or(false)
            }

            pub fn index_block_by_hash(&self, hash: &[u8; 64], bytes: &[u8]) -> io::Result<()> {
                let block = Block::deserialize_from_storage(bytes)?;
                let mut guard = self
                    .inner
                    .lock()
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "storage mutex poisoned"))?;
                guard.blocks_by_hash.insert(*hash, block);
                Ok(())
            }
        }
    }
}

mod network {
    pub mod p2p_003_behaviour {
        use crate::p2p_006_reqresp::{BlockTxRequest, BlockTxResponse};
        use libp2p::request_response;

        #[derive(Debug)]
        pub enum OutEvent {
            BlockTx(Box<request_response::Event<BlockTxRequest, BlockTxResponse>>),
            Other,
        }
    }
}

#[path = "../../src/network/p2p_006_reqresp.rs"]
mod p2p_006_reqresp;

use blockchain::block_002_blocks::Block;
use blockchain::mempool::MemPool;
use blockchain::transaction_001_tx::Transaction;
use network::p2p_003_behaviour::OutEvent;
use p2p_006_reqresp::{
    build_blocktx_exchange, match_blocktx_response, BlockTxCodec, BlockTxProtocol,
    BlockTxRequest, BlockTxResponse, Hash,
};
use storage::rocksdb_005_manager::RockDBManager;

const BLOCKTX_MAX_WIRE_BYTES_FUZZ: usize = 2 * 1024 * 1024;
const MAX_GENERATED_PAYLOAD: usize = 8 * 1024;

fn byte_at(data: &[u8], index: usize, fallback: u8) -> u8 {
    if data.is_empty() {
        fallback
    } else {
        data[index % data.len()]
    }
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = byte_at(data, offset + i, i as u8);
    }
    u64::from_le_bytes(out)
}

fn bounded_len(data: &[u8], salt: usize, max_len: usize) -> usize {
    if max_len == 0 {
        return 0;
    }

    let upper = max_len.saturating_add(1);
    let raw = usize::try_from(read_u64(data, salt)).unwrap_or(usize::MAX);
    raw % upper
}

fn fuzz_hash(data: &[u8], salt: usize) -> Hash {
    let mut out = [0u8; 64];

    if data.is_empty() {
        for (i, b) in out.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(salt as u8).wrapping_add(1);
        }
        return out;
    }

    for i in 0..64 {
        let a = data[(i + salt) % data.len()];
        let b = data[(i.wrapping_mul(17).wrapping_add(salt)) % data.len()];
        out[i] = a ^ b ^ (i as u8).wrapping_add(salt as u8);
    }

    out
}

fn bounded_index(data: &[u8], salt: usize) -> u64 {
    read_u64(data, salt) % 1_000_000
}

fn bounded_payload(data: &[u8], salt: usize, max_len: usize) -> Vec<u8> {
    let len = bounded_len(data, salt, max_len.min(MAX_GENERATED_PAYLOAD));
    let mut out = Vec::with_capacity(len);

    for i in 0..len {
        let a = byte_at(data, salt.wrapping_add(1).wrapping_add(i), i as u8);
        let b = byte_at(
            data,
            salt.wrapping_add(1).wrapping_add(i.wrapping_mul(13)),
            (i as u8).wrapping_mul(7),
        );
        out.push(a ^ b ^ (salt as u8));
    }

    out
}

fn make_block(data: &[u8], salt: usize) -> Block {
    Block::new(
        fuzz_hash(data, salt),
        bounded_index(data, salt + 64),
        bounded_payload(data, salt + 80, MAX_GENERATED_PAYLOAD),
    )
}

fn make_tx(data: &[u8], salt: usize) -> Transaction {
    Transaction::new(
        fuzz_hash(data, salt),
        read_u64(data, salt + 64),
        bounded_payload(data, salt + 80, MAX_GENERATED_PAYLOAD),
    )
}

fn make_request(data: &[u8], salt: usize) -> BlockTxRequest {
    match byte_at(data, salt, 0) % 5 {
        0 => BlockTxRequest::GetBlock {
            hash: fuzz_hash(data, salt + 1),
        },
        1 => BlockTxRequest::GetTx {
            hash: fuzz_hash(data, salt + 2),
        },
        2 => BlockTxRequest::GetBlockByIndex {
            index: bounded_index(data, salt + 3),
        },
        3 => BlockTxRequest::GetBatchByIndex {
            index: bounded_index(data, salt + 4),
        },
        _ => BlockTxRequest::GetBatchByHash {
            hash: fuzz_hash(data, salt + 5),
        },
    }
}

fn make_response(data: &[u8], salt: usize) -> BlockTxResponse {
    match byte_at(data, salt, 0) % 4 {
        0 => BlockTxResponse::NotFound,
        1 => BlockTxResponse::BatchData(bounded_payload(data, salt + 1, MAX_GENERATED_PAYLOAD)),
        2 => BlockTxResponse::BlockData(Box::new(make_block(data, salt + 2))),
        _ => BlockTxResponse::TxData(Box::new(make_tx(data, salt + 3))),
    }
}

fn write_varint_u32_for_fuzz(mut val: u32, out: &mut Vec<u8>) {
    loop {
        let mut b = (val & 0x7F) as u8;
        val >>= 7;
        if val == 0 {
            out.push(b);
            return;
        }
        b |= 0x80;
        out.push(b);
    }
}

fn framed_postcard<M: serde::Serialize>(msg: &M) -> Option<Vec<u8>> {
    let payload = postcard::to_stdvec(msg).ok()?;
    let len = u32::try_from(payload.len()).ok()?;

    let mut framed = Vec::with_capacity(payload.len().saturating_add(5));
    write_varint_u32_for_fuzz(len, &mut framed);
    framed.extend_from_slice(&payload);
    Some(framed)
}

fn framed_postcard_with_trailing<M: serde::Serialize>(msg: &M, trailing: &[u8]) -> Option<Vec<u8>> {
    let mut payload = postcard::to_stdvec(msg).ok()?;
    payload.extend_from_slice(trailing);
    let len = u32::try_from(payload.len()).ok()?;

    let mut framed = Vec::with_capacity(payload.len().saturating_add(5));
    write_varint_u32_for_fuzz(len, &mut framed);
    framed.extend_from_slice(&payload);
    Some(framed)
}

fn malformed_oversized_frame() -> Vec<u8> {
    let mut framed = Vec::new();
    write_varint_u32_for_fuzz(
        (BLOCKTX_MAX_WIRE_BYTES_FUZZ as u32).saturating_add(1),
        &mut framed,
    );
    framed
}

fn malformed_varint_frame() -> Vec<u8> {
    vec![0x80, 0x80, 0x80, 0x80, 0x80]
}

fn exercise_protocol() {
    let protocol = BlockTxProtocol;
    assert_eq!(protocol.as_ref(), "/remzar/blocktx/1.0.0");
    let _ = format!("{:?}", protocol);
}

fn exercise_request_roundtrip(req: BlockTxRequest, data: &[u8]) {
    let _ = format!("{:?}", &req);

    if let Ok(bytes) = postcard::to_stdvec(&req) {
        if let Ok(decoded) = postcard::from_bytes::<BlockTxRequest>(&bytes) {
            assert_eq!(decoded, req);
        }
    }

    let mut codec = BlockTxCodec;
    let protocol = BlockTxProtocol;
    let mut writer = Cursor::new(Vec::<u8>::new());

    if block_on(codec.write_request(&protocol, &mut writer, req.clone())).is_ok() {
        let framed = writer.into_inner();
        let mut reader = Cursor::new(framed.clone());
        let decoded = block_on(codec.read_request(&protocol, &mut reader));
        if let Ok(decoded) = decoded {
            assert_eq!(decoded, req);
        }

        let mut truncated = framed;
        if !truncated.is_empty() {
            let new_len = bounded_len(data, 700, truncated.len() - 1);
            truncated.truncate(new_len);
            let mut reader = Cursor::new(truncated);
            let _ = block_on(codec.read_request(&protocol, &mut reader));
        }
    }

    if let Some(trailing) = framed_postcard_with_trailing(&req, &[byte_at(data, 701, 1).max(1)]) {
        let mut reader = Cursor::new(trailing);
        let result = block_on(codec.read_request(&protocol, &mut reader));
        assert!(result.is_err());
    }

    let mut reader = Cursor::new(malformed_oversized_frame());
    assert!(block_on(codec.read_request(&protocol, &mut reader)).is_err());

    let mut reader = Cursor::new(malformed_varint_frame());
    assert!(block_on(codec.read_request(&protocol, &mut reader)).is_err());
}

fn exercise_response_roundtrip(rsp: BlockTxResponse, data: &[u8]) {
    let _ = format!("{:?}", &rsp);

    if let Ok(bytes) = postcard::to_stdvec(&rsp) {
        if let Ok(decoded) = postcard::from_bytes::<BlockTxResponse>(&bytes) {
            assert_eq!(decoded, rsp);
        }
    }

    let mut codec = BlockTxCodec;
    let protocol = BlockTxProtocol;
    let mut writer = Cursor::new(Vec::<u8>::new());

    if block_on(codec.write_response(&protocol, &mut writer, rsp.clone())).is_ok() {
        let framed = writer.into_inner();
        let mut reader = Cursor::new(framed.clone());
        let decoded = block_on(codec.read_response(&protocol, &mut reader));
        if let Ok(decoded) = decoded {
            assert_eq!(decoded, rsp);
        }

        let mut truncated = framed;
        if !truncated.is_empty() {
            let new_len = bounded_len(data, 800, truncated.len() - 1);
            truncated.truncate(new_len);
            let mut reader = Cursor::new(truncated);
            let _ = block_on(codec.read_response(&protocol, &mut reader));
        }
    }

    if let Some(trailing) = framed_postcard_with_trailing(&rsp, &[byte_at(data, 801, 1).max(1)]) {
        let mut reader = Cursor::new(trailing);
        let result = block_on(codec.read_response(&protocol, &mut reader));
        assert!(result.is_err());
    }

    let mut reader = Cursor::new(malformed_oversized_frame());
    assert!(block_on(codec.read_response(&protocol, &mut reader)).is_err());

    let mut reader = Cursor::new(malformed_varint_frame());
    assert!(block_on(codec.read_response(&protocol, &mut reader)).is_err());
}

fn exercise_raw_wire_bytes(data: &[u8]) {
    let protocol = BlockTxProtocol;

    let mut codec = BlockTxCodec;
    let mut reader = Cursor::new(data.to_vec());
    let _ = block_on(codec.read_request(&protocol, &mut reader));

    let mut codec = BlockTxCodec;
    let mut reader = Cursor::new(data.to_vec());
    let _ = block_on(codec.read_response(&protocol, &mut reader));

    let framed_len = data.len().min(MAX_GENERATED_PAYLOAD);
    let mut framed = Vec::with_capacity(framed_len.saturating_add(5));
    write_varint_u32_for_fuzz(u32::try_from(framed_len).unwrap_or(u32::MAX), &mut framed);
    framed.extend_from_slice(&data[..framed_len]);

    let mut codec = BlockTxCodec;
    let mut reader = Cursor::new(framed.clone());
    let _ = block_on(codec.read_request(&protocol, &mut reader));

    let mut codec = BlockTxCodec;
    let mut reader = Cursor::new(framed);
    let _ = block_on(codec.read_response(&protocol, &mut reader));
}

fn exercise_manual_valid_frames(data: &[u8]) {
    let req = make_request(data, 900);
    if let Some(frame) = framed_postcard(&req) {
        let protocol = BlockTxProtocol;
        let mut codec = BlockTxCodec;
        let mut reader = Cursor::new(frame);
        let decoded = block_on(codec.read_request(&protocol, &mut reader));
        if let Ok(decoded) = decoded {
            assert_eq!(decoded, req);
        }
    }

    let rsp = make_response(data, 1000);
    if let Some(frame) = framed_postcard(&rsp) {
        let protocol = BlockTxProtocol;
        let mut codec = BlockTxCodec;
        let mut reader = Cursor::new(frame);
        let decoded = block_on(codec.read_response(&protocol, &mut reader));
        if let Ok(decoded) = decoded {
            assert_eq!(decoded, rsp);
        }
    }
}

fn exercise_storage_mempool_mocks(data: &[u8]) {
    let storage = RockDBManager::new_for_fuzz();
    let mempool = MemPool::new_for_fuzz();

    let block = make_block(data, 1200);
    let block_hash = block.block_hash;
    let block_index = block.index;
    storage.insert_block(block.clone());

    assert!(storage.has_block_by_hash(&block_hash));
    assert_eq!(storage.get_block_by_hash(&block_hash), Some(block.clone()));
    assert_eq!(storage.get_block_hash_by_index(block_index).ok(), Some(block_hash));
    assert!(storage.get_block_bytes_by_index(block_index).ok().flatten().is_some());

    let missing_hash = fuzz_hash(data, 1300);
    let _ = storage.get_block_by_hash(&missing_hash);
    let _ = storage.get_block_hash_by_index(block_index.saturating_add(1));

    let batch = bounded_payload(data, 1400, MAX_GENERATED_PAYLOAD);
    storage.insert_batch_by_index(block_index, batch.clone());
    storage.insert_batch_by_hash(block_hash, batch.clone());
    assert_eq!(storage.get_batch_bytes_by_index(block_index).ok().flatten(), Some(batch.clone()));
    assert_eq!(storage.get_batch_by_block_hash(&block_hash).ok().flatten(), Some(batch));

    if let Ok(bytes) = block.serialize_for_storage() {
        let alias_hash = fuzz_hash(data, 1500);
        let _ = storage.index_block_by_hash(&alias_hash, &bytes);
        let _ = storage.get_block_by_hash(&alias_hash);
    }

    let invalid_block_bytes = bounded_payload(data, 1600, MAX_GENERATED_PAYLOAD);
    storage.insert_block_bytes_by_index(block_index.saturating_add(7), invalid_block_bytes);
    storage.insert_block_hash_by_index(block_index.saturating_add(7), fuzz_hash(data, 1601));

    let tx = make_tx(data, 1700);
    let tx_hash = tx.tx_hash;
    mempool.insert_transaction(tx_hash, tx.clone());
    assert_eq!(mempool.get_transaction(&tx_hash).ok().flatten(), Some(tx));
    let _ = mempool.get_transaction(&fuzz_hash(data, 1800));
}

fn exercise_behaviour_helpers(data: &[u8]) {
    let mut exchange = build_blocktx_exchange();
    let peer = PeerId::random();
    let req_id = exchange.send_request(&peer, make_request(data, 1900));

    let ignored = match_blocktx_response(
        &peer,
        req_id,
        SwarmEvent::Behaviour(OutEvent::Other),
    );
    assert!(ignored.is_none());
}

fn exercise_rare_write_cap(data: &[u8]) {
    if byte_at(data, 2000, 1) != 0 {
        return;
    }

    let protocol = BlockTxProtocol;
    let mut codec = BlockTxCodec;
    let mut writer = Cursor::new(Vec::<u8>::new());
    let oversized = BlockTxResponse::BatchData(vec![
        byte_at(data, 2001, 0);
        BLOCKTX_MAX_WIRE_BYTES_FUZZ.saturating_add(1)
    ]);

    let result = block_on(codec.write_response(&protocol, &mut writer, oversized));
    assert!(result.is_err());
}

fuzz_target!(|data: &[u8]| {
    exercise_protocol();

    let req = make_request(data, 0);
    exercise_request_roundtrip(req, data);

    let rsp = make_response(data, 100);
    exercise_response_roundtrip(rsp, data);

    exercise_raw_wire_bytes(data);
    exercise_manual_valid_frames(data);
    exercise_storage_mempool_mocks(data);
    exercise_behaviour_helpers(data);
    exercise_rare_write_cap(data);
});
