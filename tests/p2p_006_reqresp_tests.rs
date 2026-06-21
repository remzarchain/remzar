#![cfg(test)]
#![deny(unsafe_code)]

use fips204::ml_dsa_65;
use futures::executor::block_on;
use libp2p::request_response::Codec;
use remzar::{
    blockchain::{
        block_001_metadata::BlockMetadata, block_002_blocks::Block, transaction_001_tx::Transaction,
    },
    network::p2p_006_reqresp::{
        BlockTxCodec, BlockTxExchange, BlockTxProtocol, BlockTxRequest, BlockTxResponse, Hash,
        build_blocktx_exchange,
    },
    utility::{alpha_001_global_configuration::GlobalConfiguration, helper::UNIT_DIVISOR},
};

type TestResult<T = ()> = Result<T, String>;

const TEST_TIMESTAMP: u64 = 1_700_000_000;
const BLOCKTX_TEST_MAX_WIRE_BYTES: usize = 2usize * 1024usize * 1024usize;
const FUZZ_SEED: u64 = 0x0060_0BAD_CAFE_0001;

fn p2p_006_request_frame(req: &BlockTxRequest) -> TestResult<Vec<u8>> {
    block_on(async {
        let protocol = BlockTxProtocol;
        let mut codec = BlockTxCodec;
        let mut bytes = Vec::new();

        codec
            .write_request(&protocol, &mut bytes, req.clone())
            .await
            .map_err(fmt_err)?;

        Ok(bytes)
    })
}

fn p2p_006_response_frame(resp: &BlockTxResponse) -> TestResult<Vec<u8>> {
    block_on(async {
        let protocol = BlockTxProtocol;
        let mut codec = BlockTxCodec;
        let mut bytes = Vec::new();

        codec
            .write_response(&protocol, &mut bytes, resp.clone())
            .await
            .map_err(fmt_err)?;

        Ok(bytes)
    })
}

fn p2p_006_decode_varint_prefix(bytes: &[u8]) -> TestResult<(usize, usize)> {
    let mut value = 0u32;
    let mut shift = 0u32;

    for (pos, byte) in bytes.iter().copied().enumerate() {
        let low = u32::from(byte & 0x7Fu8);
        let shifted = low
            .checked_shl(shift)
            .ok_or_else(|| "varint shift overflow".to_string())?;
        value |= shifted;

        if byte & 0x80u8 == 0u8 {
            let consumed = pos
                .checked_add(1usize)
                .ok_or_else(|| "varint consumed overflow".to_string())?;
            let len = usize::try_from(value).map_err(fmt_err)?;

            return Ok((len, consumed));
        }

        shift = shift
            .checked_add(7u32)
            .ok_or_else(|| "varint shift add overflow".to_string())?;

        if shift >= 32u32 {
            return Err("varint too long for u32".to_string());
        }
    }

    Err("incomplete varint".to_string())
}

fn p2p_006_postcard_request_len(req: &BlockTxRequest) -> TestResult<usize> {
    postcard::to_allocvec(req)
        .map(|bytes| bytes.len())
        .map_err(fmt_err)
}

fn p2p_006_postcard_response_len(resp: &BlockTxResponse) -> TestResult<usize> {
    postcard::to_allocvec(resp)
        .map(|bytes| bytes.len())
        .map_err(fmt_err)
}

fn p2p_006_large_batch_response_under_wire_cap() -> TestResult<BlockTxResponse> {
    let mut payload_len = BLOCKTX_TEST_MAX_WIRE_BYTES
        .checked_sub(32usize)
        .ok_or_else(|| "wire cap subtraction underflow".to_string())?;

    loop {
        let response = BlockTxResponse::BatchData(vec![0x33u8; payload_len]);
        let encoded_len = p2p_006_postcard_response_len(&response)?;

        if encoded_len <= BLOCKTX_TEST_MAX_WIRE_BYTES {
            return Ok(response);
        }

        payload_len = payload_len
            .checked_sub(1024usize)
            .ok_or_else(|| "could not find under-cap batch response".to_string())?;
    }
}

fn fmt_err<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn wallet(ch: char) -> String {
    format!("r{}", ch.to_string().repeat(128usize))
}

fn sender_wallet() -> String {
    wallet('1')
}

fn receiver_wallet() -> String {
    wallet('2')
}

fn hash64(byte: u8) -> Hash {
    [byte; 64]
}

fn make_transaction(amount: u64) -> TestResult<Transaction> {
    Transaction::new(sender_wallet(), receiver_wallet(), amount).map_err(fmt_err)
}

fn make_block(index: u64) -> TestResult<Block> {
    let index_mod = index
        .checked_rem(251u64)
        .ok_or_else(|| "index modulo failed".to_string())?;

    let fill = u8::try_from(index_mod).map_err(fmt_err)?;

    let previous_fill = fill.wrapping_add(17u8);
    let merkle_fill = fill.wrapping_add(1u8);

    let metadata = BlockMetadata::new(
        index,
        TEST_TIMESTAMP,
        hash64(previous_fill),
        hash64(merkle_fill),
        [merkle_fill; ml_dsa_65::SIG_LEN],
        None,
        GlobalConfiguration::MAX_BLOCK_SIZE,
    );

    Block::new(
        metadata,
        Some(format!("tx_batch_{index:010}")),
        sender_wallet(),
        0u64,
    )
    .map_err(fmt_err)
}

fn make_all_requests() -> Vec<BlockTxRequest> {
    vec![
        BlockTxRequest::GetBlock { hash: hash64(1u8) },
        BlockTxRequest::GetTx { hash: hash64(2u8) },
        BlockTxRequest::GetBlockByIndex { index: 3u64 },
        BlockTxRequest::GetBatchByIndex { index: 4u64 },
        BlockTxRequest::GetBatchByHash { hash: hash64(5u8) },
    ]
}

fn make_all_responses() -> TestResult<Vec<BlockTxResponse>> {
    Ok(vec![
        BlockTxResponse::BlockData(Box::new(make_block(1u64)?)),
        BlockTxResponse::BatchData(vec![1u8, 2u8, 3u8, 4u8]),
        BlockTxResponse::TxData(Box::new(make_transaction(UNIT_DIVISOR)?)),
        BlockTxResponse::NotFound,
    ])
}

fn next_xorshift64(seed: &mut u64) -> u64 {
    let mut x = *seed;
    x ^= x.wrapping_shl(13);
    x ^= x.wrapping_shr(7);
    x ^= x.wrapping_shl(17);
    *seed = x;
    x
}

fn write_varint_u32_test(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();

    loop {
        let low = value & 0x7Fu32;
        let mut byte = u8::try_from(low).unwrap_or_default();
        value >>= 7;

        if value == 0u32 {
            out.push(byte);
            return out;
        }

        byte |= 0x80u8;
        out.push(byte);
    }
}

async fn codec_roundtrip_request(req: BlockTxRequest) -> TestResult<BlockTxRequest> {
    let protocol = BlockTxProtocol;
    let mut codec = BlockTxCodec;
    let mut bytes = Vec::new();

    codec
        .write_request(&protocol, &mut bytes, req)
        .await
        .map_err(fmt_err)?;

    assert!(!bytes.is_empty());

    let mut reader = bytes.as_slice();
    codec
        .read_request(&protocol, &mut reader)
        .await
        .map_err(fmt_err)
}

async fn codec_roundtrip_response(resp: BlockTxResponse) -> TestResult<BlockTxResponse> {
    let protocol = BlockTxProtocol;
    let mut codec = BlockTxCodec;
    let mut bytes = Vec::new();

    codec
        .write_response(&protocol, &mut bytes, resp)
        .await
        .map_err(fmt_err)?;

    assert!(!bytes.is_empty());

    let mut reader = bytes.as_slice();
    codec
        .read_response(&protocol, &mut reader)
        .await
        .map_err(fmt_err)
}

fn assert_request_roundtrip(req: BlockTxRequest) -> TestResult {
    let decoded = block_on(codec_roundtrip_request(req.clone()))?;

    assert_eq!(decoded, req);
    Ok(())
}

fn assert_response_roundtrip(resp: BlockTxResponse) -> TestResult {
    let decoded = block_on(codec_roundtrip_response(resp.clone()))?;

    assert_eq!(decoded, resp);
    Ok(())
}

fn assert_request_codec_error(bytes: Vec<u8>) -> TestResult {
    block_on(async {
        let protocol = BlockTxProtocol;
        let mut codec = BlockTxCodec;
        let mut reader = bytes.as_slice();

        match codec.read_request(&protocol, &mut reader).await {
            Ok(req) => Err(format!("expected request decode error, got {req:?}")),
            Err(err) => {
                assert!(!err.to_string().is_empty() || err.kind() != std::io::ErrorKind::Other);
                Ok(())
            }
        }
    })
}

fn assert_response_codec_error(bytes: Vec<u8>) -> TestResult {
    block_on(async {
        let protocol = BlockTxProtocol;
        let mut codec = BlockTxCodec;
        let mut reader = bytes.as_slice();

        match codec.read_response(&protocol, &mut reader).await {
            Ok(resp) => Err(format!("expected response decode error, got {resp:?}")),
            Err(err) => {
                assert!(!err.to_string().is_empty() || err.kind() != std::io::ErrorKind::Other);
                Ok(())
            }
        }
    })
}

#[test]
fn p2p_01_006_reqresp_hash_width_is_64_bytes() -> TestResult {
    let hash = hash64(1u8);

    assert_eq!(hash.len(), 64usize);
    Ok(())
}

#[test]
fn p2p_02_006_reqresp_protocol_name_matches_expected() -> TestResult {
    let protocol = BlockTxProtocol;

    assert_eq!(protocol.as_ref(), "/remzar/blocktx/1.0.0");
    Ok(())
}

#[test]
fn p2p_03_006_reqresp_protocol_clone_preserves_name() -> TestResult {
    let protocol = BlockTxProtocol;
    let cloned = protocol.clone();

    assert_eq!(protocol.as_ref(), cloned.as_ref());
    Ok(())
}

#[test]
fn p2p_04_006_reqresp_protocol_debug_contains_type_name() -> TestResult {
    let protocol = BlockTxProtocol;
    let debug = format!("{protocol:?}");

    assert!(debug.contains("BlockTxProtocol"));
    Ok(())
}

#[test]
fn p2p_05_006_reqresp_codec_default_constructs() -> TestResult {
    let codec = BlockTxCodec;
    let _cloned = codec.clone();

    Ok(())
}

#[test]
fn p2p_06_006_reqresp_build_blocktx_exchange_constructs_behaviour() -> TestResult {
    let exchange: BlockTxExchange = build_blocktx_exchange();

    drop(exchange);
    Ok(())
}

#[test]
fn p2p_07_006_reqresp_get_block_request_preserves_hash() -> TestResult {
    let req = BlockTxRequest::GetBlock { hash: hash64(7u8) };

    match req {
        BlockTxRequest::GetBlock { hash } => {
            assert_eq!(hash, hash64(7u8));
            Ok(())
        }
        other => Err(format!("unexpected request {other:?}")),
    }
}

#[test]
fn p2p_08_006_reqresp_get_tx_request_preserves_hash() -> TestResult {
    let req = BlockTxRequest::GetTx { hash: hash64(8u8) };

    match req {
        BlockTxRequest::GetTx { hash } => {
            assert_eq!(hash, hash64(8u8));
            Ok(())
        }
        other => Err(format!("unexpected request {other:?}")),
    }
}

#[test]
fn p2p_09_006_reqresp_get_block_by_index_preserves_index() -> TestResult {
    let req = BlockTxRequest::GetBlockByIndex { index: 9u64 };

    match req {
        BlockTxRequest::GetBlockByIndex { index } => {
            assert_eq!(index, 9u64);
            Ok(())
        }
        other => Err(format!("unexpected request {other:?}")),
    }
}

#[test]
fn p2p_10_006_reqresp_get_batch_by_index_preserves_index() -> TestResult {
    let req = BlockTxRequest::GetBatchByIndex { index: 10u64 };

    match req {
        BlockTxRequest::GetBatchByIndex { index } => {
            assert_eq!(index, 10u64);
            Ok(())
        }
        other => Err(format!("unexpected request {other:?}")),
    }
}

#[test]
fn p2p_11_006_reqresp_get_batch_by_hash_preserves_hash() -> TestResult {
    let req = BlockTxRequest::GetBatchByHash { hash: hash64(11u8) };

    match req {
        BlockTxRequest::GetBatchByHash { hash } => {
            assert_eq!(hash, hash64(11u8));
            Ok(())
        }
        other => Err(format!("unexpected request {other:?}")),
    }
}

#[test]
fn p2p_12_006_reqresp_request_postcard_roundtrip_all_variants() -> TestResult {
    for req in make_all_requests() {
        let bytes = postcard::to_allocvec(&req).map_err(fmt_err)?;
        let decoded: BlockTxRequest = postcard::from_bytes(&bytes).map_err(fmt_err)?;

        assert_eq!(decoded, req);
    }

    Ok(())
}

#[test]
fn p2p_13_006_reqresp_response_postcard_roundtrip_all_variants() -> TestResult {
    for resp in make_all_responses()? {
        let bytes = postcard::to_allocvec(&resp).map_err(fmt_err)?;
        let decoded: BlockTxResponse = postcard::from_bytes(&bytes).map_err(fmt_err)?;

        assert_eq!(decoded, resp);
    }

    Ok(())
}

#[test]
fn p2p_14_006_reqresp_codec_roundtrip_get_block_request() -> TestResult {
    assert_request_roundtrip(BlockTxRequest::GetBlock { hash: hash64(14u8) })
}

#[test]
fn p2p_15_006_reqresp_codec_roundtrip_get_tx_request() -> TestResult {
    assert_request_roundtrip(BlockTxRequest::GetTx { hash: hash64(15u8) })
}

#[test]
fn p2p_16_006_reqresp_codec_roundtrip_get_block_by_index_request() -> TestResult {
    assert_request_roundtrip(BlockTxRequest::GetBlockByIndex { index: 16u64 })
}

#[test]
fn p2p_17_006_reqresp_codec_roundtrip_get_batch_by_index_request() -> TestResult {
    assert_request_roundtrip(BlockTxRequest::GetBatchByIndex { index: 17u64 })
}

#[test]
fn p2p_18_006_reqresp_codec_roundtrip_get_batch_by_hash_request() -> TestResult {
    assert_request_roundtrip(BlockTxRequest::GetBatchByHash { hash: hash64(18u8) })
}

#[test]
fn p2p_19_006_reqresp_codec_roundtrip_block_data_response() -> TestResult {
    assert_response_roundtrip(BlockTxResponse::BlockData(Box::new(make_block(19u64)?)))
}

#[test]
fn p2p_20_006_reqresp_codec_roundtrip_batch_data_response() -> TestResult {
    assert_response_roundtrip(BlockTxResponse::BatchData(vec![20u8, 21u8, 22u8]))
}

#[test]
fn p2p_21_006_reqresp_codec_roundtrip_tx_data_response() -> TestResult {
    assert_response_roundtrip(BlockTxResponse::TxData(Box::new(make_transaction(21u64)?)))
}

#[test]
fn p2p_22_006_reqresp_codec_roundtrip_not_found_response() -> TestResult {
    assert_response_roundtrip(BlockTxResponse::NotFound)
}

#[test]
fn p2p_23_006_reqresp_block_data_response_preserves_block_index() -> TestResult {
    let decoded = block_on(codec_roundtrip_response(BlockTxResponse::BlockData(
        Box::new(make_block(23u64)?),
    )))?;

    match decoded {
        BlockTxResponse::BlockData(block) => {
            assert_eq!(block.metadata.index, 23u64);
            assert!(block.verify_block_hash().map_err(fmt_err)?);
            Ok(())
        }
        other => Err(format!("unexpected response {other:?}")),
    }
}

#[test]
fn p2p_24_006_reqresp_tx_data_response_preserves_amount() -> TestResult {
    let decoded = block_on(codec_roundtrip_response(BlockTxResponse::TxData(Box::new(
        make_transaction(24u64)?,
    ))))?;

    match decoded {
        BlockTxResponse::TxData(tx) => {
            assert_eq!(tx.amount, 24u64);
            tx.validate().map_err(fmt_err)?;
            Ok(())
        }
        other => Err(format!("unexpected response {other:?}")),
    }
}

#[test]
fn p2p_25_006_reqresp_batch_data_response_preserves_bytes() -> TestResult {
    let payload = vec![1u8, 3u8, 5u8, 7u8, 9u8];
    let decoded = block_on(codec_roundtrip_response(BlockTxResponse::BatchData(
        payload.clone(),
    )))?;

    match decoded {
        BlockTxResponse::BatchData(bytes) => {
            assert_eq!(bytes, payload);
            Ok(())
        }
        other => Err(format!("unexpected response {other:?}")),
    }
}

#[test]
fn p2p_26_006_reqresp_empty_input_request_decode_errors() -> TestResult {
    assert_request_codec_error(Vec::new())
}

#[test]
fn p2p_27_006_reqresp_empty_input_response_decode_errors() -> TestResult {
    assert_response_codec_error(Vec::new())
}

#[test]
fn p2p_28_006_reqresp_invalid_varint_request_decode_errors() -> TestResult {
    let bytes = vec![0x80u8, 0x80u8, 0x80u8, 0x80u8, 0x80u8];

    assert_request_codec_error(bytes)
}

#[test]
fn p2p_29_006_reqresp_invalid_varint_response_decode_errors() -> TestResult {
    let bytes = vec![0x80u8, 0x80u8, 0x80u8, 0x80u8, 0x80u8];

    assert_response_codec_error(bytes)
}

#[test]
fn p2p_30_006_reqresp_declared_oversized_request_frame_is_rejected_before_alloc_payload()
-> TestResult {
    let too_large = BLOCKTX_TEST_MAX_WIRE_BYTES
        .checked_add(1usize)
        .ok_or_else(|| "too large request length overflow".to_string())?;
    let too_large_u32 = u32::try_from(too_large).map_err(fmt_err)?;
    let bytes = write_varint_u32_test(too_large_u32);

    assert_request_codec_error(bytes)
}

#[test]
fn p2p_31_006_reqresp_declared_oversized_response_frame_is_rejected_before_alloc_payload()
-> TestResult {
    let too_large = BLOCKTX_TEST_MAX_WIRE_BYTES
        .checked_add(1usize)
        .ok_or_else(|| "too large response length overflow".to_string())?;
    let too_large_u32 = u32::try_from(too_large).map_err(fmt_err)?;
    let bytes = write_varint_u32_test(too_large_u32);

    assert_response_codec_error(bytes)
}

#[test]
fn p2p_32_006_reqresp_truncated_request_frame_errors() -> TestResult {
    block_on(async {
        let protocol = BlockTxProtocol;
        let mut codec = BlockTxCodec;
        let mut bytes = Vec::new();

        codec
            .write_request(
                &protocol,
                &mut bytes,
                BlockTxRequest::GetBlock { hash: hash64(32u8) },
            )
            .await
            .map_err(fmt_err)?;

        bytes
            .pop()
            .ok_or_else(|| "request frame was unexpectedly empty".to_string())?;

        let mut reader = bytes.as_slice();
        assert!(codec.read_request(&protocol, &mut reader).await.is_err());
        Ok(())
    })
}

#[test]
fn p2p_33_006_reqresp_truncated_response_frame_errors() -> TestResult {
    block_on(async {
        let protocol = BlockTxProtocol;
        let mut codec = BlockTxCodec;
        let mut bytes = Vec::new();

        codec
            .write_response(&protocol, &mut bytes, BlockTxResponse::NotFound)
            .await
            .map_err(fmt_err)?;

        bytes
            .pop()
            .ok_or_else(|| "response frame was unexpectedly empty".to_string())?;

        let mut reader = bytes.as_slice();
        assert!(codec.read_response(&protocol, &mut reader).await.is_err());
        Ok(())
    })
}

#[test]
fn p2p_34_006_reqresp_corrupted_request_payload_errors() -> TestResult {
    block_on(async {
        let protocol = BlockTxProtocol;
        let mut codec = BlockTxCodec;
        let mut bytes = Vec::new();

        codec
            .write_request(
                &protocol,
                &mut bytes,
                BlockTxRequest::GetBatchByHash { hash: hash64(34u8) },
            )
            .await
            .map_err(fmt_err)?;

        let (_declared_len, header_len) = p2p_006_decode_varint_prefix(&bytes)?;

        let payload_tag = bytes
            .get_mut(header_len)
            .ok_or_else(|| "request frame missing payload tag".to_string())?;

        *payload_tag = 250u8;

        let mut reader = bytes.as_slice();
        assert!(codec.read_request(&protocol, &mut reader).await.is_err());
        Ok(())
    })
}

#[test]
fn p2p_35_006_reqresp_corrupted_response_payload_errors() -> TestResult {
    block_on(async {
        let protocol = BlockTxProtocol;
        let mut codec = BlockTxCodec;
        let mut bytes = Vec::new();

        codec
            .write_response(
                &protocol,
                &mut bytes,
                BlockTxResponse::BatchData(vec![1u8, 2u8]),
            )
            .await
            .map_err(fmt_err)?;

        let (_declared_len, header_len) = p2p_006_decode_varint_prefix(&bytes)?;

        let payload_tag = bytes
            .get_mut(header_len)
            .ok_or_else(|| "response frame missing payload tag".to_string())?;

        *payload_tag = 250u8;

        let mut reader = bytes.as_slice();
        assert!(codec.read_response(&protocol, &mut reader).await.is_err());
        Ok(())
    })
}

#[test]
fn p2p_36_006_reqresp_oversized_batch_response_write_is_rejected() -> TestResult {
    block_on(async {
        let protocol = BlockTxProtocol;
        let mut codec = BlockTxCodec;
        let mut bytes = Vec::new();
        let payload_len = BLOCKTX_TEST_MAX_WIRE_BYTES
            .checked_add(1usize)
            .ok_or_else(|| "oversized batch payload len overflow".to_string())?;
        let response = BlockTxResponse::BatchData(vec![0u8; payload_len]);

        assert!(
            codec
                .write_response(&protocol, &mut bytes, response)
                .await
                .is_err()
        );
        Ok(())
    })
}

#[test]
fn p2p_37_006_reqresp_load_roundtrip_128_get_block_by_index_requests() -> TestResult {
    let mut checked = 0usize;

    for index in 0u64..128u64 {
        assert_request_roundtrip(BlockTxRequest::GetBlockByIndex { index })?;

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "request load counter overflow".to_string())?;
    }

    assert_eq!(checked, 128usize);
    Ok(())
}

#[test]
fn p2p_38_006_reqresp_load_roundtrip_128_batch_data_responses() -> TestResult {
    let mut checked = 0usize;

    for index in 0u8..128u8 {
        assert_response_roundtrip(BlockTxResponse::BatchData(vec![index; 8usize]))?;

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "response load counter overflow".to_string())?;
    }

    assert_eq!(checked, 128usize);
    Ok(())
}

#[test]
fn p2p_39_006_reqresp_fuzz_request_hash_roundtrips_64_samples() -> TestResult {
    let mut seed = FUZZ_SEED;
    let mut checked = 0usize;

    for _ in 0usize..64usize {
        let sample = next_xorshift64(&mut seed);
        let byte = u8::try_from(sample & 0xFFu64).map_err(fmt_err)?;
        let request = if (sample & 1u64) == 0u64 {
            BlockTxRequest::GetBlock { hash: hash64(byte) }
        } else {
            BlockTxRequest::GetTx { hash: hash64(byte) }
        };

        assert_request_roundtrip(request)?;

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "fuzz request counter overflow".to_string())?;
    }

    assert_eq!(checked, 64usize);
    Ok(())
}

#[test]
fn p2p_40_006_reqresp_full_request_response_variant_matrix_roundtrips() -> TestResult {
    let mut checked_requests = 0usize;
    let mut checked_responses = 0usize;

    for request in make_all_requests() {
        assert_request_roundtrip(request)?;

        checked_requests = checked_requests
            .checked_add(1usize)
            .ok_or_else(|| "request matrix counter overflow".to_string())?;
    }

    for response in make_all_responses()? {
        assert_response_roundtrip(response)?;

        checked_responses = checked_responses
            .checked_add(1usize)
            .ok_or_else(|| "response matrix counter overflow".to_string())?;
    }

    assert_eq!(checked_requests, 5usize);
    assert_eq!(checked_responses, 4usize);
    Ok(())
}

#[test]
fn p2p_41_006_reqresp_request_clone_preserves_all_variants() -> TestResult {
    for req in make_all_requests() {
        let cloned = req.clone();

        assert_eq!(cloned, req);
    }

    Ok(())
}

#[test]
fn p2p_42_006_reqresp_response_clone_preserves_all_variants() -> TestResult {
    for resp in make_all_responses()? {
        let cloned = resp.clone();

        assert_eq!(cloned, resp);
    }

    Ok(())
}

#[test]
fn p2p_43_006_reqresp_request_debug_strings_are_nonempty() -> TestResult {
    for req in make_all_requests() {
        let debug = format!("{req:?}");

        assert!(!debug.trim().is_empty());
    }

    Ok(())
}

#[test]
fn p2p_44_006_reqresp_response_debug_strings_are_nonempty() -> TestResult {
    for resp in make_all_responses()? {
        let debug = format!("{resp:?}");

        assert!(!debug.trim().is_empty());
    }

    Ok(())
}

#[test]
fn p2p_45_006_reqresp_request_postcard_lengths_are_nonzero() -> TestResult {
    for req in make_all_requests() {
        let len = p2p_006_postcard_request_len(&req)?;

        assert_ne!(len, 0usize);
    }

    Ok(())
}

#[test]
fn p2p_46_006_reqresp_response_postcard_lengths_are_nonzero() -> TestResult {
    for resp in make_all_responses()? {
        let len = p2p_006_postcard_response_len(&resp)?;

        assert_ne!(len, 0usize);
    }

    Ok(())
}

#[test]
fn p2p_47_006_reqresp_request_frame_prefix_matches_postcard_len() -> TestResult {
    for req in make_all_requests() {
        let frame = p2p_006_request_frame(&req)?;
        let (declared_len, consumed) = p2p_006_decode_varint_prefix(&frame)?;
        let postcard_len = p2p_006_postcard_request_len(&req)?;
        let payload_len = frame
            .len()
            .checked_sub(consumed)
            .ok_or_else(|| "request frame consumed more than length".to_string())?;

        assert_eq!(declared_len, postcard_len);
        assert_eq!(payload_len, postcard_len);
    }

    Ok(())
}

#[test]
fn p2p_48_006_reqresp_response_frame_prefix_matches_postcard_len() -> TestResult {
    for resp in make_all_responses()? {
        let frame = p2p_006_response_frame(&resp)?;
        let (declared_len, consumed) = p2p_006_decode_varint_prefix(&frame)?;
        let postcard_len = p2p_006_postcard_response_len(&resp)?;
        let payload_len = frame
            .len()
            .checked_sub(consumed)
            .ok_or_else(|| "response frame consumed more than length".to_string())?;

        assert_eq!(declared_len, postcard_len);
        assert_eq!(payload_len, postcard_len);
    }

    Ok(())
}

#[test]
fn p2p_49_006_reqresp_request_read_leaves_trailing_bytes_for_next_frame() -> TestResult {
    block_on(async {
        let req = BlockTxRequest::GetBlock { hash: hash64(49u8) };
        let protocol = BlockTxProtocol;
        let mut codec = BlockTxCodec;
        let mut frame = Vec::new();

        codec
            .write_request(&protocol, &mut frame, req.clone())
            .await
            .map_err(fmt_err)?;

        frame.extend_from_slice(&[0xAAu8, 0xBBu8, 0xCCu8]);

        let mut reader = frame.as_slice();
        let decoded = codec
            .read_request(&protocol, &mut reader)
            .await
            .map_err(fmt_err)?;

        assert_eq!(decoded, req);
        assert_eq!(reader, &[0xAAu8, 0xBBu8, 0xCCu8]);
        Ok(())
    })
}

#[test]
fn p2p_50_006_reqresp_response_read_leaves_trailing_bytes_for_next_frame() -> TestResult {
    block_on(async {
        let resp = BlockTxResponse::NotFound;
        let protocol = BlockTxProtocol;
        let mut codec = BlockTxCodec;
        let mut frame = Vec::new();

        codec
            .write_response(&protocol, &mut frame, resp.clone())
            .await
            .map_err(fmt_err)?;

        frame.extend_from_slice(&[0x11u8, 0x22u8]);

        let mut reader = frame.as_slice();
        let decoded = codec
            .read_response(&protocol, &mut reader)
            .await
            .map_err(fmt_err)?;

        assert_eq!(decoded, resp);
        assert_eq!(reader, &[0x11u8, 0x22u8]);
        Ok(())
    })
}

#[test]
fn p2p_51_006_reqresp_vector_get_block_zero_hash_roundtrips() -> TestResult {
    assert_request_roundtrip(BlockTxRequest::GetBlock { hash: [0u8; 64] })
}

#[test]
fn p2p_52_006_reqresp_vector_get_block_ff_hash_roundtrips() -> TestResult {
    assert_request_roundtrip(BlockTxRequest::GetBlock { hash: [0xFFu8; 64] })
}

#[test]
fn p2p_53_006_reqresp_vector_get_tx_alternating_hash_roundtrips() -> TestResult {
    let mut hash = [0u8; 64];

    for (index, byte) in hash.iter_mut().enumerate() {
        *byte = if index % 2usize == 0usize {
            0xAAu8
        } else {
            0x55u8
        };
    }

    assert_request_roundtrip(BlockTxRequest::GetTx { hash })
}

#[test]
fn p2p_54_006_reqresp_vector_get_batch_by_hash_pattern_roundtrips() -> TestResult {
    let mut hash = [0u8; 64];

    for (index, byte) in hash.iter_mut().enumerate() {
        let value = u8::try_from(index).map_err(fmt_err)?;
        *byte = value;
    }

    assert_request_roundtrip(BlockTxRequest::GetBatchByHash { hash })
}

#[test]
fn p2p_55_006_reqresp_vector_get_block_by_index_zero_roundtrips() -> TestResult {
    assert_request_roundtrip(BlockTxRequest::GetBlockByIndex { index: 0u64 })
}

#[test]
fn p2p_56_006_reqresp_vector_get_block_by_index_u64_max_roundtrips() -> TestResult {
    assert_request_roundtrip(BlockTxRequest::GetBlockByIndex { index: u64::MAX })
}

#[test]
fn p2p_57_006_reqresp_vector_get_batch_by_index_zero_roundtrips() -> TestResult {
    assert_request_roundtrip(BlockTxRequest::GetBatchByIndex { index: 0u64 })
}

#[test]
fn p2p_58_006_reqresp_vector_get_batch_by_index_u64_max_roundtrips() -> TestResult {
    assert_request_roundtrip(BlockTxRequest::GetBatchByIndex { index: u64::MAX })
}

#[test]
fn p2p_59_006_reqresp_empty_batch_data_response_roundtrips() -> TestResult {
    assert_response_roundtrip(BlockTxResponse::BatchData(Vec::new()))
}

#[test]
fn p2p_60_006_reqresp_4k_batch_data_response_roundtrips() -> TestResult {
    assert_response_roundtrip(BlockTxResponse::BatchData(vec![0x60u8; 4096usize]))
}

#[test]
fn p2p_61_006_reqresp_near_wire_cap_batch_data_response_roundtrips() -> TestResult {
    let response = p2p_006_large_batch_response_under_wire_cap()?;
    let encoded_len = p2p_006_postcard_response_len(&response)?;

    assert!(encoded_len <= BLOCKTX_TEST_MAX_WIRE_BYTES);
    assert_response_roundtrip(response)
}

#[test]
fn p2p_62_006_reqresp_block_data_response_postcard_is_under_wire_cap() -> TestResult {
    let response = BlockTxResponse::BlockData(Box::new(make_block(62u64)?));
    let len = p2p_006_postcard_response_len(&response)?;

    assert!(len <= BLOCKTX_TEST_MAX_WIRE_BYTES);
    Ok(())
}

#[test]
fn p2p_63_006_reqresp_tx_data_response_postcard_is_under_wire_cap() -> TestResult {
    let response = BlockTxResponse::TxData(Box::new(make_transaction(63u64)?));
    let len = p2p_006_postcard_response_len(&response)?;

    assert!(len <= BLOCKTX_TEST_MAX_WIRE_BYTES);
    Ok(())
}

#[test]
fn p2p_64_006_reqresp_not_found_response_is_smaller_than_tx_data_response() -> TestResult {
    let not_found = p2p_006_postcard_response_len(&BlockTxResponse::NotFound)?;
    let tx_data = p2p_006_postcard_response_len(&BlockTxResponse::TxData(Box::new(
        make_transaction(64u64)?,
    )))?;

    assert!(not_found < tx_data);
    Ok(())
}

#[test]
fn p2p_65_006_reqresp_request_hash_variants_have_distinct_postcard_bytes() -> TestResult {
    let get_block =
        postcard::to_allocvec(&BlockTxRequest::GetBlock { hash: hash64(65u8) }).map_err(fmt_err)?;
    let get_tx =
        postcard::to_allocvec(&BlockTxRequest::GetTx { hash: hash64(65u8) }).map_err(fmt_err)?;
    let get_batch = postcard::to_allocvec(&BlockTxRequest::GetBatchByHash { hash: hash64(65u8) })
        .map_err(fmt_err)?;

    assert_ne!(get_block, get_tx);
    assert_ne!(get_tx, get_batch);
    assert_ne!(get_block, get_batch);
    Ok(())
}

#[test]
fn p2p_66_006_reqresp_response_variants_have_distinct_postcard_bytes() -> TestResult {
    let block = postcard::to_allocvec(&BlockTxResponse::BlockData(Box::new(make_block(66u64)?)))
        .map_err(fmt_err)?;
    let batch = postcard::to_allocvec(&BlockTxResponse::BatchData(vec![66u8])).map_err(fmt_err)?;
    let tx = postcard::to_allocvec(&BlockTxResponse::TxData(Box::new(make_transaction(66u64)?)))
        .map_err(fmt_err)?;
    let not_found = postcard::to_allocvec(&BlockTxResponse::NotFound).map_err(fmt_err)?;

    assert_ne!(block, batch);
    assert_ne!(block, tx);
    assert_ne!(block, not_found);
    assert_ne!(batch, tx);
    assert_ne!(batch, not_found);
    assert_ne!(tx, not_found);
    Ok(())
}

#[test]
fn p2p_67_006_reqresp_fuzz_index_requests_roundtrip_256_samples() -> TestResult {
    let mut seed = FUZZ_SEED;
    let mut checked = 0usize;

    for _ in 0usize..256usize {
        let sample = next_xorshift64(&mut seed);
        let req = if sample & 1u64 == 0u64 {
            BlockTxRequest::GetBlockByIndex { index: sample }
        } else {
            BlockTxRequest::GetBatchByIndex { index: sample }
        };

        assert_request_roundtrip(req)?;

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "index fuzz counter overflow".to_string())?;
    }

    assert_eq!(checked, 256usize);
    Ok(())
}

#[test]
fn p2p_68_006_reqresp_fuzz_batch_by_hash_roundtrip_64_samples() -> TestResult {
    let mut seed = FUZZ_SEED;
    let mut checked = 0usize;

    for _ in 0usize..64usize {
        let sample = next_xorshift64(&mut seed);
        let byte = u8::try_from(sample & 0xFFu64).map_err(fmt_err)?;
        let req = BlockTxRequest::GetBatchByHash { hash: hash64(byte) };

        assert_request_roundtrip(req)?;

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "batch-by-hash fuzz counter overflow".to_string())?;
    }

    assert_eq!(checked, 64usize);
    Ok(())
}

#[test]
fn p2p_69_006_reqresp_load_tx_data_roundtrip_128_responses() -> TestResult {
    let mut checked = 0usize;

    for amount in 1u64..=128u64 {
        assert_response_roundtrip(BlockTxResponse::TxData(Box::new(make_transaction(amount)?)))?;

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "tx response load counter overflow".to_string())?;
    }

    assert_eq!(checked, 128usize);
    Ok(())
}

#[test]
fn p2p_70_006_reqresp_load_block_data_roundtrip_32_responses() -> TestResult {
    let mut checked = 0usize;

    for index in 0u64..32u64 {
        assert_response_roundtrip(BlockTxResponse::BlockData(Box::new(make_block(index)?)))?;

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "block response load counter overflow".to_string())?;
    }

    assert_eq!(checked, 32usize);
    Ok(())
}

#[test]
fn p2p_71_006_reqresp_load_not_found_roundtrip_256_responses() -> TestResult {
    let mut checked = 0usize;

    for _ in 0usize..256usize {
        assert_response_roundtrip(BlockTxResponse::NotFound)?;

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "not-found load counter overflow".to_string())?;
    }

    assert_eq!(checked, 256usize);
    Ok(())
}

#[test]
fn p2p_72_006_reqresp_one_byte_declared_request_payload_errors() -> TestResult {
    let bytes = vec![1u8, 250u8];

    assert_request_codec_error(bytes)
}

#[test]
fn p2p_73_006_reqresp_one_byte_declared_response_payload_errors() -> TestResult {
    let bytes = vec![1u8, 250u8];

    assert_response_codec_error(bytes)
}

#[test]
fn p2p_74_006_reqresp_declared_len_two_but_one_request_byte_errors() -> TestResult {
    let bytes = vec![2u8, 0u8];

    assert_request_codec_error(bytes)
}

#[test]
fn p2p_75_006_reqresp_declared_len_two_but_one_response_byte_errors() -> TestResult {
    let bytes = vec![2u8, 0u8];

    assert_response_codec_error(bytes)
}

#[test]
fn p2p_76_006_reqresp_declared_zero_len_request_errors() -> TestResult {
    let bytes = vec![0u8];

    assert_request_codec_error(bytes)
}

#[test]
fn p2p_77_006_reqresp_declared_zero_len_response_errors() -> TestResult {
    let bytes = vec![0u8];

    assert_response_codec_error(bytes)
}

#[test]
fn p2p_78_006_reqresp_six_byte_invalid_varint_request_errors() -> TestResult {
    let bytes = vec![0x80u8, 0x80u8, 0x80u8, 0x80u8, 0x80u8, 0x00u8];

    assert_request_codec_error(bytes)
}

#[test]
fn p2p_79_006_reqresp_six_byte_invalid_varint_response_errors() -> TestResult {
    let bytes = vec![0x80u8, 0x80u8, 0x80u8, 0x80u8, 0x80u8, 0x00u8];

    assert_response_codec_error(bytes)
}

#[test]
fn p2p_80_006_reqresp_empty_batch_data_frame_len_matches_postcard_len() -> TestResult {
    let response = BlockTxResponse::BatchData(Vec::new());
    let frame = p2p_006_response_frame(&response)?;
    let (declared_len, consumed) = p2p_006_decode_varint_prefix(&frame)?;
    let payload_len = frame
        .len()
        .checked_sub(consumed)
        .ok_or_else(|| "empty batch frame consumed overflow".to_string())?;

    assert_eq!(declared_len, p2p_006_postcard_response_len(&response)?);
    assert_eq!(payload_len, declared_len);
    Ok(())
}

#[test]
fn p2p_81_006_reqresp_not_found_frame_len_matches_postcard_len() -> TestResult {
    let response = BlockTxResponse::NotFound;
    let frame = p2p_006_response_frame(&response)?;
    let (declared_len, consumed) = p2p_006_decode_varint_prefix(&frame)?;
    let payload_len = frame
        .len()
        .checked_sub(consumed)
        .ok_or_else(|| "not found frame consumed overflow".to_string())?;

    assert_eq!(declared_len, p2p_006_postcard_response_len(&response)?);
    assert_eq!(payload_len, declared_len);
    Ok(())
}

#[test]
fn p2p_82_006_reqresp_two_request_frames_can_be_read_sequentially() -> TestResult {
    block_on(async {
        let first = BlockTxRequest::GetBlockByIndex { index: 82u64 };
        let second = BlockTxRequest::GetTx { hash: hash64(82u8) };

        let protocol = BlockTxProtocol;
        let mut codec = BlockTxCodec;
        let mut combined = Vec::new();

        codec
            .write_request(&protocol, &mut combined, first.clone())
            .await
            .map_err(fmt_err)?;

        codec
            .write_request(&protocol, &mut combined, second.clone())
            .await
            .map_err(fmt_err)?;

        let mut reader = combined.as_slice();

        let first_decoded = codec
            .read_request(&protocol, &mut reader)
            .await
            .map_err(fmt_err)?;

        let second_decoded = codec
            .read_request(&protocol, &mut reader)
            .await
            .map_err(fmt_err)?;

        assert_eq!(first_decoded, first);
        assert_eq!(second_decoded, second);
        assert!(reader.is_empty());

        Ok(())
    })
}

#[test]
fn p2p_83_006_reqresp_two_response_frames_can_be_read_sequentially() -> TestResult {
    block_on(async {
        let first = BlockTxResponse::NotFound;
        let second = BlockTxResponse::BatchData(vec![83u8; 8usize]);

        let protocol = BlockTxProtocol;
        let mut codec = BlockTxCodec;
        let mut combined = Vec::new();

        codec
            .write_response(&protocol, &mut combined, first.clone())
            .await
            .map_err(fmt_err)?;

        codec
            .write_response(&protocol, &mut combined, second.clone())
            .await
            .map_err(fmt_err)?;

        let mut reader = combined.as_slice();

        let first_decoded = codec
            .read_response(&protocol, &mut reader)
            .await
            .map_err(fmt_err)?;

        let second_decoded = codec
            .read_response(&protocol, &mut reader)
            .await
            .map_err(fmt_err)?;

        assert_eq!(first_decoded, first);
        assert_eq!(second_decoded, second);
        assert!(reader.is_empty());

        Ok(())
    })
}

#[test]
fn p2p_84_006_reqresp_request_frame_encoding_is_deterministic() -> TestResult {
    let request = BlockTxRequest::GetBatchByHash { hash: hash64(84u8) };
    let first = p2p_006_request_frame(&request)?;
    let second = p2p_006_request_frame(&request)?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn p2p_85_006_reqresp_response_frame_encoding_is_deterministic() -> TestResult {
    let response = BlockTxResponse::TxData(Box::new(make_transaction(85u64)?));
    let first = p2p_006_response_frame(&response)?;
    let second = p2p_006_response_frame(&response)?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn p2p_86_006_reqresp_request_variant_postcard_tags_are_distinct() -> TestResult {
    let mut tags = std::collections::BTreeSet::new();

    for request in make_all_requests() {
        let bytes = postcard::to_allocvec(&request).map_err(fmt_err)?;
        let tag = bytes
            .first()
            .copied()
            .ok_or_else(|| "request postcard bytes empty".to_string())?;

        assert!(tags.insert(tag));
    }

    assert_eq!(tags.len(), 5usize);
    Ok(())
}

#[test]
fn p2p_87_006_reqresp_response_variant_postcard_tags_are_distinct() -> TestResult {
    let mut tags = std::collections::BTreeSet::new();

    for response in make_all_responses()? {
        let bytes = postcard::to_allocvec(&response).map_err(fmt_err)?;
        let tag = bytes
            .first()
            .copied()
            .ok_or_else(|| "response postcard bytes empty".to_string())?;

        assert!(tags.insert(tag));
    }

    assert_eq!(tags.len(), 4usize);
    Ok(())
}

#[test]
fn p2p_88_006_reqresp_protocol_default_clone_debug_is_stable() -> TestResult {
    let protocol = BlockTxProtocol;
    let cloned = protocol.clone();
    let defaulted = BlockTxProtocol;

    assert_eq!(protocol.as_ref(), cloned.as_ref());
    assert_eq!(cloned.as_ref(), defaulted.as_ref());
    assert_eq!(format!("{protocol:?}"), format!("{cloned:?}"));
    Ok(())
}

#[test]
fn p2p_89_006_reqresp_codec_clone_can_roundtrip_request() -> TestResult {
    block_on(async {
        let protocol = BlockTxProtocol;
        let codec = BlockTxCodec;
        let mut cloned = codec.clone();
        let mut bytes = Vec::new();
        let request = BlockTxRequest::GetBlockByIndex { index: 89u64 };

        cloned
            .write_request(&protocol, &mut bytes, request.clone())
            .await
            .map_err(fmt_err)?;

        let mut reader = bytes.as_slice();
        let decoded = cloned
            .read_request(&protocol, &mut reader)
            .await
            .map_err(fmt_err)?;

        assert_eq!(decoded, request);
        Ok(())
    })
}

#[test]
fn p2p_90_006_reqresp_codec_clone_can_roundtrip_response() -> TestResult {
    block_on(async {
        let protocol = BlockTxProtocol;
        let codec = BlockTxCodec;
        let mut cloned = codec.clone();
        let mut bytes = Vec::new();
        let response = BlockTxResponse::BatchData(vec![90u8; 16usize]);

        cloned
            .write_response(&protocol, &mut bytes, response.clone())
            .await
            .map_err(fmt_err)?;

        let mut reader = bytes.as_slice();
        let decoded = cloned
            .read_response(&protocol, &mut reader)
            .await
            .map_err(fmt_err)?;

        assert_eq!(decoded, response);
        Ok(())
    })
}

#[test]
fn p2p_91_006_reqresp_hash_patterns_survive_get_block_roundtrip() -> TestResult {
    let patterns = [
        [0u8; 64],
        [1u8; 64],
        [0xAAu8; 64],
        [0x55u8; 64],
        [0xFFu8; 64],
    ];

    for hash in patterns {
        assert_request_roundtrip(BlockTxRequest::GetBlock { hash })?;
    }

    Ok(())
}

#[test]
fn p2p_92_006_reqresp_hash_patterns_survive_get_tx_roundtrip() -> TestResult {
    let patterns = [
        [0u8; 64],
        [2u8; 64],
        [0xABu8; 64],
        [0xCDu8; 64],
        [0xFFu8; 64],
    ];

    for hash in patterns {
        assert_request_roundtrip(BlockTxRequest::GetTx { hash })?;
    }

    Ok(())
}

#[test]
fn p2p_93_006_reqresp_tx_data_amount_vectors_validate_after_roundtrip() -> TestResult {
    let amounts = [1u64, 2u64, 10u64, UNIT_DIVISOR, u64::from(u32::MAX)];

    for amount in amounts {
        let decoded = block_on(codec_roundtrip_response(BlockTxResponse::TxData(Box::new(
            make_transaction(amount)?,
        ))))?;

        match decoded {
            BlockTxResponse::TxData(tx) => {
                assert_eq!(tx.amount, amount);
                tx.validate().map_err(fmt_err)?;
            }
            other => return Err(format!("unexpected response {other:?}")),
        }
    }

    Ok(())
}

#[test]
fn p2p_94_006_reqresp_block_data_indices_validate_after_roundtrip() -> TestResult {
    let indices = [0u64, 1u64, 2u64, 10u64, 100u64];

    for index in indices {
        let decoded = block_on(codec_roundtrip_response(BlockTxResponse::BlockData(
            Box::new(make_block(index)?),
        )))?;

        match decoded {
            BlockTxResponse::BlockData(block) => {
                assert_eq!(block.metadata.index, index);
                assert!(block.verify_block_hash().map_err(fmt_err)?);
            }
            other => return Err(format!("unexpected response {other:?}")),
        }
    }

    Ok(())
}

#[test]
fn p2p_95_006_reqresp_batch_data_byte_patterns_roundtrip() -> TestResult {
    let patterns = [
        Vec::new(),
        vec![0u8],
        vec![0xFFu8],
        vec![0xAAu8; 32usize],
        vec![0x55u8; 128usize],
    ];

    for payload in patterns {
        let decoded = block_on(codec_roundtrip_response(BlockTxResponse::BatchData(
            payload.clone(),
        )))?;

        match decoded {
            BlockTxResponse::BatchData(bytes) => assert_eq!(bytes, payload),
            other => return Err(format!("unexpected response {other:?}")),
        }
    }

    Ok(())
}

#[test]
fn p2p_96_006_reqresp_load_roundtrip_512_small_index_requests() -> TestResult {
    let mut checked = 0usize;

    for index in 0u64..512u64 {
        assert_request_roundtrip(BlockTxRequest::GetBlockByIndex { index })?;

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "512 index request counter overflow".to_string())?;
    }

    assert_eq!(checked, 512usize);
    Ok(())
}

#[test]
fn p2p_97_006_reqresp_load_roundtrip_256_small_batch_responses() -> TestResult {
    let mut checked = 0usize;

    for value in 0u8..=255u8 {
        assert_response_roundtrip(BlockTxResponse::BatchData(vec![value; 4usize]))?;

        checked = checked
            .checked_add(1usize)
            .ok_or_else(|| "256 batch response counter overflow".to_string())?;
    }

    assert_eq!(checked, 256usize);
    Ok(())
}

#[test]
fn p2p_98_006_reqresp_adversarial_valid_invalid_valid_request_sequence_is_stateless() -> TestResult
{
    let valid_a = BlockTxRequest::GetBlockByIndex { index: 98u64 };
    let valid_b = BlockTxRequest::GetBatchByIndex { index: 99u64 };

    assert_request_roundtrip(valid_a)?;
    assert_request_codec_error(vec![1u8, 250u8])?;
    assert_request_roundtrip(valid_b)?;

    Ok(())
}

#[test]
fn p2p_99_006_reqresp_adversarial_valid_invalid_valid_response_sequence_is_stateless() -> TestResult
{
    let valid_a = BlockTxResponse::NotFound;
    let valid_b = BlockTxResponse::BatchData(vec![99u8; 8usize]);

    assert_response_roundtrip(valid_a)?;
    assert_response_codec_error(vec![1u8, 250u8])?;
    assert_response_roundtrip(valid_b)?;

    Ok(())
}

#[test]
fn p2p_100_006_reqresp_final_full_matrix_frames_are_stable_capped_and_roundtrip() -> TestResult {
    let mut checked_requests = 0usize;
    let mut checked_responses = 0usize;

    for request in make_all_requests() {
        let first = p2p_006_request_frame(&request)?;
        let second = p2p_006_request_frame(&request)?;
        let (declared_len, consumed) = p2p_006_decode_varint_prefix(&first)?;
        let payload_len = first
            .len()
            .checked_sub(consumed)
            .ok_or_else(|| "final request frame consumed overflow".to_string())?;

        assert_eq!(first, second);
        assert_eq!(declared_len, payload_len);
        assert!(payload_len <= BLOCKTX_TEST_MAX_WIRE_BYTES);
        assert_request_roundtrip(request)?;

        checked_requests = checked_requests
            .checked_add(1usize)
            .ok_or_else(|| "final request matrix counter overflow".to_string())?;
    }

    for response in make_all_responses()? {
        let first = p2p_006_response_frame(&response)?;
        let second = p2p_006_response_frame(&response)?;
        let (declared_len, consumed) = p2p_006_decode_varint_prefix(&first)?;
        let payload_len = first
            .len()
            .checked_sub(consumed)
            .ok_or_else(|| "final response frame consumed overflow".to_string())?;

        assert_eq!(first, second);
        assert_eq!(declared_len, payload_len);
        assert!(payload_len <= BLOCKTX_TEST_MAX_WIRE_BYTES);
        assert_response_roundtrip(response)?;

        checked_responses = checked_responses
            .checked_add(1usize)
            .ok_or_else(|| "final response matrix counter overflow".to_string())?;
    }

    assert_eq!(checked_requests, 5usize);
    assert_eq!(checked_responses, 4usize);
    Ok(())
}
