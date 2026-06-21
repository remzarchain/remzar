#![cfg(test)]
#![deny(unsafe_code)]

use futures::io::Cursor;
use libp2p::request_response::Codec;
use remzar::{
    blockchain::transaction_001_tx::Transaction,
    network::p2p_006_reqresp::{
        BlockTxCodec, BlockTxProtocol, BlockTxRequest, BlockTxResponse, Hash,
        build_blocktx_exchange,
    },
};
use std::{io::ErrorKind, time::Duration};
use tokio::time::timeout;

type TestResult<T = ()> = Result<T, String>;

const BLOCKTX_MAX_WIRE_BYTES_FOR_TEST: usize = 2 * 1024 * 1024;

fn fmt_err<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn hash(seed: u8) -> Hash {
    let mut out = [0u8; 64];

    for (idx, byte) in out.iter_mut().enumerate() {
        let i = u8::try_from(idx).unwrap_or(0);
        *byte = seed
            .wrapping_add(i.wrapping_mul(31))
            .wrapping_add(7)
            .rotate_left(u32::from(i % 7));
    }

    out
}

fn wallet(ch: char) -> String {
    format!("r{}", ch.to_string().repeat(128))
}

fn valid_tx() -> TestResult<Transaction> {
    Transaction::new(wallet('1'), wallet('2'), 1).map_err(fmt_err)
}

fn encode_varint_u32_for_test(mut val: u32) -> Vec<u8> {
    let mut out = Vec::new();

    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;

        if val == 0 {
            out.push(byte);
            break;
        }

        byte |= 0x80;
        out.push(byte);
    }

    out
}

fn invalid_varint_too_long_for_test() -> Vec<u8> {
    vec![0x80, 0x80, 0x80, 0x80, 0x80]
}

async fn write_request_wire(req: BlockTxRequest) -> std::io::Result<Vec<u8>> {
    let mut codec = BlockTxCodec;
    let protocol = BlockTxProtocol;
    let mut io = Cursor::new(Vec::<u8>::new());

    codec.write_request(&protocol, &mut io, req).await?;

    Ok(io.into_inner())
}

async fn read_request_wire(bytes: Vec<u8>) -> std::io::Result<BlockTxRequest> {
    let mut codec = BlockTxCodec;
    let protocol = BlockTxProtocol;
    let mut io = Cursor::new(bytes);

    codec.read_request(&protocol, &mut io).await
}

async fn write_response_wire(resp: BlockTxResponse) -> std::io::Result<Vec<u8>> {
    let mut codec = BlockTxCodec;
    let protocol = BlockTxProtocol;
    let mut io = Cursor::new(Vec::<u8>::new());

    codec.write_response(&protocol, &mut io, resp).await?;

    Ok(io.into_inner())
}

async fn read_response_wire(bytes: Vec<u8>) -> std::io::Result<BlockTxResponse> {
    let mut codec = BlockTxCodec;
    let protocol = BlockTxProtocol;
    let mut io = Cursor::new(bytes);

    codec.read_response(&protocol, &mut io).await
}

fn postcard_request_payload(req: &BlockTxRequest) -> TestResult<Vec<u8>> {
    postcard::to_allocvec(req).map_err(fmt_err)
}

fn postcard_response_payload(resp: &BlockTxResponse) -> TestResult<Vec<u8>> {
    postcard::to_allocvec(resp).map_err(fmt_err)
}

fn wire_with_declared_payload(mut payload: Vec<u8>) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let mut out = encode_varint_u32_for_test(len);
    out.append(&mut payload);
    out
}

#[test]
fn e2e_01_protocol_name_is_stable() -> TestResult {
    let protocol = BlockTxProtocol;

    assert_eq!(protocol.as_ref(), "/remzar/blocktx/1.0.0");

    Ok(())
}

#[test]
fn e2e_02_hash_helper_width_is_64_bytes() -> TestResult {
    let h = hash(2);

    assert_eq!(h.len(), 64);
    assert_ne!(h, [0u8; 64]);

    Ok(())
}

#[test]
fn e2e_03_get_block_request_clone_and_equality() -> TestResult {
    let req = BlockTxRequest::GetBlock { hash: hash(3) };
    let cloned = req.clone();

    assert_eq!(cloned, req);

    Ok(())
}

#[test]
fn e2e_04_get_tx_request_clone_and_equality() -> TestResult {
    let req = BlockTxRequest::GetTx { hash: hash(4) };
    let cloned = req.clone();

    assert_eq!(cloned, req);

    Ok(())
}

#[test]
fn e2e_05_get_block_by_index_request_clone_and_equality() -> TestResult {
    let req = BlockTxRequest::GetBlockByIndex { index: 5 };
    let cloned = req.clone();

    assert_eq!(cloned, req);

    Ok(())
}

#[test]
fn e2e_06_get_batch_by_index_request_clone_and_equality() -> TestResult {
    let req = BlockTxRequest::GetBatchByIndex { index: 6 };
    let cloned = req.clone();

    assert_eq!(cloned, req);

    Ok(())
}

#[test]
fn e2e_07_get_batch_by_hash_request_clone_and_equality() -> TestResult {
    let req = BlockTxRequest::GetBatchByHash { hash: hash(7) };
    let cloned = req.clone();

    assert_eq!(cloned, req);

    Ok(())
}

#[test]
fn e2e_08_notfound_response_clone_and_equality() -> TestResult {
    let resp = BlockTxResponse::NotFound;
    let cloned = resp.clone();

    assert_eq!(cloned, resp);

    Ok(())
}

#[test]
fn e2e_09_batchdata_response_clone_and_equality() -> TestResult {
    let resp = BlockTxResponse::BatchData(vec![1, 2, 3, 4, 5]);
    let cloned = resp.clone();

    assert_eq!(cloned, resp);

    Ok(())
}

#[test]
fn e2e_10_txdata_response_clone_and_equality() -> TestResult {
    let tx = valid_tx()?;
    let resp = BlockTxResponse::TxData(Box::new(tx));
    let cloned = resp.clone();

    assert_eq!(cloned, resp);

    Ok(())
}

#[test]
fn e2e_11_build_blocktx_exchange_can_be_constructed() -> TestResult {
    let _rr = build_blocktx_exchange();

    Ok(())
}

#[test]
fn e2e_12_build_blocktx_exchange_can_be_constructed_repeatedly() -> TestResult {
    for _ in 0usize..16usize {
        let _rr = build_blocktx_exchange();
    }

    Ok(())
}

#[tokio::test]
async fn e2e_13_codec_roundtrips_get_block_request() -> TestResult {
    let req = BlockTxRequest::GetBlock { hash: hash(13) };

    let wire = write_request_wire(req.clone()).await.map_err(fmt_err)?;
    let decoded = read_request_wire(wire).await.map_err(fmt_err)?;

    assert_eq!(decoded, req);

    Ok(())
}

#[tokio::test]
async fn e2e_14_codec_roundtrips_get_tx_request() -> TestResult {
    let req = BlockTxRequest::GetTx { hash: hash(14) };

    let wire = write_request_wire(req.clone()).await.map_err(fmt_err)?;
    let decoded = read_request_wire(wire).await.map_err(fmt_err)?;

    assert_eq!(decoded, req);

    Ok(())
}

#[tokio::test]
async fn e2e_15_codec_roundtrips_get_block_by_index_zero() -> TestResult {
    let req = BlockTxRequest::GetBlockByIndex { index: 0 };

    let wire = write_request_wire(req.clone()).await.map_err(fmt_err)?;
    let decoded = read_request_wire(wire).await.map_err(fmt_err)?;

    assert_eq!(decoded, req);

    Ok(())
}

#[tokio::test]
async fn e2e_16_codec_roundtrips_get_block_by_index_large() -> TestResult {
    let req = BlockTxRequest::GetBlockByIndex { index: u64::MAX };

    let wire = write_request_wire(req.clone()).await.map_err(fmt_err)?;
    let decoded = read_request_wire(wire).await.map_err(fmt_err)?;

    assert_eq!(decoded, req);

    Ok(())
}

#[tokio::test]
async fn e2e_17_codec_roundtrips_get_batch_by_index_zero() -> TestResult {
    let req = BlockTxRequest::GetBatchByIndex { index: 0 };

    let wire = write_request_wire(req.clone()).await.map_err(fmt_err)?;
    let decoded = read_request_wire(wire).await.map_err(fmt_err)?;

    assert_eq!(decoded, req);

    Ok(())
}

#[tokio::test]
async fn e2e_18_codec_roundtrips_get_batch_by_index_large() -> TestResult {
    let req = BlockTxRequest::GetBatchByIndex { index: u64::MAX };

    let wire = write_request_wire(req.clone()).await.map_err(fmt_err)?;
    let decoded = read_request_wire(wire).await.map_err(fmt_err)?;

    assert_eq!(decoded, req);

    Ok(())
}

#[tokio::test]
async fn e2e_19_codec_roundtrips_get_batch_by_hash_request() -> TestResult {
    let req = BlockTxRequest::GetBatchByHash { hash: hash(19) };

    let wire = write_request_wire(req.clone()).await.map_err(fmt_err)?;
    let decoded = read_request_wire(wire).await.map_err(fmt_err)?;

    assert_eq!(decoded, req);

    Ok(())
}

#[tokio::test]
async fn e2e_20_codec_roundtrips_notfound_response() -> TestResult {
    let resp = BlockTxResponse::NotFound;

    let wire = write_response_wire(resp.clone()).await.map_err(fmt_err)?;
    let decoded = read_response_wire(wire).await.map_err(fmt_err)?;

    assert_eq!(decoded, resp);

    Ok(())
}

#[tokio::test]
async fn e2e_21_codec_roundtrips_empty_batchdata_response() -> TestResult {
    let resp = BlockTxResponse::BatchData(Vec::new());

    let wire = write_response_wire(resp.clone()).await.map_err(fmt_err)?;
    let decoded = read_response_wire(wire).await.map_err(fmt_err)?;

    assert_eq!(decoded, resp);

    Ok(())
}

#[tokio::test]
async fn e2e_22_codec_roundtrips_small_batchdata_response() -> TestResult {
    let resp = BlockTxResponse::BatchData(vec![22u8; 256]);

    let wire = write_response_wire(resp.clone()).await.map_err(fmt_err)?;
    let decoded = read_response_wire(wire).await.map_err(fmt_err)?;

    assert_eq!(decoded, resp);

    Ok(())
}

#[tokio::test]
async fn e2e_23_codec_roundtrips_large_batchdata_response_under_wire_cap() -> TestResult {
    let resp = BlockTxResponse::BatchData(vec![23u8; 64 * 1024]);

    let wire = write_response_wire(resp.clone()).await.map_err(fmt_err)?;
    let decoded = read_response_wire(wire).await.map_err(fmt_err)?;

    assert_eq!(decoded, resp);

    Ok(())
}

#[tokio::test]
async fn e2e_24_codec_roundtrips_txdata_response() -> TestResult {
    let resp = BlockTxResponse::TxData(Box::new(valid_tx()?));

    let wire = write_response_wire(resp.clone()).await.map_err(fmt_err)?;
    let decoded = read_response_wire(wire).await.map_err(fmt_err)?;

    assert_eq!(decoded, resp);

    Ok(())
}

#[tokio::test]
async fn e2e_25_request_wire_has_nonempty_length_prefix_and_payload() -> TestResult {
    let req = BlockTxRequest::GetTx { hash: hash(25) };

    let wire = write_request_wire(req).await.map_err(fmt_err)?;

    assert!(wire.len() > 1);

    Ok(())
}

#[tokio::test]
async fn e2e_26_response_wire_has_nonempty_length_prefix_and_payload() -> TestResult {
    let resp = BlockTxResponse::NotFound;

    let wire = write_response_wire(resp).await.map_err(fmt_err)?;

    assert!(wire.len() > 1);

    Ok(())
}

#[tokio::test]
async fn e2e_27_read_request_rejects_empty_wire() -> TestResult {
    let err = read_request_wire(Vec::new())
        .await
        .expect_err("empty request wire must fail");

    assert_eq!(err.kind(), ErrorKind::UnexpectedEof);

    Ok(())
}

#[tokio::test]
async fn e2e_28_read_response_rejects_empty_wire() -> TestResult {
    let err = read_response_wire(Vec::new())
        .await
        .expect_err("empty response wire must fail");

    assert_eq!(err.kind(), ErrorKind::UnexpectedEof);

    Ok(())
}

#[tokio::test]
async fn e2e_29_read_request_rejects_invalid_varint() -> TestResult {
    let err = read_request_wire(invalid_varint_too_long_for_test())
        .await
        .expect_err("invalid varint must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);

    Ok(())
}

#[tokio::test]
async fn e2e_30_read_response_rejects_invalid_varint() -> TestResult {
    let err = read_response_wire(invalid_varint_too_long_for_test())
        .await
        .expect_err("invalid varint must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);

    Ok(())
}

#[tokio::test]
async fn e2e_31_read_request_rejects_truncated_payload() -> TestResult {
    let mut wire = encode_varint_u32_for_test(10);
    wire.extend_from_slice(&[1, 2, 3]);

    let err = read_request_wire(wire)
        .await
        .expect_err("truncated request payload must fail");

    assert_eq!(err.kind(), ErrorKind::UnexpectedEof);

    Ok(())
}

#[tokio::test]
async fn e2e_32_read_response_rejects_truncated_payload() -> TestResult {
    let mut wire = encode_varint_u32_for_test(10);
    wire.extend_from_slice(&[1, 2, 3]);

    let err = read_response_wire(wire)
        .await
        .expect_err("truncated response payload must fail");

    assert_eq!(err.kind(), ErrorKind::UnexpectedEof);

    Ok(())
}

#[tokio::test]
async fn e2e_33_read_request_rejects_malformed_postcard_payload() -> TestResult {
    let wire = wire_with_declared_payload(vec![0xff, 0xee, 0xdd, 0xcc]);

    let err = read_request_wire(wire)
        .await
        .expect_err("malformed request postcard must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);

    Ok(())
}

#[tokio::test]
async fn e2e_34_read_response_rejects_malformed_postcard_payload() -> TestResult {
    let wire = wire_with_declared_payload(vec![0xff, 0xee, 0xdd, 0xcc]);

    let err = read_response_wire(wire)
        .await
        .expect_err("malformed response postcard must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);

    Ok(())
}

#[tokio::test]
async fn e2e_35_read_request_rejects_trailing_bytes_after_postcard_payload() -> TestResult {
    let req = BlockTxRequest::GetBlockByIndex { index: 35 };
    let mut payload = postcard_request_payload(&req)?;
    payload.extend_from_slice(&[0xaa, 0xbb, 0xcc]);

    let wire = wire_with_declared_payload(payload);

    let err = read_request_wire(wire)
        .await
        .expect_err("request trailing bytes must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);

    Ok(())
}

#[tokio::test]
async fn e2e_36_read_response_rejects_trailing_bytes_after_postcard_payload() -> TestResult {
    let resp = BlockTxResponse::NotFound;
    let mut payload = postcard_response_payload(&resp)?;
    payload.extend_from_slice(&[0xaa, 0xbb, 0xcc]);

    let wire = wire_with_declared_payload(payload);

    let err = read_response_wire(wire)
        .await
        .expect_err("response trailing bytes must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);

    Ok(())
}

#[tokio::test]
async fn e2e_37_read_request_rejects_oversized_declared_length_before_payload_read() -> TestResult {
    let oversized = u32::try_from(BLOCKTX_MAX_WIRE_BYTES_FOR_TEST + 1).map_err(fmt_err)?;
    let wire = encode_varint_u32_for_test(oversized);

    let err = read_request_wire(wire)
        .await
        .expect_err("oversized request length must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("wire message too large"));

    Ok(())
}

#[tokio::test]
async fn e2e_38_read_response_rejects_oversized_declared_length_before_payload_read() -> TestResult
{
    let oversized = u32::try_from(BLOCKTX_MAX_WIRE_BYTES_FOR_TEST + 1).map_err(fmt_err)?;
    let wire = encode_varint_u32_for_test(oversized);

    let err = read_response_wire(wire)
        .await
        .expect_err("oversized response length must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("wire message too large"));

    Ok(())
}

#[tokio::test]
async fn e2e_39_write_response_rejects_batchdata_over_wire_cap() -> TestResult {
    let resp = BlockTxResponse::BatchData(vec![0x39; BLOCKTX_MAX_WIRE_BYTES_FOR_TEST + 1]);

    let err = write_response_wire(resp)
        .await
        .expect_err("oversized response must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("wire message too large to send"));

    Ok(())
}

#[tokio::test]
async fn e2e_40_write_response_allows_large_batchdata_under_wire_cap() -> TestResult {
    let resp = BlockTxResponse::BatchData(vec![0x40; 128 * 1024]);

    let wire = write_response_wire(resp.clone()).await.map_err(fmt_err)?;
    let decoded = read_response_wire(wire).await.map_err(fmt_err)?;

    assert_eq!(decoded, resp);

    Ok(())
}

#[tokio::test]
async fn e2e_41_request_postcard_roundtrip_get_block() -> TestResult {
    let req = BlockTxRequest::GetBlock { hash: hash(41) };

    let encoded = postcard_request_payload(&req)?;
    let decoded: BlockTxRequest = postcard::from_bytes(&encoded).map_err(fmt_err)?;

    assert_eq!(decoded, req);

    Ok(())
}

#[tokio::test]
async fn e2e_42_request_postcard_roundtrip_get_tx() -> TestResult {
    let req = BlockTxRequest::GetTx { hash: hash(42) };

    let encoded = postcard_request_payload(&req)?;
    let decoded: BlockTxRequest = postcard::from_bytes(&encoded).map_err(fmt_err)?;

    assert_eq!(decoded, req);

    Ok(())
}

#[tokio::test]
async fn e2e_43_request_postcard_roundtrip_get_block_by_index() -> TestResult {
    let req = BlockTxRequest::GetBlockByIndex { index: 43 };

    let encoded = postcard_request_payload(&req)?;
    let decoded: BlockTxRequest = postcard::from_bytes(&encoded).map_err(fmt_err)?;

    assert_eq!(decoded, req);

    Ok(())
}

#[tokio::test]
async fn e2e_44_request_postcard_roundtrip_get_batch_by_index() -> TestResult {
    let req = BlockTxRequest::GetBatchByIndex { index: 44 };

    let encoded = postcard_request_payload(&req)?;
    let decoded: BlockTxRequest = postcard::from_bytes(&encoded).map_err(fmt_err)?;

    assert_eq!(decoded, req);

    Ok(())
}

#[tokio::test]
async fn e2e_45_request_postcard_roundtrip_get_batch_by_hash() -> TestResult {
    let req = BlockTxRequest::GetBatchByHash { hash: hash(45) };

    let encoded = postcard_request_payload(&req)?;
    let decoded: BlockTxRequest = postcard::from_bytes(&encoded).map_err(fmt_err)?;

    assert_eq!(decoded, req);

    Ok(())
}

#[tokio::test]
async fn e2e_46_response_postcard_roundtrip_notfound() -> TestResult {
    let resp = BlockTxResponse::NotFound;

    let encoded = postcard_response_payload(&resp)?;
    let decoded: BlockTxResponse = postcard::from_bytes(&encoded).map_err(fmt_err)?;

    assert_eq!(decoded, resp);

    Ok(())
}

#[tokio::test]
async fn e2e_47_response_postcard_roundtrip_batchdata() -> TestResult {
    let resp = BlockTxResponse::BatchData(vec![47u8; 1024]);

    let encoded = postcard_response_payload(&resp)?;
    let decoded: BlockTxResponse = postcard::from_bytes(&encoded).map_err(fmt_err)?;

    assert_eq!(decoded, resp);

    Ok(())
}

#[tokio::test]
async fn e2e_48_response_postcard_roundtrip_txdata() -> TestResult {
    let resp = BlockTxResponse::TxData(Box::new(valid_tx()?));

    let encoded = postcard_response_payload(&resp)?;
    let decoded: BlockTxResponse = postcard::from_bytes(&encoded).map_err(fmt_err)?;

    assert_eq!(decoded, resp);

    Ok(())
}

#[tokio::test]
async fn e2e_49_codec_large_batch_roundtrip_completes_before_timeout() -> TestResult {
    let resp = BlockTxResponse::BatchData(vec![0x49; 256 * 1024]);

    timeout(Duration::from_secs(2), async {
        let wire = write_response_wire(resp.clone()).await.map_err(fmt_err)?;
        let decoded = read_response_wire(wire).await.map_err(fmt_err)?;

        if decoded != resp {
            return Err("decoded large batch response mismatch".to_string());
        }

        Ok::<(), String>(())
    })
    .await
    .map_err(|_| "large batch codec roundtrip timed out".to_string())??;

    Ok(())
}

#[tokio::test]
async fn e2e_50_full_reqresp_codec_lifecycle_all_request_variants_and_core_responses() -> TestResult
{
    let requests = vec![
        BlockTxRequest::GetBlock { hash: hash(50) },
        BlockTxRequest::GetTx { hash: hash(51) },
        BlockTxRequest::GetBlockByIndex { index: 0 },
        BlockTxRequest::GetBlockByIndex { index: u64::MAX },
        BlockTxRequest::GetBatchByIndex { index: 0 },
        BlockTxRequest::GetBatchByIndex { index: u64::MAX },
        BlockTxRequest::GetBatchByHash { hash: hash(52) },
    ];

    for req in requests {
        let wire = write_request_wire(req.clone()).await.map_err(fmt_err)?;
        let decoded = read_request_wire(wire).await.map_err(fmt_err)?;
        assert_eq!(decoded, req);
    }

    let responses = vec![
        BlockTxResponse::NotFound,
        BlockTxResponse::BatchData(Vec::new()),
        BlockTxResponse::BatchData(vec![0x50; 4096]),
        BlockTxResponse::TxData(Box::new(valid_tx()?)),
    ];

    for resp in responses {
        let wire = write_response_wire(resp.clone()).await.map_err(fmt_err)?;
        let decoded = read_response_wire(wire).await.map_err(fmt_err)?;
        assert_eq!(decoded, resp);
    }

    Ok(())
}
