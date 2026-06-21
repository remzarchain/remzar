// tests/proptests_p2p_006_reqresp.rs

use futures::executor::block_on;
use futures::io::Cursor;
use libp2p::request_response::Codec;
use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use fips204::ml_dsa_65;

use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::network::p2p_006_reqresp::{
    BlockTxCodec, BlockTxProtocol, BlockTxRequest, BlockTxResponse, Hash,
};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

const BLOCKTX_MAX_WIRE_BYTES: usize = 2 * 1024 * 1024;

fn wallet_with_prefix(prefix: char, tail_127: &str) -> String {
    format!("r{prefix}{tail_127}")
}

fn valid_transfer(sender_tail: &str, receiver_tail: &str, amount: u64) -> Transaction {
    let sender = wallet_with_prefix('0', sender_tail);
    let receiver = wallet_with_prefix('1', receiver_tail);

    Transaction::new(sender, receiver, amount).expect("generated valid transfer should construct")
}

fn encode_varint_u32(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();

    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;

        if value == 0 {
            out.push(byte);
            return out;
        }

        byte |= 0x80;
        out.push(byte);
    }
}

fn decode_varint_prefix(bytes: &[u8]) -> std::io::Result<(usize, usize)> {
    let mut value = 0u32;
    let mut shift = 0u32;

    for (index, byte) in bytes.iter().copied().enumerate() {
        value |= u32::from(byte & 0x7F) << shift;

        if byte & 0x80 == 0 {
            let len = usize::try_from(value).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "varint length overflow")
            })?;
            return Ok((len, index + 1));
        }

        shift = shift.saturating_add(7);
        if shift >= 32 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
    }

    Err(std::io::ErrorKind::UnexpectedEof.into())
}

fn frame_payload(payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("test payload length must fit u32");
    let mut out = encode_varint_u32(len);
    out.extend_from_slice(payload);
    out
}

fn codec_roundtrip_request(req: BlockTxRequest) -> std::io::Result<BlockTxRequest> {
    let mut codec = BlockTxCodec::default();
    let protocol = BlockTxProtocol;

    let mut writer = Cursor::new(Vec::<u8>::new());
    block_on(codec.write_request(&protocol, &mut writer, req))?;

    let bytes = writer.into_inner();
    let mut reader = Cursor::new(bytes);

    block_on(codec.read_request(&protocol, &mut reader))
}

fn codec_roundtrip_response(resp: BlockTxResponse) -> std::io::Result<BlockTxResponse> {
    let mut codec = BlockTxCodec::default();
    let protocol = BlockTxProtocol;

    let mut writer = Cursor::new(Vec::<u8>::new());
    block_on(codec.write_response(&protocol, &mut writer, resp))?;

    let bytes = writer.into_inner();
    let mut reader = Cursor::new(bytes);

    block_on(codec.read_response(&protocol, &mut reader))
}

fn patterned_hash(seed: u8) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut value = seed;

    for byte in &mut out {
        value = value.wrapping_mul(31).wrapping_add(17);
        *byte = value;
    }

    if out == [0u8; 64] {
        out[63] = 1;
    }

    out
}

fn nonzero_signature(seed: u8) -> [u8; ml_dsa_65::SIG_LEN] {
    let mut sig = [0u8; ml_dsa_65::SIG_LEN];
    let mut value = seed;

    for byte in &mut sig {
        value = value.wrapping_add(1);
        *byte = value.max(1);
    }

    sig
}

fn valid_metadata(index: u64, seed: u8) -> BlockMetadata {
    BlockMetadata::new(
        index,
        GlobalConfiguration::MIN_TIMESTAMP_SECS
            .saturating_add(GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS)
            .saturating_add(index),
        patterned_hash(seed),
        patterned_hash(seed.wrapping_add(1)),
        nonzero_signature(seed.wrapping_add(2)),
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    )
}

fn valid_block(index: u64, seed: u8, miner_tail: &str, reward: u64) -> Block {
    Block::new(
        valid_metadata(index.max(1), seed),
        Some(format!("batch_{seed}_{reward}")),
        wallet_with_prefix('2', miner_tail),
        reward,
    )
    .expect("generated valid block should construct")
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_protocol_name_is_stable(_probe in any::<u8>()) {
        let protocol = BlockTxProtocol;

        prop_assert_eq!(
            protocol.as_ref(),
            "/remzar/blocktx/1.0.0",
            "protocol name must remain stable for network compatibility"
        );
    }

    // 02/25
    #[test]
    fn test_002_hash_request_variants_roundtrip_and_preserve_full_64_byte_hash(
        hash in any::<Hash>(),
    ) {
        let requests = vec![
            BlockTxRequest::GetBlock { hash },
            BlockTxRequest::GetTx { hash },
            BlockTxRequest::GetBatchByHash { hash },
        ];

        for req in requests {
            let decoded = codec_roundtrip_request(req.clone())
                .expect("hash request should codec roundtrip");

            prop_assert_eq!(
                &decoded,
                &req,
                "request codec roundtrip must preserve request variant and 64-byte hash"
            );

            match &decoded {
                BlockTxRequest::GetBlock { hash }
                | BlockTxRequest::GetTx { hash }
                | BlockTxRequest::GetBatchByHash { hash } => {
                    prop_assert_eq!(
                        hash.len(),
                        64,
                        "network hash width must remain 64 bytes"
                    );
                }
                _ => unreachable!("test only generates hash request variants"),
            }
        }
    }

    // 03/25
    #[test]
    fn test_003_index_request_variants_roundtrip_and_preserve_u64_index(
        index in any::<u64>(),
    ) {
        let block_req = BlockTxRequest::GetBlockByIndex { index };
        let batch_req = BlockTxRequest::GetBatchByIndex { index };

        let decoded_block = codec_roundtrip_request(block_req.clone())
            .expect("GetBlockByIndex should codec roundtrip");

        let decoded_batch = codec_roundtrip_request(batch_req.clone())
            .expect("GetBatchByIndex should codec roundtrip");

        prop_assert_eq!(
            decoded_block,
            block_req,
            "GetBlockByIndex must preserve full u64 index"
        );

        prop_assert_eq!(
            decoded_batch,
            batch_req,
            "GetBatchByIndex must preserve full u64 index"
        );
    }

    // 04/25
    #[test]
    fn test_004_small_batch_response_and_notfound_roundtrip(
        payload in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let batch = BlockTxResponse::BatchData(payload.clone());
        let decoded_batch = codec_roundtrip_response(batch.clone())
            .expect("small BatchData response should codec roundtrip");

        prop_assert_eq!(
            decoded_batch,
            batch,
            "BatchData response codec roundtrip must preserve bytes"
        );

        let not_found = BlockTxResponse::NotFound;
        let decoded_not_found = codec_roundtrip_response(not_found.clone())
            .expect("NotFound response should codec roundtrip");

        prop_assert_eq!(
            decoded_not_found,
            not_found,
            "NotFound response codec roundtrip must preserve variant"
        );
    }

    // 05/25
    #[test]
    fn test_005_txdata_response_roundtrip_preserves_transaction(
        sender_tail in "[0-9a-f]{127}",
        receiver_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let tx = valid_transfer(&sender_tail, &receiver_tail, amount);
        let response = BlockTxResponse::TxData(Box::new(tx.clone()));

        let decoded = codec_roundtrip_response(response.clone())
            .expect("TxData response should codec roundtrip");

        prop_assert_eq!(
            &decoded,
            &response,
            "TxData response codec roundtrip must preserve transaction"
        );

        match decoded {
            BlockTxResponse::TxData(decoded_tx) => {
                prop_assert_eq!(
                    *decoded_tx,
                    tx,
                    "decoded TxData transaction must equal original"
                );
            }
            _ => unreachable!("decoded response must be TxData"),
        }
    }

    // 06/25
    #[test]
    fn test_006_request_variant_serialization_is_distinct_for_same_hash_or_index(
        hash in any::<Hash>(),
        index in any::<u64>(),
    ) {
        let requests = vec![
            BlockTxRequest::GetBlock { hash },
            BlockTxRequest::GetTx { hash },
            BlockTxRequest::GetBatchByHash { hash },
            BlockTxRequest::GetBlockByIndex { index },
            BlockTxRequest::GetBatchByIndex { index },
        ];

        let mut encoded = std::collections::BTreeSet::new();

        for req in requests {
            let bytes = postcard::to_stdvec(&req)
                .expect("request should serialize");

            prop_assert!(
                encoded.insert(bytes),
                "each request variant must have distinct postcard bytes"
            );
        }

        prop_assert_eq!(
            encoded.len(),
            5,
            "all five request variants must be wire-distinct"
        );
    }

    // 07/25
    #[test]
    fn test_007_response_variant_serialization_is_distinct_for_known_values(
        sender_tail in "[0-9a-f]{127}",
        receiver_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let tx = valid_transfer(&sender_tail, &receiver_tail, amount);

        let responses = vec![
            BlockTxResponse::NotFound,
            BlockTxResponse::BatchData(Vec::new()),
            BlockTxResponse::BatchData(vec![1, 2, 3, 4]),
            BlockTxResponse::TxData(Box::new(tx)),
        ];

        let mut encoded = std::collections::BTreeSet::new();

        for resp in responses {
            let bytes = postcard::to_stdvec(&resp)
                .expect("response should serialize");

            prop_assert!(
                encoded.insert(bytes),
                "known response variants/values must have distinct postcard bytes"
            );
        }

        prop_assert_eq!(
            encoded.len(),
            4,
            "known response variants/values must be wire-distinct"
        );
    }

    // 08/25
    #[test]
    fn test_008_read_request_rejects_empty_frame_truncated_frame_and_declared_oversize(
        req_hash in any::<Hash>(),
        keep_seed in any::<usize>(),
    ) {
        let req = BlockTxRequest::GetBlock { hash: req_hash };

        let mut codec = BlockTxCodec::default();
        let protocol = BlockTxProtocol;

        let empty = Vec::<u8>::new();
        let mut empty_reader = Cursor::new(empty);

        prop_assert!(
            block_on(codec.read_request(&protocol, &mut empty_reader)).is_err(),
            "read_request must reject empty input"
        );

        let mut writer = Cursor::new(Vec::<u8>::new());
        block_on(codec.write_request(&protocol, &mut writer, req))
            .expect("valid request should write");

        let bytes = writer.into_inner();

        prop_assume!(!bytes.is_empty());

        let keep_len = keep_seed % bytes.len();
        let truncated = bytes[..keep_len].to_vec();

        let mut truncated_reader = Cursor::new(truncated);

        prop_assert!(
            block_on(codec.read_request(&protocol, &mut truncated_reader)).is_err(),
            "read_request must reject truncated frame"
        );

        let oversized_len = u32::try_from(BLOCKTX_MAX_WIRE_BYTES)
            .expect("wire cap fits u32")
            .saturating_add(1);

        let oversized_frame = encode_varint_u32(oversized_len);
        let mut oversized_reader = Cursor::new(oversized_frame);

        prop_assert!(
            block_on(codec.read_request(&protocol, &mut oversized_reader)).is_err(),
            "read_request must reject declared length above wire cap before payload allocation"
        );
    }

    // 09/25
    #[test]
    fn test_009_read_response_rejects_empty_frame_truncated_frame_and_declared_oversize(
        payload in proptest::collection::vec(any::<u8>(), 0..4096),
        keep_seed in any::<usize>(),
    ) {
        let response = BlockTxResponse::BatchData(payload);

        let mut codec = BlockTxCodec::default();
        let protocol = BlockTxProtocol;

        let empty = Vec::<u8>::new();
        let mut empty_reader = Cursor::new(empty);

        prop_assert!(
            block_on(codec.read_response(&protocol, &mut empty_reader)).is_err(),
            "read_response must reject empty input"
        );

        let mut writer = Cursor::new(Vec::<u8>::new());
        block_on(codec.write_response(&protocol, &mut writer, response))
            .expect("valid response should write");

        let bytes = writer.into_inner();

        prop_assume!(!bytes.is_empty());

        let keep_len = keep_seed % bytes.len();
        let truncated = bytes[..keep_len].to_vec();

        let mut truncated_reader = Cursor::new(truncated);

        prop_assert!(
            block_on(codec.read_response(&protocol, &mut truncated_reader)).is_err(),
            "read_response must reject truncated frame"
        );

        let oversized_len = u32::try_from(BLOCKTX_MAX_WIRE_BYTES)
            .expect("wire cap fits u32")
            .saturating_add(1);

        let oversized_frame = encode_varint_u32(oversized_len);
        let mut oversized_reader = Cursor::new(oversized_frame);

        prop_assert!(
            block_on(codec.read_response(&protocol, &mut oversized_reader)).is_err(),
            "read_response must reject declared length above wire cap before payload allocation"
        );
    }

    // 10/25
    #[test]
    fn test_010_read_request_rejects_overlong_varint_prefix(
        continuation_count in 5usize..16usize,
    ) {
        let mut frame = vec![0x80u8; continuation_count];
        frame.push(0x00);

        let mut codec = BlockTxCodec::default();
        let protocol = BlockTxProtocol;
        let mut reader = Cursor::new(frame);

        prop_assert!(
            block_on(codec.read_request(&protocol, &mut reader)).is_err(),
            "read_request must reject overlong u32 varint prefixes"
        );
    }

    // 11/25
    #[test]
    fn test_011_read_response_rejects_overlong_varint_prefix(
        continuation_count in 5usize..16usize,
    ) {
        let mut frame = vec![0x80u8; continuation_count];
        frame.push(0x00);

        let mut codec = BlockTxCodec::default();
        let protocol = BlockTxProtocol;
        let mut reader = Cursor::new(frame);

        prop_assert!(
            block_on(codec.read_response(&protocol, &mut reader)).is_err(),
            "read_response must reject overlong u32 varint prefixes"
        );
    }

    // 12/25
    #[test]
    fn test_012_write_response_rejects_oversized_batchdata_payload(
        extra in 1usize..64usize,
    ) {
        let payload_len = BLOCKTX_MAX_WIRE_BYTES.saturating_add(extra);
        let response = BlockTxResponse::BatchData(vec![7u8; payload_len]);

        let mut codec = BlockTxCodec::default();
        let protocol = BlockTxProtocol;
        let mut writer = Cursor::new(Vec::<u8>::new());

        prop_assert!(
            block_on(codec.write_response(&protocol, &mut writer, response)).is_err(),
            "write_response must reject oversized BatchData payloads"
        );
    }

    // 13/25
    #[test]
    fn test_013_read_request_rejects_nonzero_trailing_bytes_inside_declared_frame(
        hash in any::<Hash>(),
        extra in proptest::collection::vec(1u8..=255u8, 1..16),
    ) {
        let req = BlockTxRequest::GetBlock { hash };

        let mut payload = postcard::to_stdvec(&req)
            .expect("request should serialize");
        payload.extend_from_slice(&extra);

        let frame = frame_payload(&payload);

        let mut codec = BlockTxCodec::default();
        let protocol = BlockTxProtocol;
        let mut reader = Cursor::new(frame);

        prop_assert!(
            block_on(codec.read_request(&protocol, &mut reader)).is_err(),
            "read_request must reject postcard payloads with nonzero trailing bytes inside the declared frame"
        );
    }

    // 14/25
    #[test]
    fn test_014_read_response_rejects_nonzero_trailing_bytes_inside_declared_frame(
        payload in proptest::collection::vec(any::<u8>(), 0..4096),
        extra in proptest::collection::vec(1u8..=255u8, 1..16),
    ) {
        let response = BlockTxResponse::BatchData(payload);

        let mut encoded = postcard::to_stdvec(&response)
            .expect("response should serialize");
        encoded.extend_from_slice(&extra);

        let frame = frame_payload(&encoded);

        let mut codec = BlockTxCodec::default();
        let protocol = BlockTxProtocol;
        let mut reader = Cursor::new(frame);

        prop_assert!(
            block_on(codec.read_response(&protocol, &mut reader)).is_err(),
            "read_response must reject postcard payloads with nonzero trailing bytes inside the declared frame"
        );
    }

    // 15/25
    #[test]
    fn test_015_zero_length_batchdata_roundtrips_but_zero_length_request_frame_does_not_decode(
        hash in any::<Hash>(),
    ) {
        let response = BlockTxResponse::BatchData(Vec::new());

        let decoded = codec_roundtrip_response(response.clone())
            .expect("empty BatchData response should roundtrip as a valid response");

        prop_assert_eq!(
            decoded,
            response,
            "empty BatchData is a valid response payload"
        );

        let zero_len_frame = encode_varint_u32(0);

        let mut codec = BlockTxCodec::default();
        let protocol = BlockTxProtocol;
        let mut reader = Cursor::new(zero_len_frame);

        prop_assert!(
            block_on(codec.read_request(&protocol, &mut reader)).is_err(),
            "declared zero-length request frame must not decode as a valid request"
        );

        let request = BlockTxRequest::GetTx { hash };
        let decoded_request = codec_roundtrip_request(request.clone())
            .expect("normal request should still roundtrip");

        prop_assert_eq!(
            decoded_request,
            request,
            "normal request roundtrip should be unaffected"
        );
    }

    // 16/25
    #[test]
    fn test_016_read_request_rejects_zero_trailing_bytes_inside_declared_frame(
        hash in any::<Hash>(),
        extra_len in 1usize..16usize,
    ) {
        let req = BlockTxRequest::GetBlock { hash };

        let mut payload = postcard::to_stdvec(&req)
            .expect("request should serialize");
        payload.extend(vec![0u8; extra_len]);

        let frame = frame_payload(&payload);

        let mut codec = BlockTxCodec::default();
        let protocol = BlockTxProtocol;
        let mut reader = Cursor::new(frame);

        prop_assert!(
            block_on(codec.read_request(&protocol, &mut reader)).is_err(),
            "read_request must reject zero trailing bytes after a valid postcard payload"
        );
    }

    // 17/25
    #[test]
    fn test_017_read_response_rejects_zero_trailing_bytes_inside_declared_frame(
        payload in proptest::collection::vec(any::<u8>(), 0..4096),
        extra_len in 1usize..16usize,
    ) {
        let response = BlockTxResponse::BatchData(payload);

        let mut encoded = postcard::to_stdvec(&response)
            .expect("response should serialize");
        encoded.extend(vec![0u8; extra_len]);

        let frame = frame_payload(&encoded);

        let mut codec = BlockTxCodec::default();
        let protocol = BlockTxProtocol;
        let mut reader = Cursor::new(frame);

        prop_assert!(
            block_on(codec.read_response(&protocol, &mut reader)).is_err(),
            "read_response must reject zero trailing bytes after a valid postcard payload"
        );
    }

    // 18/25
    #[test]
    fn test_018_write_request_length_prefix_matches_exact_postcard_payload(
        hash in any::<Hash>(),
        index in any::<u64>(),
        variant in 0usize..5usize,
    ) {
        let req = match variant {
            0 => BlockTxRequest::GetBlock { hash },
            1 => BlockTxRequest::GetTx { hash },
            2 => BlockTxRequest::GetBlockByIndex { index },
            3 => BlockTxRequest::GetBatchByIndex { index },
            _ => BlockTxRequest::GetBatchByHash { hash },
        };

        let expected_payload = postcard::to_stdvec(&req)
            .expect("request should serialize directly");

        let mut codec = BlockTxCodec::default();
        let protocol = BlockTxProtocol;
        let mut writer = Cursor::new(Vec::<u8>::new());

        block_on(codec.write_request(&protocol, &mut writer, req))
            .expect("write_request should succeed");

        let written = writer.into_inner();
        let (declared_len, prefix_len) = decode_varint_prefix(&written)
            .expect("written request must start with valid varint length");

        prop_assert_eq!(
            declared_len,
            expected_payload.len(),
            "request frame length prefix must equal postcard payload length"
        );

        prop_assert_eq!(
            &written[prefix_len..],
            expected_payload.as_slice(),
            "request frame payload must be exact postcard bytes"
        );
    }

    // 19/25
    #[test]
    fn test_019_write_response_length_prefix_matches_exact_postcard_payload(
        payload in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let response = BlockTxResponse::BatchData(payload);

        let expected_payload = postcard::to_stdvec(&response)
            .expect("response should serialize directly");

        let mut codec = BlockTxCodec::default();
        let protocol = BlockTxProtocol;
        let mut writer = Cursor::new(Vec::<u8>::new());

        block_on(codec.write_response(&protocol, &mut writer, response))
            .expect("write_response should succeed");

        let written = writer.into_inner();
        let (declared_len, prefix_len) = decode_varint_prefix(&written)
            .expect("written response must start with valid varint length");

        prop_assert_eq!(
            declared_len,
            expected_payload.len(),
            "response frame length prefix must equal postcard payload length"
        );

        prop_assert_eq!(
            &written[prefix_len..],
            expected_payload.as_slice(),
            "response frame payload must be exact postcard bytes"
        );
    }

    // 20/25
    #[test]
    fn test_020_blockdata_response_roundtrip_preserves_full_block(
        miner_tail in "[0-9a-f]{127}",
        index in 1u64..=10_000u64,
        seed in any::<u8>(),
        reward in any::<u64>(),
    ) {
        let block = valid_block(index, seed, &miner_tail, reward);
        let response = BlockTxResponse::BlockData(Box::new(block.clone()));

        let decoded = codec_roundtrip_response(response.clone())
            .expect("BlockData response should codec roundtrip");

        prop_assert_eq!(
            &decoded,
            &response,
            "BlockData response codec roundtrip must preserve full block"
        );

        match decoded {
            BlockTxResponse::BlockData(decoded_block) => {
                prop_assert_eq!(
                    decoded_block.as_ref(),
                    &block,
                    "decoded BlockData block must equal original"
                );

                prop_assert!(
                    decoded_block
                        .verify_block_hash()
                        .expect("decoded block hash verification should run"),
                    "decoded BlockData block must preserve valid block hash"
                );
            }
            _ => unreachable!("decoded response must be BlockData"),
        }
    }

    // 21/25
    #[test]
    fn test_021_read_request_never_panics_for_arbitrary_external_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut codec = BlockTxCodec::default();
            let protocol = BlockTxProtocol;
            let mut reader = Cursor::new(data);

            block_on(codec.read_request(&protocol, &mut reader))
        }));

        prop_assert!(
            result.is_ok(),
            "read_request must never panic for arbitrary external bytes"
        );
    }

    // 22/25
    #[test]
    fn test_022_read_response_never_panics_for_arbitrary_external_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut codec = BlockTxCodec::default();
            let protocol = BlockTxProtocol;
            let mut reader = Cursor::new(data);

            block_on(codec.read_response(&protocol, &mut reader))
        }));

        prop_assert!(
            result.is_ok(),
            "read_response must never panic for arbitrary external bytes"
        );
    }

    // 23/25
    #[test]
    fn test_023_write_request_never_panics_and_succeeds_for_all_request_variants(
        hash in any::<Hash>(),
        index in any::<u64>(),
    ) {
        let requests = vec![
            BlockTxRequest::GetBlock { hash },
            BlockTxRequest::GetTx { hash },
            BlockTxRequest::GetBlockByIndex { index },
            BlockTxRequest::GetBatchByIndex { index },
            BlockTxRequest::GetBatchByHash { hash },
        ];

        for req in requests {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut codec = BlockTxCodec::default();
                let protocol = BlockTxProtocol;
                let mut writer = Cursor::new(Vec::<u8>::new());

                block_on(codec.write_request(&protocol, &mut writer, req))
            }));

            prop_assert!(
                result.is_ok(),
                "write_request must never panic for valid request variants"
            );

            prop_assert!(
                result.expect("panic was already checked").is_ok(),
                "write_request must succeed for valid request variants"
            );
        }
    }

    // 24/25
    #[test]
    fn test_024_write_response_never_panics_and_succeeds_for_small_response_variants(
        sender_tail in "[0-9a-f]{127}",
        receiver_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
        payload in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let tx = valid_transfer(&sender_tail, &receiver_tail, amount);

        let responses = vec![
            BlockTxResponse::NotFound,
            BlockTxResponse::BatchData(payload),
            BlockTxResponse::TxData(Box::new(tx)),
        ];

        for response in responses {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut codec = BlockTxCodec::default();
                let protocol = BlockTxProtocol;
                let mut writer = Cursor::new(Vec::<u8>::new());

                block_on(codec.write_response(&protocol, &mut writer, response))
            }));

            prop_assert!(
                result.is_ok(),
                "write_response must never panic for small valid response variants"
            );

            prop_assert!(
                result.expect("panic was already checked").is_ok(),
                "write_response must succeed for small valid response variants"
            );
        }
    }

    // 25/25
    #[test]
    fn test_025_zero_length_response_frame_does_not_decode(
        payload in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let zero_len_frame = encode_varint_u32(0);

        let mut codec = BlockTxCodec::default();
        let protocol = BlockTxProtocol;
        let mut reader = Cursor::new(zero_len_frame);

        prop_assert!(
            block_on(codec.read_response(&protocol, &mut reader)).is_err(),
            "declared zero-length response frame must not decode as a valid response"
        );

        let response = BlockTxResponse::BatchData(payload);
        let decoded = codec_roundtrip_response(response.clone())
            .expect("normal response should still roundtrip");

        prop_assert_eq!(
            decoded,
            response,
            "normal response roundtrip should be unaffected"
        );
    }
}
