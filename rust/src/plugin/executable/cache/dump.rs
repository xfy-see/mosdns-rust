// Copyright (C) 2020-2022, IrineSistiana
// SPDX-License-Identifier: GPL-3.0-or-later

//! mosdns v2 dump compatibility: a named gzip stream containing big-endian
//! eight-byte block lengths and the protobuf messages in cache/dump.proto.

use super::{Cache, Item, Key};
use anyhow::{bail, Context, Result};
use flate2::{read::MultiGzDecoder, Compression, GzBuilder};
use hickory_proto::op::Message;
use prost::Message as ProstMessage;
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const DUMP_HEADER: &[u8] = b"mosdns_cache_v2";
const BLOCK_SIZE: usize = 128;
const MAXIMUM_BLOCK_LENGTH: usize = 1 << 20;

#[derive(Clone, PartialEq, ProstMessage)]
struct CachedEntry {
    #[prost(bytes = "vec", tag = "1")]
    key: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    msg: Vec<u8>,
    #[prost(int64, tag = "3")]
    cache_expiration_time: i64,
    #[prost(int64, tag = "4")]
    msg_expiration_time: i64,
    #[prost(int64, tag = "5")]
    msg_stored_time: i64,
}

#[derive(Clone, PartialEq, ProstMessage)]
struct CacheDumpBlock {
    #[prost(message, repeated, tag = "1")]
    entries: Vec<CachedEntry>,
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

fn duration_between(later: i64, earlier: i64) -> Duration {
    Duration::from_secs(
        (i128::from(later) - i128::from(earlier)).clamp(0, i128::from(u64::MAX)) as u64,
    )
}

fn encode_key(key: &Key) -> Vec<u8> {
    let flags = u8::from(key.ad) | (u8::from(key.cd) << 1) | (u8::from(key.do_bit) << 2);
    // Go's getMsgKey writes byte(Qtype << 8), which is always zero, and does
    // not encode class. Preserve that layout for existing Go cache readers.
    let mut bytes = Vec::with_capacity(4 + key.name.len());
    bytes.extend_from_slice(&[flags, 0, key.typ as u8, key.name.len() as u8]);
    bytes.extend_from_slice(key.name.as_bytes());
    bytes
}

fn decode_key(bytes: &[u8], response: &Message) -> Option<Key> {
    if bytes.len() < 4 {
        return None;
    }
    let name = std::str::from_utf8(&bytes[4..]).ok()?.to_owned();
    let question = response.queries().first();
    let typ = question.map_or(u16::from_be_bytes([bytes[1], bytes[2]]), |question| {
        question.query_type().into()
    });
    let class = question.map_or(1, |question| question.query_class().into());
    Some(Key {
        name,
        typ,
        class,
        ad: bytes[0] & 1 != 0,
        cd: bytes[0] & 2 != 0,
        do_bit: bytes[0] & 4 != 0,
    })
}

impl Cache {
    pub fn dump_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.encode_dump()?.0)
    }

    fn encode_dump(&self) -> Result<(Vec<u8>, usize)> {
        let now = unix_now();
        let mut blocks = Vec::<CachedEntry>::new();
        {
            self.entries.range(|key, item, _| -> Result<()> {
                let age = item.stored.elapsed().saturating_add(item.age_offset);
                if age >= item.cache_ttl {
                    return Ok(());
                }
                let stored = now.saturating_sub(age.as_secs().min(i64::MAX as u64) as i64);
                blocks.push(CachedEntry {
                    key: encode_key(key),
                    msg: item
                        .response
                        .to_vec()
                        .context("encode cached DNS message")?,
                    cache_expiration_time: stored
                        .saturating_add(item.cache_ttl.as_secs().min(i64::MAX as u64) as i64),
                    msg_expiration_time: stored
                        .saturating_add(item.message_ttl.as_secs().min(i64::MAX as u64) as i64),
                    // The Go writer omitted this field. Populating it remains
                    // protobuf-compatible and keeps Go's imported TTL accurate.
                    msg_stored_time: stored,
                });
                Ok(())
            })?;
        }
        let entry_count = blocks.len();
        let mut writer = GzBuilder::new()
            .filename(DUMP_HEADER)
            .write(Vec::new(), Compression::fast());
        for entries in blocks.chunks(BLOCK_SIZE) {
            let data = CacheDumpBlock {
                entries: entries.to_vec(),
            }
            .encode_to_vec();
            if data.len() > MAXIMUM_BLOCK_LENGTH {
                bail!("cache dump block exceeds maximum length");
            }
            writer.write_all(&(data.len() as u64).to_be_bytes())?;
            writer.write_all(&data)?;
        }
        Ok((
            writer.finish().context("finish cache dump gzip stream")?,
            entry_count,
        ))
    }

    pub fn load_dump_bytes(&self, bytes: &[u8]) -> Result<usize> {
        let mut reader = MultiGzDecoder::new(bytes);
        if reader.header().and_then(|header| header.filename()) != Some(DUMP_HEADER) {
            bail!("invalid or old cache dump: expected gzip filename mosdns_cache_v2");
        }
        let now = unix_now();
        let mut count = 0;
        loop {
            let mut header = [0u8; 8];
            if reader
                .read(&mut header[..1])
                .context("read cache dump block header")?
                == 0
            {
                break;
            }
            reader
                .read_exact(&mut header[1..])
                .context("read complete cache dump block header")?;
            let length = u64::from_be_bytes(header);
            if length > MAXIMUM_BLOCK_LENGTH as u64 {
                bail!("invalid cache dump block length {length}");
            }
            let mut data = vec![0u8; length as usize];
            reader
                .read_exact(&mut data)
                .context("read cache dump block data")?;
            let block =
                CacheDumpBlock::decode(data.as_slice()).context("decode cache dump protobuf")?;
            count += block.entries.len();
            for entry in block.entries {
                let response =
                    Message::from_vec(&entry.msg).context("decode cache dump DNS message")?;
                // Go's backend discards expired entries on lookup; skip them at
                // import while returning the same decoded-entry count.
                if entry.cache_expiration_time <= now {
                    continue;
                }
                let Some(key) = decode_key(&entry.key, &response) else {
                    continue;
                };
                let item = Item {
                    response,
                    stored: Instant::now(),
                    // A Go dump without msg_stored_time means Unix epoch zero.
                    // This retains its existing TTL behavior without relying on
                    // subtracting an epoch-length duration from an Instant.
                    age_offset: duration_between(now, entry.msg_stored_time),
                    message_ttl: duration_between(entry.msg_expiration_time, entry.msg_stored_time),
                    cache_ttl: duration_between(entry.cache_expiration_time, entry.msg_stored_time),
                };
                let remaining = duration_between(entry.cache_expiration_time, now);
                let expiration = Instant::now()
                    .checked_add(remaining)
                    .context("cache dump expiration exceeds this platform's monotonic clock")?;
                self.entries
                    .store(key, std::sync::Arc::new(item), expiration);
            }
        }
        Ok(count)
    }

    pub fn load_dump<P: AsRef<Path>>(&self, path: P) -> Result<usize> {
        let path = path.as_ref();
        let bytes =
            fs::read(path).with_context(|| format!("read cache dump {}", path.display()))?;
        self.load_dump_bytes(&bytes)
    }

    pub fn save_dump<P: AsRef<Path>>(&self, path: P) -> Result<usize> {
        let path = path.as_ref();
        let (bytes, count) = self.encode_dump()?;
        fs::write(path, bytes).with_context(|| format!("write cache dump {}", path.display()))?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::query_context::{reply, QueryContext};
    use hickory_proto::{
        op::{Query, ResponseCode},
        rr::{
            rdata::{A, AAAA},
            Name, RData, Record, RecordType,
        },
    };

    fn contexts() -> Vec<(QueryContext, Message)> {
        [
            ("dump-a.test.", RecordType::A, true),
            ("dump-aaaa.test.", RecordType::AAAA, false),
            ("dump-negative.test.", RecordType::A, false),
        ]
        .into_iter()
        .map(|(name, typ, flags)| {
            let mut query = Message::new();
            query
                .set_id(123)
                .set_recursion_desired(true)
                .add_query(Query::query(Name::from_ascii(name).unwrap(), typ));
            let mut context = QueryContext::new(query, "127.0.0.1".parse().unwrap());
            context
                .query
                .set_authentic_data(flags)
                .set_checking_disabled(flags);
            context
                .query
                .extensions_mut()
                .as_mut()
                .unwrap()
                .set_dnssec_ok(flags);
            let mut response = reply(
                &context.query,
                if name == "dump-negative.test." {
                    ResponseCode::NXDomain
                } else {
                    ResponseCode::NoError
                },
            );
            let data = match typ {
                RecordType::A => RData::A(A("1.0.1.9".parse().unwrap())),
                _ => RData::AAAA(AAAA("2400:3200::9".parse().unwrap())),
            };
            if name != "dump-negative.test." {
                response.add_answer(Record::from_rdata(
                    Name::from_ascii(name).unwrap(),
                    300,
                    data,
                ));
            }
            (context, response)
        })
        .collect()
    }

    #[test]
    fn export_rust_cache_dump_interop_fixture() {
        let Some(path) = std::env::var_os("MOSDNS_EXPORT_RUST_DUMP") else {
            return;
        };
        let cache = Cache::new(32, 0);
        for (context, response) in contexts() {
            let key = Cache::key(&context).unwrap();
            cache.store(key.clone(), &response);
            let deadline = duration_between(4_102_444_800, unix_now());
            cache.update_for_test(&key, |item| {
                item.message_ttl = deadline;
                item.cache_ttl = deadline;
            });
        }
        assert_eq!(cache.save_dump(Path::new(&path)).unwrap(), 3);
    }

    #[test]
    fn imports_shared_go_and_rust_dump_fixtures_with_original_key_flags() {
        for (file, bytes) in [
            (
                "cache_go_v2.gz",
                include_bytes!("../../../../../tests/fixtures/cache_go_v2.gz").as_slice(),
            ),
            (
                "cache_rust_v2.gz",
                include_bytes!("../../../../../tests/fixtures/cache_rust_v2.gz").as_slice(),
            ),
        ] {
            let cache = Cache::new(32, 0);
            assert_eq!(cache.load_dump_bytes(bytes).unwrap(), 3, "{file}");
            for (context, expected) in contexts() {
                let key = Cache::key(&context).unwrap();
                let (response, lazy) = cache.lookup(&key);
                let response =
                    response.unwrap_or_else(|| panic!("{file}: {} cache miss", key.name));
                assert!(!lazy, "{file}: unexpected lazy cache hit");
                assert_eq!(
                    response.response_code(),
                    expected.response_code(),
                    "{file}: {}",
                    key.name
                );
                assert_eq!(response.answers().len(), expected.answers().len());
                for (answer, original) in response.answers().iter().zip(expected.answers()) {
                    assert_eq!(answer.data(), original.data(), "{file}: {}", key.name);
                    if file == "cache_go_v2.gz" {
                        assert_eq!(answer.ttl(), 1, "legacy Go writer omitted stored time");
                    } else {
                        let (item, _) = cache.entries.get(&key).unwrap();
                        let age = item.stored.elapsed().saturating_add(item.age_offset);
                        let expected_ttl =
                            original.ttl().saturating_sub(age.as_secs() as u32).max(1);
                        assert_eq!(answer.ttl(), expected_ttl);
                    }
                }
            }
        }
    }

    #[test]
    fn native_dump_roundtrip_preserves_answers_and_remaining_ttl() {
        let source = Cache::new(32, 0);
        let cases = contexts();
        for (context, response) in &cases {
            source.store(Cache::key(context).unwrap(), response);
        }
        let restored = Cache::new(32, 0);
        assert_eq!(
            restored
                .load_dump_bytes(&source.dump_bytes().unwrap())
                .unwrap(),
            3
        );
        for (context, expected) in cases {
            let (actual, lazy) = restored.lookup(&Cache::key(&context).unwrap());
            let actual = actual.unwrap();
            assert!(!lazy);
            assert_eq!(actual.response_code(), expected.response_code());
            for (answer, original) in actual.answers().iter().zip(expected.answers()) {
                assert_eq!(answer.data(), original.data());
                assert!((299..=300).contains(&answer.ttl()));
            }
        }
    }

    #[test]
    fn concatenated_gzip_members_match_go_multistream_reader() {
        let source = Cache::new(32, 0);
        for (context, response) in contexts() {
            source.store(Cache::key(&context).unwrap(), &response);
        }
        let member = source.dump_bytes().unwrap();
        let mut combined = member.clone();
        combined.extend_from_slice(&member);
        let restored = Cache::new(32, 0);
        assert_eq!(restored.load_dump_bytes(&combined).unwrap(), 6);
        assert_eq!(restored.stats().len, 3);
    }

    fn compressed(filename: &[u8], data: &[u8]) -> Vec<u8> {
        let mut encoder = GzBuilder::new()
            .filename(filename)
            .write(Vec::new(), Compression::fast());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn rejects_wrong_version_corrupt_blocks_and_gzip_checksum() {
        let cache = Cache::new(32, 0);
        assert!(cache.load_dump_bytes(b"not gzip").is_err());
        assert!(cache
            .load_dump_bytes(&compressed(b"mosdns_cache_v1", &[]))
            .is_err());
        assert!(cache
            .load_dump_bytes(&compressed(DUMP_HEADER, &[0, 0, 0]))
            .is_err());
        assert!(cache
            .load_dump_bytes(&compressed(
                DUMP_HEADER,
                &((MAXIMUM_BLOCK_LENGTH + 1) as u64).to_be_bytes()
            ))
            .is_err());
        let mut block = 3u64.to_be_bytes().to_vec();
        block.push(1);
        assert!(cache
            .load_dump_bytes(&compressed(DUMP_HEADER, &block))
            .is_err());
        let mut invalid = 1u64.to_be_bytes().to_vec();
        invalid.push(0xff);
        assert!(cache
            .load_dump_bytes(&compressed(DUMP_HEADER, &invalid))
            .is_err());
        let mut valid = cache.dump_bytes().unwrap();
        let checksum = valid.len() - 8;
        valid[checksum] ^= 1;
        assert!(cache.load_dump_bytes(&valid).is_err());
    }

    #[test]
    fn expired_entries_count_as_decoded_and_are_not_retained() {
        let cache = Cache::new(32, 0);
        let (context, response) = contexts().remove(0);
        let entry = CachedEntry {
            key: encode_key(&Cache::key(&context).unwrap()),
            msg: response.to_vec().unwrap(),
            cache_expiration_time: unix_now() - 1,
            msg_expiration_time: unix_now() - 1,
            msg_stored_time: unix_now() - 301,
        };
        let data = CacheDumpBlock {
            entries: vec![entry],
        }
        .encode_to_vec();
        let mut block = (data.len() as u64).to_be_bytes().to_vec();
        block.extend_from_slice(&data);
        assert_eq!(
            cache
                .load_dump_bytes(&compressed(DUMP_HEADER, &block))
                .unwrap(),
            1
        );
        assert_eq!(cache.stats().len, 0);
    }
    #[test]
    fn unrepresentable_import_deadline_returns_error_without_panicking() {
        let cache = Cache::new(32, 0);
        let (context, response) = contexts().remove(0);
        let data = CacheDumpBlock {
            entries: vec![CachedEntry {
                key: encode_key(&Cache::key(&context).unwrap()),
                msg: response.to_vec().unwrap(),
                cache_expiration_time: i64::MAX,
                msg_expiration_time: i64::MAX,
                msg_stored_time: 0,
            }],
        }
        .encode_to_vec();
        let mut block = (data.len() as u64).to_be_bytes().to_vec();
        block.extend_from_slice(&data);
        // Some monotonic clock implementations can represent this enormous
        // deadline. Only require rejection when this platform cannot.
        let remaining = duration_between(i64::MAX, unix_now());
        let result = cache.load_dump_bytes(&compressed(DUMP_HEADER, &block));
        if Instant::now().checked_add(remaining).is_none() {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), 1);
        }
    }
}
