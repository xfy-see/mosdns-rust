// SPDX-License-Identifier: GPL-3.0-or-later
//! Go-compatible master-file records, retained in original order.
mod generate;
mod rdata;
mod zone;
pub use zone::parse_zone;
#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::RData;
    #[test]
    fn defaults_soa_ttl_txt_and_multiline_origin() {
        let records=parse_zone("$ORIGIN example.org.\n@ 17 IN SOA ns.example.org. host.example.org. ( 42 10 20 30 40 )\nwww IN A 192.0.2.1\n  IN AAAA 2001:db8::1\n$TTL 99\ntxt IN TXT \"a b; (c)\" \"\" ; comment\n").unwrap();
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].ttl(), 17);
        assert_eq!(records[1].ttl(), 17);
        assert_eq!(records[2].name().to_ascii(), "www.example.org.");
        assert_eq!(records[3].ttl(), 99);
        match records[3].data().unwrap() {
            RData::TXT(txt) => assert_eq!(
                txt.txt_data()
                    .iter()
                    .map(|s| s.as_ref())
                    .collect::<Vec<&[u8]>>(),
                vec![b"a b; (c)".as_slice(), b"".as_slice()]
            ),
            _ => panic!(),
        }
    }
}
