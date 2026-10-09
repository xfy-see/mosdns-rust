use crate::plugin::executable::stateful::unmap;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Mutex,
    time::{Duration, Instant},
};
struct Bucket {
    tokens: f64,
    last: Instant,
}
pub struct RateLimiter {
    qps: f64,
    burst: f64,
    mask4: u8,
    mask6: u8,
    clients: Mutex<HashMap<IpAddr, Bucket>>,
}
impl RateLimiter {
    pub fn new(qps: f64, burst: u32, mask4: u8, mask6: u8) -> Self {
        Self {
            qps,
            burst: f64::from(burst),
            mask4,
            mask6,
            clients: Mutex::new(HashMap::new()),
        }
    }
    pub fn allow(&self, ip: IpAddr) -> bool {
        let ip = match unmap(ip) {
            IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(
                u32::from(ip)
                    & if self.mask4 == 0 {
                        0
                    } else {
                        u32::MAX << (32 - self.mask4)
                    },
            )),
            IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(
                u128::from(ip)
                    & if self.mask6 == 0 {
                        0
                    } else {
                        u128::MAX << (128 - self.mask6)
                    },
            )),
        };
        let now = Instant::now();
        let mut clients = self.clients.lock().unwrap();
        if clients.len() > 1024 {
            clients.retain(|_, v| now.duration_since(v.last) < Duration::from_secs(300));
        }
        let b = clients.entry(ip).or_insert(Bucket {
            tokens: self.burst,
            last: now,
        });
        b.tokens = (b.tokens + now.duration_since(b.last).as_secs_f64() * self.qps).min(self.burst);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}
