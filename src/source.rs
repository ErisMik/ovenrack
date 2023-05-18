use log::*;

use std::net::UdpSocket;

use crate::cache::DnsCache;
use crate::dns;

pub struct SourceServer {
    addr: String,
    cache: DnsCache,
}

impl SourceServer {
    pub fn new<S: Into<String>>(addr: S, cache: DnsCache) -> Self {
        Self {
            addr: addr.into(),
            cache,
        }
    }

    pub fn start(&mut self) {
        info!("Binding to: {}", self.addr);
        let socket = UdpSocket::bind(self.addr.clone()).unwrap();

        loop {
            let mut buf = [0; 512];
            let (_number_of_bytes, src_addr) = socket.recv_from(&mut buf).unwrap();

            let dns_request = dns::DnsPacket::from_slice(&buf);
            if dns_request.header.isrequest() {
                let dns_response = self.cache.query(dns_request);
                socket.send_to(&dns_response.bytes(), src_addr).unwrap();
            }
        }
    }
}
