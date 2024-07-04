use std::net::UdpSocket;

use log::*;
use retry::delay::Fixed;
use retry::*;

use crate::cache::DnsCacheManager;
use crate::dns;

pub struct SourceServer {
    addr: String,
    cache: DnsCacheManager,
}

impl SourceServer {
    pub fn new<S: Into<String>>(addr: S, cache: DnsCacheManager) -> Self {
        Self {
            addr: addr.into(),
            cache,
        }
    }

    pub fn start(&mut self) {
        info!("Binding to: {}", self.addr);
        let socket = UdpSocket::bind(self.addr.clone())
            .unwrap_or_else(|error| panic!("Failed to bind UDP socket `{}`: {error}", self.addr));

        loop {
            let mut buf = [0; 512];
            let (_number_of_bytes, src_addr) = match socket.recv_from(&mut buf) {
                Ok(data) => data,
                Err(error) => {
                    error!("Failed to receive data from socket: {error}");
                    continue;
                }
            };

            let dns_request = dns::DnsPacket::from_slice(&buf);
            if dns_request.header.isrequest() {
                let dns_response = self.cache.query(dns_request);
                if let Err(error) = retry(Fixed::from_millis(25).take(3), || {
                    socket.send_to(&dns_response.bytes(), src_addr)
                }) {
                    error!("Failed to send data from socket (tried 3 times): {error}");
                }
            }
        }
    }
}
