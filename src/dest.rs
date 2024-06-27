use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::str::FromStr;
use std::sync::Arc;

use byteorder::{ByteOrder, NetworkEndian};
use log::*;
use rustls::*;

use crate::dns;

const DEFAULT_LOCAL_DNS_PORT: u16 = 5354;

const DEFAULT_DNS_PORT: u16 = 53;
const DEFAULT_DOT_PORT: u16 = 853;

trait DnsDest {
    fn query(&mut self, request: dns::DnsPacket) -> dns::DnsPacket;
}

struct DnsClient {
    local_socket: UdpSocket,
    remote_socket_addr: SocketAddr,
}

impl DnsClient {
    fn new<S: Into<String>>(addr: S) -> Self {
        let mut addr: String = addr.into();

        let local_socket_addr = format!("0.0.0.0:{DEFAULT_LOCAL_DNS_PORT}");
        let local_socket = UdpSocket::bind(&local_socket_addr).unwrap_or_else(|error| {
            panic!("Failed to bind UDP socket `{local_socket_addr}`: {error}",)
        });

        if addr.find(':').is_none() {
            addr.push_str(&format!(":{DEFAULT_DNS_PORT}"));
        }

        let remote_socket_addr = SocketAddr::from_str(&addr)
            .unwrap_or_else(|error| panic!("Failed parse socket address `{addr}`: {error}",));

        Self {
            local_socket,
            remote_socket_addr,
        }
    }
}

impl DnsDest for DnsClient {
    fn query(&mut self, request: dns::DnsPacket) -> dns::DnsPacket {
        self.local_socket
            .send_to(&request.bytes(), self.remote_socket_addr)
            .unwrap();

        let mut buf = [0; 512];
        let (_number_of_bytes, _src_addr) = self.local_socket.recv_from(&mut buf).unwrap();

        dns::DnsPacket::from_slice(&buf)
    }
}

struct DotClient {
    tls_stream: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
}

impl DotClient {
    fn new<S: AsRef<str>>(addr: S, hostname: S) -> Self {
        Self {
            tls_stream: Self::get_tls_connection(addr, hostname),
        }
    }

    fn get_tls_connection<S: AsRef<str>>(
        addr: S,
        hostname: S,
    ) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_name = String::from(hostname.as_ref())
            .try_into()
            .unwrap_or_else(|error| {
                panic!("Failed parse hostname `{}`: {error}", hostname.as_ref())
            });
        let conn = rustls::ClientConnection::new(Arc::new(config), server_name)
            .unwrap_or_else(|error| panic!("Failed to create TLS client connection: {error}"));

        let addr = format!("{}:{}", addr.as_ref(), DEFAULT_DOT_PORT);
        let sock = TcpStream::connect(&addr).unwrap_or_else(|error| {
            panic!("Failed to create TCP socket connection to `{addr}`: {error}")
        });

        rustls::StreamOwned::new(conn, sock)
    }
}

impl DnsDest for DotClient {
    fn query(&mut self, request: dns::DnsPacket) -> dns::DnsPacket {
        let mut request_payload: Vec<u8> = Vec::new();
        let dns_len_u16: u16 = request.bytes().len() as u16;
        let mut u16buf = [0; 2];
        NetworkEndian::write_u16(&mut u16buf, dns_len_u16);
        request_payload.extend_from_slice(&u16buf);
        request_payload.extend(request.bytes().iter());

        self.tls_stream.write_all(&request_payload).unwrap();

        let mut reply_len_buff: [u8; 2] = [0; 2];
        self.tls_stream.read_exact(&mut reply_len_buff).unwrap();
        let reply_len = NetworkEndian::read_u16(&reply_len_buff);

        let mut response_payload: Vec<u8> = vec![0u8; reply_len.into()];
        self.tls_stream.read_exact(&mut response_payload).unwrap();

        dns::DnsPacket::from_slice(&response_payload)
    }
}

struct DohClient {
    addr: String,
    client: reqwest::blocking::Client,
}

impl DohClient {
    fn new<S: Into<String>>(addr: S) -> Self {
        Self {
            addr: addr.into(),
            client: reqwest::blocking::Client::new(),
        }
    }
}

impl DnsDest for DohClient {
    fn query(&mut self, request: dns::DnsPacket) -> dns::DnsPacket {
        let https_response = self
            .client
            .post(&self.addr)
            .header(reqwest::header::ACCEPT, "application/dns-message")
            .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
            .body(request.bytes())
            .send()
            .unwrap();

        dns::DnsPacket::from_slice(&https_response.bytes().unwrap())
    }
}

pub struct DestClient {
    client: Box<dyn DnsDest>,
}

impl DestClient {
    pub fn new<S: Into<String>>(addr: S) -> Self {
        let addr: String = addr.into();
        let is_tls = addr.contains('#');
        let is_https = addr.contains("https://");

        if is_https {
            info!("Protocol: DoH");
            Self {
                client: Box::new(DohClient::new(addr)),
            }
        } else if is_tls {
            info!("Protocol: DoT");
            let addr_parts: Vec<&str> = addr.split('#').collect();
            let socket_addr = addr_parts[0].to_string();
            let hostname = addr_parts[1].to_string();

            Self {
                client: Box::new(DotClient::new(socket_addr, hostname)),
            }
        } else {
            info!("Protocol: DNS");
            Self {
                client: Box::new(DnsClient::new(addr)),
            }
        }
    }

    pub fn query(&mut self, request: dns::DnsPacket) -> dns::DnsPacket {
        let mut request = request;

        let previous_id = request.header.id;
        request.header.id = request.header.id.wrapping_add(1);
        info!(
            "Proxy query SEND: {} --> {}",
            previous_id, request.header.id
        );
        let mut response = self.client.query(request);

        if response.header.isrequest() {
            // TODO: handle error
            panic!();
        }

        let previous_id = response.header.id;
        response.header.id = response.header.id.wrapping_sub(1);
        info!(
            "Proxy query RECV: {} <-- {}",
            response.header.id, previous_id
        );

        response
    }
}
