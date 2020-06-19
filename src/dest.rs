use byteorder::{ByteOrder, NetworkEndian};
use crossbeam::crossbeam_channel;
use std::io::{Read, Write};
use std::net::IpAddr;

use super::dns;

const DEFAULT_DOT_PORT: u16 = 853;
const DEFAULT_DNS_PORT: u16 = 53;

pub struct DNSConfig {
    port: u16,
    address: IpAddr,
}

pub struct DOTConfig {
    port: u16,
    address: IpAddr,
    domain: Vec<u8>,
}

pub enum DestConfig {
    Dns(DNSConfig),
    Dot(DOTConfig),
    Stdout,
}

pub fn parse_args(matches: &clap::ArgMatches) -> DestConfig {
    let dest_string: String = match matches.value_of("dest") {
        Some(dest_str) => dest_str.to_string(),
        None => "".to_string(),
    };

    let is_tls = match dest_string.find("#") {
        Some(_) => true,
        None => false,
    };

    if dest_string == "-" {
        println!("STDOUT");
        return DestConfig::Stdout;
    } else if is_tls {
        println!("DoT");
        let dest_parts: Vec<&str> = dest_string.split('#').collect();
        let ip_addr: IpAddr = dest_parts[0].parse::<IpAddr>().unwrap();
        let hostname: String = dest_parts[1].to_string();

        let dns_config = DOTConfig {
            port: DEFAULT_DOT_PORT,
            address: ip_addr,
            domain: hostname.as_bytes().to_vec(),
        };
        return DestConfig::Dot(dns_config);
    } else {
        println!("DNS");
        let ip_addr = dest_string.parse::<IpAddr>().unwrap();
        let dns_config = DNSConfig {
            port: DEFAULT_DNS_PORT,
            address: ip_addr,
        };
        return DestConfig::Dns(dns_config);
    }
}

pub fn dest_loop(
    flag_input: crossbeam_channel::Receiver<bool>,
    inputs: Vec<crossbeam_channel::Receiver<dns::DnsPacket>>,
    outputs: Vec<crossbeam_channel::Sender<dns::DnsPacket>>,
    config: DestConfig,
) {
    match config {
        DestConfig::Dot(config) => dot_dest(flag_input, inputs, outputs, config),
        _ => println!("Not implemented yet."),
    }
}

pub fn dot_dest(
    flag_input: crossbeam_channel::Receiver<bool>,
    inputs: Vec<crossbeam_channel::Receiver<dns::DnsPacket>>,
    outputs: Vec<crossbeam_channel::Sender<dns::DnsPacket>>,
    dnsconfig: DOTConfig,
) {
    let hostname = std::str::from_utf8(&dnsconfig.domain).unwrap();
    let ip = {
        match dnsconfig.address {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => ip.to_string(),
        }
    };
    let tcp_connection_string = format!("{}:{}", ip, dnsconfig.port);

    loop {
        if let Ok(_) = flag_input.recv() {
            for input in &inputs {
                if let Ok(mut dns_packet) = input.try_recv() {
                    let previous_id = dns_packet.header.id;
                    println!("{} --> {}", previous_id, previous_id.wrapping_add(1));
                    dns_packet.header.id = dns_packet.header.id.wrapping_add(1);

                    let mut dns_payload: Vec<u8> = Vec::new();
                    let dns_len_u16: u16 = dns_packet.bytes().len() as u16;
                    let mut u16buf = [0; 2];
                    NetworkEndian::write_u16(&mut u16buf, dns_len_u16);
                    dns_payload.extend_from_slice(&u16buf);
                    dns_payload.extend(dns_packet.bytes().iter());

                    let mut socket = std::net::TcpStream::connect(&tcp_connection_string).unwrap();
                    let mut config = rustls::ClientConfig::new();
                    config
                        .root_store
                        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
                    let arc = std::sync::Arc::new(config);
                    let dns_name = webpki::DNSNameRef::try_from_ascii_str(hostname).unwrap();
                    let mut client = rustls::ClientSession::new(&arc, dns_name);
                    let mut stream = rustls::Stream::new(&mut client, &mut socket);

                    stream.write(&dns_payload).unwrap();

                    let mut len_buff: [u8; 2] = [0; 2];
                    match stream.read(&mut len_buff) {
                        Ok(_) => {
                            let reply_len = NetworkEndian::read_u16(&len_buff);

                            let mut dns_vec: Vec<u8> = Vec::new();
                            let mut dns_buff: [u8; 1] = [0; 1];
                            for _i in 0..reply_len {
                                if let Err(e) = stream.read(&mut dns_buff) {
                                    println!("Error fwding: {}", e);
                                    println!("{:?}", dns_packet);
                                    continue;
                                } else {
                                    dns_vec.extend_from_slice(&dns_buff);
                                }
                            }

                            if reply_len > 0 {
                                let dns_response_packet =
                                    dns::DnsPacket::from_slice_debug(&dns_vec);
                                for output in &outputs {
                                    let mut cloned_packet = dns_response_packet.clone();
                                    cloned_packet.header.id =
                                        cloned_packet.header.id.wrapping_sub(1);
                                    if let Ok(_) = output.send(cloned_packet) {};
                                }
                            }
                        }
                        Err(e) => {
                            println!("Error fwding: {}", e);
                            println!("{:?}", dns_packet);
                            continue;
                        }
                    }
                }
            }
        }
    }
}
