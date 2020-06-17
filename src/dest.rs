use byteorder::{ByteOrder, NetworkEndian};
use crossbeam::crossbeam_channel;
use std::io::{Read, Write};

use super::dns;

pub fn dot_dest(
    inputs: Vec<crossbeam_channel::Receiver<dns::DnsPacket>>,
    outputs: Vec<crossbeam_channel::Sender<dns::DnsPacket>>,
) {
    loop {
        if let Ok(mut dns_packet) = inputs[0].recv() {
            let previous_id = dns_packet.header.id;
            println!("{} --> {}", previous_id, previous_id.wrapping_add(1));
            dns_packet.header.id = dns_packet.header.id.wrapping_add(1);

            let mut dns_payload: Vec<u8> = Vec::new();
            let dns_len_u16: u16 = dns_packet.bytes().len() as u16;
            let mut u16buf = [0; 2];
            NetworkEndian::write_u16(&mut u16buf, dns_len_u16);
            dns_payload.extend_from_slice(&u16buf);
            dns_payload.extend(dns_packet.bytes().iter());

            let mut socket = std::net::TcpStream::connect("45.33.36.222:853").unwrap();
            let mut config = rustls::ClientConfig::new();
            config
                .root_store
                .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
            let arc = std::sync::Arc::new(config);
            let dns_name = webpki::DNSNameRef::try_from_ascii_str("dns.ericmikulin.ca").unwrap();
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

                    let dns_response_packet = dns::DnsPacket::from_slice_debug(&dns_vec);
                    for output in &outputs {
                        let cloned_packet = dns_response_packet.clone();
                        output.send(cloned_packet);
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
