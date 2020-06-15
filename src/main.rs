extern crate rustls;

use byteorder::{ByteOrder, NetworkEndian};
use etherparse::{SlicedPacket, TransportSlice};
use io::{Read, Write};
use pcap::Device;
use std::io;
use std::sync::{Arc, Mutex};
use std::thread;
mod dns;

fn parse_dns(payload: &[u8]) -> dns::DnsPacket {
    let dns_packet = dns::DnsPacket::from_slice(payload);
    println!(
        "DNS id: {}, NAME: {}, TYPE {}, Q:{}, A:{}",
        dns_packet.header.id,
        dns_packet.question_section[0].name_string(),
        dns_packet.question_section[0].qtype,
        dns_packet.question_section.len(),
        dns_packet.answer_section.len()
    );
    return dns_packet;
}

fn main() {
    let packvec: Vec<dns::DnsPacket> = Vec::new();
    let packets = Arc::new(Mutex::new(packvec));

    let cap = thread::spawn({
        let cap_clone = Arc::clone(&packets);
        move || {
            match Device::lookup() {
                Ok(d) => println!("Using device: {}", d.name),
                Err(e) => println!("Error using device: {}", e),
            }

            let mut cap = Device::lookup().unwrap().open().unwrap();

            while let Ok(packet) = cap.next() {
                match SlicedPacket::from_ethernet(&packet.data) {
                    Err(value) => println!("Err {:?}", value),
                    Ok(slicedpacket) => {
                        if let Some(transport) = slicedpacket.transport {
                            match transport {
                                TransportSlice::Udp(transportheader) => {
                                    if transportheader.destination_port() == 53
                                        || transportheader.source_port() == 53
                                    {
                                        let mut v = cap_clone.lock().unwrap();
                                        v.push(parse_dns(slicedpacket.payload));
                                    }
                                }
                                TransportSlice::Tcp(_) => {} // Currently broken :(
                                                             // TransportSlice::Tcp(transportheader) => {
                                                             //     if transportheader.destination_port() == 53
                                                             //         || transportheader.source_port() == 53
                                                             //     {
                                                             //         let mut v = cap_clone.lock().unwrap();
                                                             //         v.push(parse_dns(slicedpacket.payload));
                                                             //     }
                                                             // }
                            };
                        }
                    }
                }
            }
        }
    });

    let fwd = thread::spawn({
        let fwd_clone = Arc::clone(&packets);
        move || loop {
            let mut v = fwd_clone.lock().unwrap();

            if v.len() > 0 {
                let mut dns_packet = v.pop().unwrap();
                if dns_packet.answer_section.len() == 0 {
                    print!("{} --> ", dns_packet.header.id);
                    dns_packet.header.id = dns_packet.header.id.wrapping_add(1);
                    println!("{}", dns_packet.header.id);

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
                    let dns_name =
                        webpki::DNSNameRef::try_from_ascii_str("dns.ericmikulin.ca").unwrap();
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
                                stream.read(&mut dns_buff).unwrap();
                                dns_vec.extend_from_slice(&dns_buff);
                            }

                            parse_dns(&dns_vec);
                        }
                        Err(e) => println!("Error fwding: {}", e),
                    }
                }
            }
        }
    });

    fwd.join().unwrap();
    cap.join().unwrap();
}
