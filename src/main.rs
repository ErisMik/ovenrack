extern crate rustls;

use byteorder::{ByteOrder, NetworkEndian};
use clap::{App, Arg};
use crossbeam::crossbeam_channel;
use etherparse::{SlicedPacket, TransportSlice};
use io::{Read, Write};
use pcap::Device;
use std::io;
use std::thread;

mod dns;

fn parse_dns(payload: &[u8]) -> dns::DnsPacket {
    let dns_packet = dns::DnsPacket::from_slice(payload);
    println!(
        "DNS id: {}, NAME: {}, TYPE {}, Q:{}, A:{}, NS:{}, AR:{}",
        dns_packet.header.id,
        dns_packet.question_section[0].name_string(),
        dns_packet.question_section[0].qtype,
        dns_packet.header.qdcount,
        dns_packet.header.ancount,
        dns_packet.header.nscount,
        dns_packet.header.arcount,
    );
    return dns_packet;
}

fn main() {
    let matches = App::new("Ovenrack")
        .version("0.1.0")
        .author("Eric M. <ericm99@gmail.com>")
        .about("Keeps your pi(e)S warm!")
        .arg(Arg::with_name("verbose").short("v").help("Verbose output"))
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("PORT")
                .help("Port to serve at if serving, or snoop at if snooping")
                .default_value("53")
                .takes_value(true),
        )
        .arg(Arg::with_name("tls").short("t").help("Tunnel over TLS"))
        .arg(
            Arg::with_name("serve")
                .short("s")
                .long("serve")
                .value_name("ADDRESS")
                .help("Act as a DNS server instead of snooping DNS requests")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("dev")
                .short("d")
                .long("dev")
                .value_name("DEVICE")
                .help("Device to snoop on, defaults to first device")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("DEST")
                .help(
                    "Destination for recived or snooped requests. Not specifying outputs to stdout",
                )
                .required(false)
                .index(1),
        )
        .get_matches();

    let port: u16 = matches.value_of("port").unwrap().parse::<u16>().unwrap();

    let (s, r) = crossbeam_channel::unbounded();

    let cap = thread::spawn({
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
                                    if transportheader.destination_port() == port
                                        || transportheader.source_port() == port
                                    {
                                        let dns_packet = parse_dns(slicedpacket.payload);
                                        if dns_packet.header.isrequest() == true {
                                            s.send(dns_packet).unwrap();
                                        }
                                    }
                                }
                                TransportSlice::Tcp(_) => {}
                            };
                        }
                    }
                }
            }
        }
    });

    let fwd = thread::spawn({
        move || loop {
            if let Ok(mut dns_packet) = r.recv() {
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
                            if let Err(e) = stream.read(&mut dns_buff) {
                                println!("Error fwding: {}", e);
                                println!("{:?}", dns_packet);
                                continue;
                            } else {
                                dns_vec.extend_from_slice(&dns_buff);
                            }
                        }

                        parse_dns(&dns_vec);
                    }
                    Err(e) => {
                        println!("Error fwding: {}", e);
                        println!("{:?}", dns_packet);
                        continue;
                    }
                }
            }
        }
    });

    fwd.join().unwrap();
    cap.join().unwrap();
}
