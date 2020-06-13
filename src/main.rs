use byteorder::{ByteOrder, NetworkEndian};
use etherparse::{SlicedPacket, TransportSlice};
use pcap::Device;
use std::net::{Ipv4Addr, Ipv6Addr};

// struct DnsQuestion {
//     qname_raw: Vec<u8>,
//     qname: Vec<Vec<char>>,
//     qtype: u16,
//     qclass: u16,
// }

struct DnsHeader {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

fn parse_dns(payload: &[u8]) {
    let dns_header = DnsHeader {
        id: NetworkEndian::read_u16(&payload[0..2]),
        flags: NetworkEndian::read_u16(&payload[2..4]),
        qdcount: NetworkEndian::read_u16(&payload[4..6]),
        ancount: NetworkEndian::read_u16(&payload[6..8]),
        nscount: NetworkEndian::read_u16(&payload[8..10]),
        arcount: NetworkEndian::read_u16(&payload[10..12]),
    };

    let mut payload_offset = 12;

    let mut dns_questions = 0;
    while dns_questions < dns_header.qdcount {
        print!("Question for: {} ", dns_header.id);

        loop {
            let qname_field_len = payload[payload_offset];
            payload_offset += 1;

            if qname_field_len == 0 {
                break;
            }

            let payload_offset_end = payload_offset + qname_field_len as usize;
            let qname_field =
                std::str::from_utf8(&payload[payload_offset..payload_offset_end]).unwrap();
            payload_offset = payload_offset_end;
            print!("{}.", qname_field);
        }

        let mut payload_offset_end = payload_offset + 2;
        print!(
            " type: {}",
            NetworkEndian::read_u16(&payload[payload_offset..payload_offset_end])
        );
        payload_offset = payload_offset_end;

        payload_offset_end += 2;
        print!(
            " class: {}",
            NetworkEndian::read_u16(&payload[payload_offset..payload_offset_end])
        );
        payload_offset = payload_offset_end;

        dns_questions += 1;
        println!(";");
    }

    let mut dns_answers = 0;
    while dns_answers < dns_header.ancount {
        print!("Answer for: {} ", dns_header.id);

        loop {
            let qname_field_len = payload[payload_offset];
            payload_offset += 1;

            if qname_field_len == 0 {
                break;
            } else if qname_field_len == 192 {
                payload_offset += 1;
                print!("PTR");
                break;
            }

            let payload_offset_end = payload_offset + qname_field_len as usize;
            let qname_field =
                std::str::from_utf8(&payload[payload_offset..payload_offset_end]).unwrap();
            payload_offset = payload_offset_end;
            print!("{}.", qname_field);
        }

        let mut payload_offset_end = payload_offset + 2;
        let rtype = NetworkEndian::read_u16(&payload[payload_offset..payload_offset_end]);
        print!(" type: {}", rtype);
        payload_offset = payload_offset_end;

        payload_offset_end += 2;
        print!(
            " class: {}",
            NetworkEndian::read_u16(&payload[payload_offset..payload_offset_end])
        );
        payload_offset = payload_offset_end;

        payload_offset_end += 4;
        print!(
            " ttl: {}",
            NetworkEndian::read_u16(&payload[payload_offset..payload_offset_end])
        );
        payload_offset = payload_offset_end;

        payload_offset_end += 2;
        let rdlen = NetworkEndian::read_u16(&payload[payload_offset..payload_offset_end]);
        print!(" len: {}", rdlen);
        payload_offset = payload_offset_end;

        payload_offset_end += rdlen as usize;
        if rtype == 1 || rtype == 28 {  // A, AAAA
            print!(" data: {:?}", &payload[payload_offset..payload_offset_end]);
        }
        payload_offset = payload_offset_end;

        dns_answers += 1;
        println!(";");
    }
}

fn main() {
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
                                parse_dns(slicedpacket.payload);
                            }
                        }
                        TransportSlice::Tcp(transportheader) => {
                            if transportheader.destination_port() == 53
                                || transportheader.source_port() == 53
                            {
                                parse_dns(slicedpacket.payload);
                            }
                        }
                    };
                }
            }
        }
    }
}
