use etherparse::{SlicedPacket, TransportSlice};
use pcap::Device;
mod dns;

fn parse_dns(payload: &[u8]) {
    let dns_packet = dns::DnsPacket::from_slice(payload);
    println!("{:?}", dns_packet);
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
