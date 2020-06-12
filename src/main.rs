use etherparse::InternetSlice;
use etherparse::SlicedPacket;
use etherparse::TransportSlice;
use pcap::Device;

fn parse_dns(payload: &[u8]) {
    print!("DNS Query: ");
    if let Ok(payload_string) = std::str::from_utf8(payload) {
        println!("{}", payload_string);
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
                // match slicedpacket.ip {
                //     None => println!("Missing IP slice"),
                //     Some(ip) => match ip {
                //         InternetSlice::Ipv4(ipheader) => println!(
                //             "{:?} --> {:?}",
                //             ipheader.source_addr(),
                //             ipheader.destination_addr()
                //         ),
                //         InternetSlice::Ipv6(ipheader, _ipheaderext) => println!(
                //             "{:?} --> {:?}",
                //             ipheader.source_addr(),
                //             ipheader.destination_addr()
                //         ),
                //     },
                // }
                match slicedpacket.transport {
                    None => println!("Missing transport data"),
                    Some(transport) => match transport {
                        TransportSlice::Udp(transportheader) => {
                            // println!(
                            //     "{} --> {}",
                            //     transportheader.source_port(),
                            //     transportheader.destination_port()
                            // );
                            if transportheader.destination_port() == 53 {
                                parse_dns(slicedpacket.payload);
                            }
                        }
                        TransportSlice::Tcp(transportheader) => {
                            // println!(
                            //     "{} --> {}",
                            //     transportheader.source_port(),
                            //     transportheader.destination_port()
                            // );
                            if transportheader.destination_port() == 53 {
                                parse_dns(slicedpacket.payload);
                            }
                        }
                    },
                }
            }
        }
    }
}
