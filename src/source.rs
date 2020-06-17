use crossbeam::crossbeam_channel;
use etherparse::{SlicedPacket, TransportSlice};
use pcap::Device;

use super::dns;

pub struct SnoopConfig {
    pub port: u16,
}

pub fn snoop_source(
    output: crossbeam_channel::Sender<dns::DnsPacket>,
    input: crossbeam_channel::Receiver<dns::DnsPacket>,
    config: SnoopConfig,
) {
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
                            if transportheader.destination_port() == config.port
                                || transportheader.source_port() == config.port
                            {
                                let dns_packet =
                                    dns::DnsPacket::from_slice_debug(slicedpacket.payload);
                                if dns_packet.header.isrequest() == true {
                                    output.send(dns_packet).unwrap();
                                }
                            }
                        }
                        TransportSlice::Tcp(_) => {}
                    };
                }
            }
        }

        // Empty receive queue
        while !input.is_empty() {
            if let Ok(_) = input.try_recv() {};
        }
    }
}

fn serve_source<T>(_output: crossbeam_channel::Sender<T>, _input: crossbeam_channel::Receiver<T>) {}
