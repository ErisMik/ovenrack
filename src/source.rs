use clap;
use crossbeam::crossbeam_channel;
use etherparse::{SlicedPacket, TransportSlice};
use pcap::Device;
use std::net::{IpAddr, UdpSocket};

use super::dns;

pub struct ServeConfig {
    pub port: u16,
    pub address: IpAddr,
}

pub struct SnoopConfig {
    pub port: u16,
    pub device: pcap::Device,
}

pub enum SourceConfig {
    Snoop(SnoopConfig),
    Serve(ServeConfig),
    Stdin,
}

fn get_device_from_name(name: &str) -> Result<pcap::Device, pcap::Error> {
    for dev in Device::list()? {
        if dev.name == name {
            return Ok(dev);
        }
    }
    
    println!("Device {} not found, using default", name);
    return Ok(Device::lookup()?);
}

pub fn parse_args(matches: &clap::ArgMatches) -> SourceConfig {
    let port: u16 = matches.value_of("port").unwrap().parse::<u16>().unwrap();

    let src_string: String = match matches.value_of("source") {
        Some(src_str) => src_str.to_string(),
        None => "".to_string(),
    };

    if src_string == "-" {
        println!("STDIN");
        return SourceConfig::Stdin;
    } else if let Ok(ip_addr) = src_string.parse::<IpAddr>() {
        println!("SERVE");
        let serve_config = ServeConfig {
            port: port,
            address: ip_addr,
        };
        return SourceConfig::Serve(serve_config);
    } else {
        println!("SNOOP");

        let dev = get_device_from_name(&src_string).unwrap();
        let snoop_config = SnoopConfig {
            port: port,
            device: dev,
        };
        return SourceConfig::Snoop(snoop_config);
    }
}

pub fn source_loop(
    flag_output: crossbeam_channel::Sender<bool>,
    output: crossbeam_channel::Sender<dns::DnsPacket>,
    input: crossbeam_channel::Receiver<dns::DnsPacket>,
    config: SourceConfig,
) {
    match config {
        SourceConfig::Snoop(config) => snoop_source(flag_output, output, input, config),
        SourceConfig::Serve(config) => serve_source(flag_output, output, input, config),
        _ => println!("Not implemented yet."),
    }
}

pub fn snoop_source(
    flag_output: crossbeam_channel::Sender<bool>,
    output: crossbeam_channel::Sender<dns::DnsPacket>,
    input: crossbeam_channel::Receiver<dns::DnsPacket>,
    config: SnoopConfig,
) {
    match Device::lookup() {
        Ok(d) => println!("Using device: {}", d.name),
        Err(e) => println!("Error using device: {}", e),
    }

    let mut cap = config.device.open().unwrap();

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
                                    flag_output.send(true).unwrap();
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

pub fn serve_source(
    flag_output: crossbeam_channel::Sender<bool>,
    output: crossbeam_channel::Sender<dns::DnsPacket>,
    input: crossbeam_channel::Receiver<dns::DnsPacket>,
    config: ServeConfig,
) {
    let ip = {
        match config.address {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => ip.to_string(),
        }
    };
    let connection_string = format!("{}:{}", ip, config.port);

    let socket = UdpSocket::bind(connection_string).unwrap();

    loop {
        let mut buf = [0; 512];

        let (_amt, src) = socket.recv_from(&mut buf).unwrap();
        let dns_packet = dns::DnsPacket::from_slice_debug(&buf);
        if dns_packet.header.isrequest() == true {
            output.send(dns_packet).unwrap();
            flag_output.send(true).unwrap();
        }

        let dns_response = input.recv().unwrap();
        socket.send_to(&dns_response.bytes(), &src).unwrap();
    }
}
