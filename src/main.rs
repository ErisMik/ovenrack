extern crate rustls;

use clap::{App, Arg};
use crossbeam::crossbeam_channel;
use std::thread;

mod dest;
mod dns;
mod source;

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
    let (s2, r2) = crossbeam_channel::unbounded();
    let snoop_config = source::SnoopConfig { port: port };

    let mut threads = vec![];

    threads.push(thread::spawn({
        move || {
            source::snoop_source(s, r2, snoop_config);
        }
    }));

    let dest_receivers: Vec<crossbeam_channel::Receiver<dns::DnsPacket>> = vec![r];
    let dest_senders: Vec<crossbeam_channel::Sender<dns::DnsPacket>> = vec![s2];

    threads.push(thread::spawn({
        move || {
            dest::dot_dest(dest_receivers, dest_senders);
        }
    }));

    for thread in threads {
        thread.join().unwrap();
    }
}
