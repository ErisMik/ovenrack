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
                .help("Act as a DNS server instead of snooping DNS requests. ADDRESS is the address the server will bind too")
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
            Arg::with_name("dest")
                .value_name("DEST")
                .help(
                    "Destination for recived or snooped requests. Not specifying outputs to stdout"
                )
                .required(false)
                .index(1),
        )
        .get_matches();

    let port: u16 = matches.value_of("port").unwrap().parse::<u16>().unwrap();
    let is_tls: bool = matches.occurrences_of("tls") > 0;
    let dest_string: String = match matches.value_of("dest") {
        Some(dest_str) => dest_str.to_string(),
        None => "".to_string(),
    };
    let is_stdout: bool = dest_string.len() == 0;

    if is_stdout {
        println!("Stdio not enabled yet...");
        std::process::exit(1);
    }

    let snoop_config = source::SnoopConfig { port: port };
    let dot_config = dest::DNSConfig::from_dest_string(dest_string, is_tls);

    let (request_sender, request_reciever) = crossbeam_channel::unbounded();
    let (response_sender, response_reciever) = crossbeam_channel::unbounded();

    let (cache_request_sender, cache_request_reciever) = crossbeam_channel::unbounded();
    let (cache_response_sender, cache_response_reciever) = crossbeam_channel::unbounded();

    let mut threads = vec![];

    threads.push(thread::spawn({
        move || {
            source::snoop_source(request_sender, response_reciever, snoop_config);
        }
    }));

    let dest_receivers: Vec<crossbeam_channel::Receiver<dns::DnsPacket>> =
        vec![request_reciever, cache_request_reciever];
    let dest_senders: Vec<crossbeam_channel::Sender<dns::DnsPacket>> =
        vec![response_sender, cache_response_sender];

    threads.push(thread::spawn({
        move || {
            dest::dot_dest(dest_receivers, dest_senders, dot_config);
        }
    }));

    for thread in threads {
        thread.join().unwrap();
    }
}
