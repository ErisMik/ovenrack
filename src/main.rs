extern crate rustls;

use clap::{App, Arg};
use crossbeam::crossbeam_channel;
use std::thread;

mod cache;
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
                .help("Override the default input port")
                .default_value("53")
                .takes_value(true),
        )
                .arg(Arg::with_name("cache").short("c").help("Enable prefetch cache"))
        .arg(
            Arg::with_name("source")
                .value_name("SRC")
                .help(
                    "Source for the requests. Using \"-\" outputs to stdout. See README for usage."
                )
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("dest")
                .value_name("DEST")
                .help(
                    "Destination for the requests. Using \"-\" outputs to stdout. See README for usage."
                )
                .required(true)
                .index(2),
        )
        .get_matches();

    let source_config = source::parse_args(&matches);
    let dest_config = dest::parse_args(&matches);
    let enable_cache: bool = matches.occurrences_of("cache") > 0;

    let (request_sender, request_reciever) = crossbeam_channel::unbounded();
    let (response_sender, response_reciever) = crossbeam_channel::unbounded();
    let (dest_flag_sender, dest_flag_reciever) = crossbeam_channel::unbounded();

    let mut threads = vec![];

    threads.push(thread::spawn({
        let flag_sender = dest_flag_sender.clone();
        move || {
            source::source_loop(
                flag_sender,
                request_sender,
                response_reciever,
                source_config,
            );
        }
    }));

    let mut dest_receivers: Vec<crossbeam_channel::Receiver<dns::DnsPacket>> =
        vec![request_reciever];
    let mut dest_senders: Vec<crossbeam_channel::Sender<dns::DnsPacket>> = vec![response_sender];

    if enable_cache {
        let (cache_request_sender, cache_request_reciever) = crossbeam_channel::unbounded();
        let (cache_response_sender, cache_response_reciever) = crossbeam_channel::unbounded();

        dest_receivers.push(cache_request_reciever);
        dest_senders.push(cache_response_sender);

        threads.push(thread::spawn({
            let flag_sender = dest_flag_sender.clone();
            move || {
                cache::cache_loop(flag_sender, cache_request_sender, cache_response_reciever);
            }
        }));
    }

    threads.push(thread::spawn({
        move || {
            dest::dest_loop(
                dest_flag_reciever,
                dest_receivers,
                dest_senders,
                dest_config,
            );
        }
    }));

    for thread in threads {
        thread.join().unwrap();
    }
}
