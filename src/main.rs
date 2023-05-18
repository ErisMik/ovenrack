use clap::{arg, command};
use simplelog::*;

mod cache;
mod dest;
mod dns;
mod error;
mod source;

fn main() {
    CombinedLogger::init(vec![TermLogger::new(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )])
    .unwrap();

    let matches = command!()
        .arg(arg!(-v --verbose "Print verbose output"))
        .arg(arg!(-c --cache "Enable the prefetch cache"))
        .arg(arg!(-s --source <SOURCE> "Source for the requests. Using \"-\" inputs from stdin. See README for detailed usage.").required(true))
        .arg(arg!(-d --dest <DEST> "Destination for the requests. Using \"-\" outputs to stdout. See README for detailed usage.").required(true))
        .get_matches();

    let source_addr = matches.value_of("source").unwrap();
    let dest_addr = matches.value_of("dest").unwrap();

    let dest = dest::DestClient::new(dest_addr);
    let cache = cache::DnsCache::new(dest);
    let mut source = source::SourceServer::new(source_addr, cache);

    source.start()
}
