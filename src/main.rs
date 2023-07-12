use clap::{arg, command};
use simplelog::*;

mod cache;
mod dest;
mod dns;
mod source;

fn main() {
    let matches = command!()
        .arg(arg!(-v --verbose "Print verbose output"))
        .arg(arg!(-c --cache "Enable the prefetch cache"))
        .arg(arg!(-s --source <SOURCE> "Source for the requests. Using \"-\" inputs from stdin. See README for detailed usage.").required(true))
        .arg(arg!(-d --dest <DEST> "Destination for the requests. Using \"-\" outputs to stdout. See README for detailed usage.").required(true))
        .get_matches();

    let log_level = match matches.get_flag("verbose") {
        true => LevelFilter::Debug,
        _ => LevelFilter::Info,
    };

    CombinedLogger::init(vec![TermLogger::new(
        log_level,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )])
    .expect("Failed to initialize logger(s)");

    let source_addr = matches
        .get_one::<String>("source")
        .expect("Argument should be required");
    let dest_addr = matches
        .get_one::<String>("dest")
        .expect("Argument should be required");

    let dest = dest::DestClient::new(dest_addr);
    let cache = cache::DnsCache::new(dest);
    let mut source = source::SourceServer::new(source_addr, cache);

    source.start()
}
