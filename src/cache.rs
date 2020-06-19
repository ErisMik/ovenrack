use crossbeam::crossbeam_channel;

use super::dns;

pub fn cache_loop(
    flag_output: crossbeam_channel::Sender<bool>,
    output: crossbeam_channel::Sender<dns::DnsPacket>,
    input: crossbeam_channel::Receiver<dns::DnsPacket>,
) {
    loop {
        // Pull requests/response (if any)

        // Place into cache

        // Check cache for expires

        // Send out expired caches
    }
}
