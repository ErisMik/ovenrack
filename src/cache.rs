use std::collections::HashMap;
use std::time::{Duration, Instant};

use log::*;

use crate::dest;
use crate::dns;

const TTL_GRACE_PERIOD: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct DnsCacheEntry {
    value: Vec<dns::DnsAnswerSection>,
    insert_time: Instant,
    ttl: Duration,
}

pub struct DnsCache {
    cache: HashMap<dns::DnsQuestionSection, DnsCacheEntry>,
    dest_client: dest::DestClient,
}

impl DnsCache {
    pub fn new(dest_client: dest::DestClient) -> Self {
        let cache = HashMap::new();

        Self { cache, dest_client }
    }

    fn query_cache(&self, request: &dns::DnsPacket) -> Option<Vec<dns::DnsAnswerSection>> {
        let current_time = Instant::now();

        let mut answers = Vec::new();
        for dns_question in request.question_section.clone() {
            if let Some(entry) = self.cache.get(&dns_question) {
                if current_time > (entry.insert_time + entry.ttl) {
                    return None;
                }
                answers.extend_from_slice(&entry.value);
            } else {
                return None;
            }
        }

        if answers.is_empty() {
            return None;
        }

        Some(answers)
    }

    fn update_cache(&mut self, response: dns::DnsPacket) {
        let cache_key = response.question_section[0].clone();

        if response.answer_section.is_empty() {
            return;
        }

        let min_ttl = Duration::from_secs(
            response
                .answer_section
                .iter()
                .map(|ans| ans.ttl)
                .min()
                .unwrap()
                .into(),
        );

        let cache_value = DnsCacheEntry {
            value: response.answer_section,
            insert_time: Instant::now(),
            ttl: min_ttl - TTL_GRACE_PERIOD,
        };

        debug!(
            "Inserting into CACHE: KEY {:?} VALUE {:?}",
            cache_key, cache_value
        );
        self.cache.insert(cache_key, cache_value);
    }

    fn build_dns_response(
        request: &dns::DnsPacket,
        answers: Vec<dns::DnsAnswerSection>,
    ) -> dns::DnsPacket {
        let mut response = request.clone();
        response.add_to_answer_section(&answers);
        response
    }

    pub fn query(&mut self, request: dns::DnsPacket) -> dns::DnsPacket {
        match self.query_cache(&request) {
            Some(cached_answers) => {
                info!("Cache HIT: {} <-- CACHE", request.header.id);
                DnsCache::build_dns_response(&request, cached_answers)
            }
            None => {
                debug!("Cache MISS: {}", request.header.id);
                let response = self.dest_client.query(request);
                self.update_cache(response.clone());
                response
            }
        }
    }
}
