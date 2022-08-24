use chrono::*;
use log::*;

use std::collections::HashMap;

use crate::dest;
use crate::dns;

const TTL_GRACE_PERIOD_SECS: i64 = 15;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct DnsCacheEntry {
    value: Vec<dns::DnsAnswerSection>,
    expiry_time: DateTime<Utc>,
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
        let current_time = Utc::now();

        let mut answers = Vec::new();
        for dns_question in request.question_section.clone() {
            if let Some(entry) = self.cache.get(&dns_question) {
                if current_time > entry.expiry_time {
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

        let current_time = Utc::now();
        let grace_duration = Duration::seconds(TTL_GRACE_PERIOD_SECS);
        let min_expiry_time = response
            .answer_section
            .iter()
            .map(|ans| current_time + (Duration::seconds(ans.ttl.into()) - grace_duration))
            .min()
            .unwrap();

        let cache_value = DnsCacheEntry {
            value: response.answer_section,
            expiry_time: min_expiry_time,
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
                let response = self.dest_client.query(request);
                self.update_cache(response.clone());
                response
            }
        }
    }
}
