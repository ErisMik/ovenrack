use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use log::*;

use crate::dest;
use crate::dns;

const TTL_GRACE_PERIOD: Duration = Duration::from_secs(15);
const PREFETCH_SLEEP_TIME: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct CacheExpiry {
    insert_time: Instant,
    ttl: Duration,
}

impl CacheExpiry {
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expiry_time()
    }

    pub fn expiry_time(&self) -> Instant {
        self.insert_time + self.ttl - TTL_GRACE_PERIOD
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct DnsCacheEntry {
    value: Vec<dns::DnsAnswerSection>,
    expiry: CacheExpiry,
}

#[derive(Eq)]
struct DnsHeapEntry {
    question: dns::DnsQuestionSection,
    expiry: CacheExpiry,
}

impl Ord for DnsHeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.expiry.expiry_time().cmp(&other.expiry.expiry_time()).reverse()
    }
}

impl PartialOrd for DnsHeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for DnsHeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.expiry.expiry_time() == other.expiry.expiry_time()
    }
}

pub struct DnsCache {
    cache: HashMap<dns::DnsQuestionSection, DnsCacheEntry>,
    expiry_heap: BinaryHeap<DnsHeapEntry>,
}

impl DnsCache {
    pub fn new() -> Self {
        let cache = HashMap::new();
        let expiry_heap = BinaryHeap::new();

        Self { cache, expiry_heap }
    }

    pub fn query(&self, request: &dns::DnsPacket) -> Option<Vec<dns::DnsAnswerSection>> {
        let mut answers = Vec::new();
        for dns_question in request.question_section.clone() {
            if let Some(entry) = self.cache.get(&dns_question) {
                if entry.expiry.is_expired() {
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

    pub fn update(&mut self, response: dns::DnsPacket) {
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

        let expiry = CacheExpiry {
                insert_time: Instant::now(),
                ttl: min_ttl,
            };

        let cache_value = DnsCacheEntry {
            value: response.answer_section,
            expiry: expiry.clone()
        };

        let heap_value = DnsHeapEntry {
            question: cache_key.clone(),
            expiry: expiry.clone()
        };

        debug!(
            "Inserting into CACHE: KEY {:?} VALUE {:?}",
            cache_key, cache_value
        );
        self.cache.insert(cache_key, cache_value);
        self.expiry_heap.push(heap_value);
    }

    pub fn pop_next_expired(&mut self) -> Result<dns::DnsQuestionSection, Instant> {
        let mut sleep_time = PREFETCH_SLEEP_TIME;

        let result = match self.expiry_heap.peek() {
            Some(entry) => {
                if entry.expiry.is_expired() {
                    Ok(entry.question.clone())
                } else {
                    Err(entry.expiry.expiry_time())
                }
            },
            None => {
                Err(Instant::now() + PREFETCH_SLEEP_TIME)
            }
        };

        if result.is_ok() {
            self.expiry_heap.pop();
        }

        result
    }
}

pub struct DnsCacheManager {
    dns_cache: Arc<Mutex<DnsCache>>,
    dest_client: dest::DestClient,

    prefetch_thread: thread::JoinHandle<()>,
}

impl DnsCacheManager {
    pub fn new(dns_cache: DnsCache, dest_client: dest::DestClient) -> Self {
        let dns_cache = Arc::new(Mutex::new(dns_cache));

        let prefetch_thread = {
            let dns_cache = Arc::clone(&dns_cache);

            thread::spawn(move || {
                loop {
                    let entry = {
                        let mut dns_cache = dns_cache.lock().unwrap();
                        dns_cache.pop_next_expired()
                    };

                    match entry {
                        Ok(expired_dns_question) => {
                            debug!("Prefetching: {}", expired_dns_question);
                            let request = build_dns_request(expired_dns_question);
                            // TODO
                        }
                        Err(next_expiry) => {
                            thread::sleep(next_expiry - Instant::now());
                        }
                    }
                }
            })
        };

        Self {
            dns_cache,
            dest_client,
            prefetch_thread,
        }
    }

    fn build_dns_request(
        questions: Vec<dns::DnsQuestionSection>,
    ) -> dns::DnsPacket {
        unimplemented!()
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
        let mut dns_cache = self.dns_cache.lock().unwrap();

        match dns_cache.query(&request) {
            Some(cached_answers) => {
                info!("Cache HIT: {} <-- CACHE", request.header.id);
                DnsCacheManager::build_dns_response(&request, cached_answers)
            }
            None => {
                debug!("Cache MISS: {}", request.header.id);
                let response = self.dest_client.query(request);
                dns_cache.update(response.clone());
                response
            }
        }
    }
}
