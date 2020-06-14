use byteorder::{ByteOrder, NetworkEndian};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub enum RData {
    AData { ip: Ipv4Addr },
    AAAAData { ip: Ipv6Addr },
    OtherData { data: Vec<u8> },
}

#[derive(Debug)]
pub struct DnsAnswerSection {
    name: Vec<u8>,
    r#type: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: RData,
}

#[derive(Debug)]
pub struct DnsQuestionSection {
    qname: Vec<u8>,
    qtype: u16,
    qclass: u16,
}

#[derive(Debug)]
pub struct DnsHeader {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}
const DNS_HEADER_LEN: usize = 12;

#[derive(Debug)]
pub struct DnsPacket {
    header: DnsHeader,
    question_section: Vec<DnsQuestionSection>,
    answer_section: Vec<DnsAnswerSection>,
    authority_section: Vec<DnsAnswerSection>,
    additional_section: Vec<DnsAnswerSection>,
}

impl RData {
    fn aaaa_from_slice(slice: &[u8]) -> (RData, usize) {
        let mut ip: [u16; 8] = [0; 8];

        let mut slice_idx = 0;
        for i in 0..ip.len() {
            let slice_idx_end = slice_idx + 2;
            ip[i] = NetworkEndian::read_u16(&slice[slice_idx..slice_idx_end]);
            slice_idx = slice_idx_end;
        }

        let aaaa_data = RData::AAAAData {
            ip: Ipv6Addr::new(ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7]),
        };
        let bytes_read = ip.len() * 2;

        return (aaaa_data, bytes_read);
    }

    fn a_from_slice(slice: &[u8]) -> (RData, usize) {
        let a_data = RData::AData {
            ip: Ipv4Addr::new(slice[0], slice[1], slice[2], slice[3]),
        };
        let bytes_read = 4;

        return (a_data, bytes_read);
    }

    fn other_from_slice(slice: &[u8]) -> (RData, usize) {
        let mut bytes: Vec<u8> = Vec::new();

        for byteptr in slice {
            bytes.push(*byteptr);
        }

        let bytes_read = bytes.len();
        let other_data = RData::OtherData { data: bytes };

        return (other_data, bytes_read);
    }

    fn from_slice(slice: &[u8], atype: Option<u16>) -> (RData, usize) {
        match atype {
            None => RData::other_from_slice(slice),
            Some(atype) => match atype {
                1 => RData::a_from_slice(slice),
                28 => RData::aaaa_from_slice(slice),
                _ => RData::other_from_slice(slice),
            },
        }
    }
}

impl DnsAnswerSection {
    fn from_slice(slice: &[u8]) -> (DnsAnswerSection, usize) {
        let mut offset = 0;
        let mut aname: Vec<u8> = Vec::new();

        loop {
            let aname_field_len = slice[offset];
            aname.push(slice[offset]);
            offset += 1;

            if aname_field_len == 0 {
                break;
            }

            if aname_field_len == 192 {
                aname.push(slice[offset]);
                offset += 1;

                break;
            } else {
                let offset_end = offset + aname_field_len as usize;

                for byteptr in &slice[offset..offset_end] {
                    aname.push(*byteptr);
                }
                offset = offset_end;
            }
        }

        let offset_end = offset + 2;
        let atype = NetworkEndian::read_u16(&slice[offset..offset_end]);
        offset = offset_end;

        let offset_end = offset + 2;
        let aclass = NetworkEndian::read_u16(&slice[offset..offset_end]);
        offset = offset_end;

        let offset_end = offset + 4;
        let attl = NetworkEndian::read_u32(&slice[offset..offset_end]);
        offset = offset_end;

        let offset_end = offset + 2;
        let rdlength = NetworkEndian::read_u16(&slice[offset..offset_end]);
        offset = offset_end;

        let offset_end = offset + rdlength as usize;
        let result = RData::from_slice(&slice[offset..offset_end], Some(atype));
        let rdata = result.0;
        offset += result.1;

        let dns_answer_section = DnsAnswerSection {
            name: aname,
            r#type: atype,
            class: aclass,
            ttl: attl,
            rdlength: rdlength,
            rdata: rdata,
        };
        let bytes_read = offset;

        return (dns_answer_section, bytes_read);
    }
}

impl DnsQuestionSection {
    fn from_slice(slice: &[u8]) -> (DnsQuestionSection, usize) {
        let mut offset = 0;
        let mut qname: Vec<u8> = Vec::new();

        loop {
            let qname_field_len = slice[offset];
            qname.push(slice[offset]);
            offset += 1;

            if qname_field_len == 0 {
                break;
            }

            let offset_end = offset + qname_field_len as usize;
            for byteptr in &slice[offset..offset_end] {
                qname.push(*byteptr);
            }
            offset = offset_end;
        }

        let offset_end = offset + 2;
        let qtype = NetworkEndian::read_u16(&slice[offset..offset_end]);
        offset = offset_end;

        let offset_end = offset + 2;
        let qclass = NetworkEndian::read_u16(&slice[offset..offset_end]);
        offset = offset_end;

        let dns_question_section = DnsQuestionSection {
            qname: qname,
            qtype: qtype,
            qclass: qclass,
        };
        let bytes_read = offset;

        return (dns_question_section, bytes_read);
    }

    fn name_string(&self) -> String {
        let mut qname: String = String::from("");

        let mut offset = 0;
        loop {
            let qname_field_len = self.qname[offset];
            offset += 1;

            if qname_field_len == 0 {
                break;
            }

            let offset_end = offset + qname_field_len as usize;
            let qname_field = std::str::from_utf8(&self.qname[offset..offset_end]).unwrap();
            offset = offset_end;

            qname.push_str(qname_field);
            qname.push('.');
        }

        return qname;
    }
}

impl DnsHeader {
    fn from_slice(slice: &[u8]) -> (DnsHeader, usize) {
        let dns_header = DnsHeader {
            id: NetworkEndian::read_u16(&slice[0..2]),
            flags: NetworkEndian::read_u16(&slice[2..4]),
            qdcount: NetworkEndian::read_u16(&slice[4..6]),
            ancount: NetworkEndian::read_u16(&slice[6..8]),
            nscount: NetworkEndian::read_u16(&slice[8..10]),
            arcount: NetworkEndian::read_u16(&slice[10..12]),
        };

        let bytes_read = DNS_HEADER_LEN;

        return (dns_header, bytes_read);
    }
}

impl DnsPacket {
    pub fn from_slice(slice: &[u8]) -> DnsPacket {
        let mut offset = 0;

        let result = DnsHeader::from_slice(&slice[offset..]);
        let dns_header = result.0;
        offset += result.1;

        let mut questions: Vec<DnsQuestionSection> = Vec::new();
        for _i in 0..dns_header.qdcount {
            let result = DnsQuestionSection::from_slice(&slice[offset..]);
            questions.push(result.0);
            offset += result.1;
        }

        let mut answers: Vec<DnsAnswerSection> = Vec::new();
        for _i in 0..dns_header.ancount {
            let result = DnsAnswerSection::from_slice(&slice[offset..]);
            answers.push(result.0);
            offset += result.1;
        }

        let mut authorities: Vec<DnsAnswerSection> = Vec::new();
        for _i in 0..dns_header.nscount {
            let result = DnsAnswerSection::from_slice(&slice[offset..]);
            authorities.push(result.0);
            offset += result.1;
        }

        let mut additionals: Vec<DnsAnswerSection> = Vec::new();
        for _i in 0..dns_header.arcount {
            let result = DnsAnswerSection::from_slice(&slice[offset..]);
            additionals.push(result.0);
            offset += result.1;
        }

        return DnsPacket {
            header: dns_header,
            question_section: questions,
            answer_section: answers,
            authority_section: authorities,
            additional_section: additionals,
        };
    }
}
