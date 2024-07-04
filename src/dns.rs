use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use byteorder::{ByteOrder, NetworkEndian};
use log::*;
use rand::prelude::*;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum RData {
    ARecord { ip: Ipv4Addr },
    AAAARecord { ip: Ipv6Addr },
    Other { data: Vec<u8> },
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct DnsAnswerSection {
    pub name: Vec<u8>,
    pub atype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: RData,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct DnsQuestionSection {
    pub qname: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}
const DNS_HEADER_LEN: usize = 12;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub question_section: Vec<DnsQuestionSection>,
    pub answer_section: Vec<DnsAnswerSection>,
    pub authority_section: Vec<DnsAnswerSection>,
    pub additional_section: Vec<DnsAnswerSection>,
}

fn dns_name_bytes_to_string(name_bytes: &[u8]) -> String {
    let mut name: String = String::from("");

    let first_byte = name_bytes[0];
    if ((3 << 7) & first_byte) != 0 {
        return String::from("<PTR>");
    }

    let mut offset = 0;
    loop {
        let name_len = name_bytes[offset];
        offset += 1;

        if name_len == 0 {
            break;
        }

        let offset_end = offset + name_len as usize;
        let name_field =
            std::str::from_utf8(&name_bytes[offset..offset_end]).unwrap_or_else(|error| {
                error!("Invalid UTF8 string parsing DNS name bytes: {error}");
                "<ERR>"
            });
        offset = offset_end;

        name.push_str(name_field);
        name.push('.');
    }

    name
}

impl RData {
    fn aaaa_from_slice(slice: &[u8]) -> (RData, usize) {
        const IPV6_LENGTH: usize = 8;

        let mut ip: [u16; IPV6_LENGTH] = [0; 8];

        let mut slice_idx = 0;
        for ip_short in &mut ip {
            let slice_idx_end = slice_idx + 2;
            *ip_short = NetworkEndian::read_u16(&slice[slice_idx..slice_idx_end]);
            slice_idx = slice_idx_end;
        }

        let aaaa_data = RData::AAAARecord {
            ip: Ipv6Addr::new(ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7]),
        };
        let bytes_read = ip.len() * 2;

        (aaaa_data, bytes_read)
    }

    fn a_from_slice(slice: &[u8]) -> (RData, usize) {
        let a_data = RData::ARecord {
            ip: Ipv4Addr::new(slice[0], slice[1], slice[2], slice[3]),
        };
        let bytes_read = 4;

        (a_data, bytes_read)
    }

    fn other_from_slice(slice: &[u8]) -> (RData, usize) {
        let mut bytes: Vec<u8> = Vec::new();

        for byteptr in slice {
            bytes.push(*byteptr);
        }

        let bytes_read = bytes.len();
        let other_data = RData::Other { data: bytes };

        (other_data, bytes_read)
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

    fn bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        match self {
            RData::ARecord { ip } => {
                for byteptr in ip.octets().iter() {
                    result.push(*byteptr);
                }
                result
            }
            RData::AAAARecord { ip } => {
                for byteptr in ip.octets().iter() {
                    result.push(*byteptr);
                }
                result
            }
            RData::Other { data } => data.to_vec(),
        }
    }
}

impl fmt::Display for RData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RData::ARecord { ip } => write!(f, "A:{}", ip),
            RData::AAAARecord { ip } => write!(f, "AAAA:{}", ip),
            RData::Other { data } => write!(f, "?:{:?}", data),
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
            atype,
            class: aclass,
            ttl: attl,
            rdlength,
            rdata,
        };
        let bytes_read = offset;

        (dns_answer_section, bytes_read)
    }

    pub fn name_string(&self) -> String {
        dns_name_bytes_to_string(&self.name)
    }

    fn bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        let mut u16buf = [0; 2];
        let mut u32buf = [0; 4];

        result.extend(self.name.iter());

        NetworkEndian::write_u16(&mut u16buf, self.atype);
        result.extend_from_slice(&u16buf);

        NetworkEndian::write_u16(&mut u16buf, self.class);
        result.extend_from_slice(&u16buf);

        NetworkEndian::write_u32(&mut u32buf, self.ttl);
        result.extend_from_slice(&u32buf);

        NetworkEndian::write_u16(&mut u16buf, self.rdlength);
        result.extend_from_slice(&u16buf);

        result.extend(self.rdata.bytes().iter());

        result
    }
}

impl fmt::Display for DnsAnswerSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "name:{}, type:{}, class:{}, ttl:{}, rdlength:{}, rdata:{}",
            self.name_string(),
            self.atype,
            self.class,
            self.ttl,
            self.rdlength,
            self.rdata
        )
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
            qname,
            qtype,
            qclass,
        };
        let bytes_read = offset;

        (dns_question_section, bytes_read)
    }

    pub fn name_string(&self) -> String {
        dns_name_bytes_to_string(&self.qname)
    }

    fn bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        let mut u16buf = [0; 2];

        result.extend(self.qname.iter());

        NetworkEndian::write_u16(&mut u16buf, self.qtype);
        result.extend_from_slice(&u16buf);

        NetworkEndian::write_u16(&mut u16buf, self.qclass);
        result.extend_from_slice(&u16buf);

        result
    }
}

impl fmt::Display for DnsQuestionSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "name:{}, type:{}, class:{}",
            self.name_string(),
            self.qtype,
            self.qclass
        )
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

        (dns_header, bytes_read)
    }

    fn bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        let mut u16buf = [0; 2];

        NetworkEndian::write_u16(&mut u16buf, self.id);
        result.extend_from_slice(&u16buf);

        NetworkEndian::write_u16(&mut u16buf, self.flags);
        result.extend_from_slice(&u16buf);

        NetworkEndian::write_u16(&mut u16buf, self.qdcount);
        result.extend_from_slice(&u16buf);

        NetworkEndian::write_u16(&mut u16buf, self.ancount);
        result.extend_from_slice(&u16buf);

        NetworkEndian::write_u16(&mut u16buf, self.nscount);
        result.extend_from_slice(&u16buf);

        NetworkEndian::write_u16(&mut u16buf, self.arcount);
        result.extend_from_slice(&u16buf);

        result
    }

    pub fn isrequest(&self) -> bool {
        let result = self.flags & 0x8000;
        result == 0
    }

    fn new(id: u16) -> Self {
        DnsHeader {
            id,
            flags: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    fn add_to_question_section(&mut self, count: u16) {
        self.qdcount += count;
    }
}

impl fmt::Display for DnsHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "id:{}, flags:{}, QD:{}, AN:{}, NS:{}, AR:{}",
            self.id, self.flags, self.qdcount, self.ancount, self.nscount, self.arcount
        )
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

        let dns_packet = DnsPacket {
            header: dns_header,
            question_section: questions,
            answer_section: answers,
            authority_section: authorities,
            additional_section: additionals,
        };

        debug!("Parsed DNS: {}", dns_packet);

        dns_packet
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        result.extend(self.header.bytes().iter());

        for question in &self.question_section {
            result.extend(question.bytes().iter());
        }

        for answer in &self.answer_section {
            result.extend(answer.bytes().iter());
        }

        for authority in &self.authority_section {
            result.extend(authority.bytes().iter());
        }

        for additional in &self.additional_section {
            result.extend(additional.bytes().iter());
        }

        result
    }

    pub fn new_with_questions(questions: Vec<DnsQuestionSection>) -> DnsPacket {
        let mut dns_header = DnsHeader::new(random());
        dns_header.add_to_question_section(questions.len() as u16);

        let dns_packet = DnsPacket {
            header: dns_header,
            question_section: questions,
            answer_section: vec![],
            authority_section: vec![],
            additional_section: vec![],
        };

        debug!("Generated DNS: {}", dns_packet);

        dns_packet
    }

    pub fn add_to_answer_section(&mut self, answers: &[DnsAnswerSection]) {
        self.answer_section.extend_from_slice(answers);
        self.header.ancount += answers.len() as u16;
    }
}

impl fmt::Display for DnsPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HEADER[{{ {} }}]", self.header)?;
        write!(f, " ")?;

        write!(f, "QUESTION[")?;
        for entry in self.question_section.iter() {
            write!(f, "{{ {} }}", entry)?;
        }
        write!(f, "]")?;
        write!(f, " ")?;

        write!(f, "ANSWER[")?;
        for entry in self.answer_section.iter() {
            write!(f, "{{ {} }}", entry)?;
        }
        write!(f, "]")?;
        write!(f, " ")?;

        write!(f, "AUTHORITY[")?;
        for entry in self.authority_section.iter() {
            write!(f, "{{ {} }}", entry)?;
        }
        write!(f, "]")?;
        write!(f, " ")?;

        write!(f, "ADDITIONAL[")?;
        for entry in self.additional_section.iter() {
            write!(f, "{{ {} }}", entry)?;
        }
        write!(f, "]")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdata_serialize_deserialize_ipv4() {
        let raw_rdata: [u8; 4] = [0x3f, 0xf5, 0xd0, 0xc3];
        let rdata_struct = RData::from_slice(&raw_rdata, Some(1)); // A
        let rdata_bytes = rdata_struct.0.bytes();

        assert_eq!(raw_rdata, rdata_bytes.as_ref());
    }

    #[test]
    fn rdata_serialize_deserialize_ipv6() {
        let raw_rdata: [u8; 16] = [
            0x20, 0x01, 0x41, 0xd0, 0x03, 0x02, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x76, 0x15,
        ];
        let rdata_struct = RData::from_slice(&raw_rdata, Some(28)); // AAAA
        let rdata_bytes = rdata_struct.0.bytes();

        assert_eq!(raw_rdata, rdata_bytes.as_ref());
    }

    #[test]
    fn rdata_serialize_deserialize_other() {
        let raw_rdata = b"\x06\x74\x77\x69\x74\x63\x68\x03\x6d\x61\x70\x06\x66\x61\x73\x74\x6c\x79\x03\x6e\x65\x74\x00";
        let rdata_struct = RData::from_slice(raw_rdata, Some(5)); // CNAME
        let rdata_bytes = rdata_struct.0.bytes();

        assert_eq!(raw_rdata, rdata_bytes.as_slice());
    }

    #[test]
    fn dnsanswersection_serialize_deserialize() {
        let raw_dns_answer = b"\xc0\x0c\x00\x1c\x00\x01\x00\x01\x51\x80\x00\x10\x26\x00\x3c\x01\x00\x00\x00\x00\xf0\x3c\x92\xff\xfe\xb3\x3c\x07";
        let dns_answer_struct = DnsAnswerSection::from_slice(raw_dns_answer);
        let dns_answer_bytes = dns_answer_struct.0.bytes();

        assert_eq!(raw_dns_answer, dns_answer_bytes.as_slice());
    }

    #[test]
    fn dnsquestionsection_serialize_deserialize() {
        let raw_dns_question = b"\x06\x67\x69\x74\x68\x75\x62\x03\x63\x6f\x6d\x00\x00\x1c\x00\x01";
        let dns_question_struct = DnsQuestionSection::from_slice(raw_dns_question);
        let dns_question_bytes = dns_question_struct.0.bytes();

        assert_eq!(raw_dns_question, dns_question_bytes.as_slice());
    }

    #[test]
    fn dnsheader_serialize_deserialize() {
        let raw_dns_header = b"\x02\xaf\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00";
        let dns_header_struct = DnsHeader::from_slice(raw_dns_header);
        let dns_header_bytes = dns_header_struct.0.bytes();

        assert_eq!(raw_dns_header, dns_header_bytes.as_slice());
    }

    #[test]
    fn dnsquery_serialize_deserialize() {
        let raw_dns = b"\x2b\x25\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x07\x6e\x65\x74\x66\x6c\x69\x78\x03\x63\x6f\x6d\x00\x00\x1c\x00\x01";
        let dns_struct = DnsPacket::from_slice(raw_dns);
        let dns_bytes = dns_struct.bytes();

        assert_eq!(&raw_dns[0..], dns_bytes.as_slice());
    }

    #[test]
    fn dnsresponse_serialize_deserialize() {
        let raw_dns = b"\
\x2b\x25\x81\x80\x00\x01\x00\x0a\x00\x00\x00\x00\x03\x77\x77\x77\
\x07\x6e\x65\x74\x66\x6c\x69\x78\x03\x63\x6f\x6d\x00\x00\x1c\x00\
\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x07\x07\x00\x0a\x03\x77\x77\
\x77\x03\x67\x65\x6f\xc0\x10\xc0\x2d\x00\x05\x00\x01\x00\x00\x07\
\x07\x00\x17\x03\x77\x77\x77\x09\x75\x73\x2d\x77\x65\x73\x74\x2d\
\x32\x06\x70\x72\x6f\x64\x61\x61\xc0\x10\xc0\x43\x00\x1c\x00\x01\
\x00\x00\x00\x13\x00\x10\x26\x20\x01\x08\x70\x0f\x00\x00\x00\x00\
\x00\x00\x34\x0a\x19\xa7\xc0\x43\x00\x1c\x00\x01\x00\x00\x00\x13\
\x00\x10\x26\x20\x01\x08\x70\x0f\x00\x00\x00\x00\x00\x00\x22\xdf\
\xe8\x9d\xc0\x43\x00\x1c\x00\x01\x00\x00\x00\x13\x00\x10\x26\x20\
\x01\x08\x70\x0f\x00\x00\x00\x00\x00\x00\x34\x1b\x35\x54\xc0\x43\
\x00\x1c\x00\x01\x00\x00\x00\x13\x00\x10\x26\x20\x01\x08\x70\x0f\
\x00\x00\x00\x00\x00\x00\x34\x23\xd9\x0b\xc0\x43\x00\x1c\x00\x01\
\x00\x00\x00\x13\x00\x10\x26\x20\x01\x08\x70\x0f\x00\x00\x00\x00\
\x00\x00\x34\x23\xe4\xb9\xc0\x43\x00\x1c\x00\x01\x00\x00\x00\x13\
\x00\x10\x26\x20\x01\x08\x70\x0f\x00\x00\x00\x00\x00\x00\x36\xbb\
\xed\x4c\xc0\x43\x00\x1c\x00\x01\x00\x00\x00\x13\x00\x10\x26\x20\
\x01\x08\x70\x0f\x00\x00\x00\x00\x00\x00\x23\xa2\x22\x9f\xc0\x43\
\x00\x1c\x00\x01\x00\x00\x00\x13\x00\x10\x26\x20\x01\x08\x70\x0f\
\x00\x00\x00\x00\x00\x00\x34\x28\xd6\x48";
        let dns_struct = DnsPacket::from_slice(raw_dns);
        let dns_bytes = dns_struct.bytes();

        assert_eq!(&raw_dns[0..], dns_bytes.as_slice());
    }
}
