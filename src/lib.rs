use std::net::Ipv4Addr;

pub mod general_codes;
pub trait PvsDecoding<E> : Sized {
    fn pvs_try_decode(b: &Vec<u8>) -> Result<Self,E>;
}

pub trait PvsEncoding {
    fn pvs_encode(&self) -> (u8,Vec<u8>); // u8 should be a valid Address Type (from the protocol specification not the enum defined here)
}

pub trait PvsProtocolCoding<E> : PvsEncoding + PvsDecoding<E> {}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum GeneralAddressType {
    Reflective = 0,
    IPv4,
    IPv4AndPort,
    IPv6,
    IPv6AndPort,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct IPv4AndPort {
    address: Ipv4Addr,
    port: u16
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum GeneralMetadataType {
    LogicalTimestamp = 0,
    UTCTimestamp,
    ErrorMessage, // string
}

pub struct PvsData {
    format: u8,
    value_to_send: Option<Box<dyn PvsEncoding>>,
    recvd_bytes: Option<Vec<u8>>
}

//TODO: comment back in stuff once we settle on a format

pub struct PvsPeerEntry {
    pub addresses: Vec<PvsData>,
    pub metadata: Vec<PvsData>
}

pub struct PvsViewExchange {
    pub view: Vec<PvsPeerEntry>,
    pub metadata: Vec<PvsData>
}