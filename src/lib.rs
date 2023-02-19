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
    pub address: Ipv4Addr,
    pub port: u16
}

pub struct AddressAndPort<T : PvsEncoding> {
    pub address: T,
    pub port: u16,
    pub code: u8 // code defined in the standard 
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum GeneralMetadataType {
    LogicalTimestamp = 0,
    UTCTimestamp,
    // ErrorMessage, // string ?
}

pub struct PvsData {
    pub format: u8,
    pub value_to_send: Option<Box<dyn PvsEncoding>>,
    pub recvd_bytes: Option<Vec<u8>>
}

pub struct PvsPeerEntry {
    pub addresses: Vec<PvsData>,
    pub metadata: Vec<PvsData>
}

pub struct PvsViewExchange {
    pub view: Vec<PvsPeerEntry>,
    pub metadata: Vec<PvsData>
}

// Message Types
pub const PVS_VIEW_EXCHANGE_REQUEST: u8 = 0;
pub const PVS_VIEW_EXCHANGE_RESPONSE: u8 = 1;