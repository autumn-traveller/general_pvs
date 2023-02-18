use crate::*;
use std::net::{Ipv4Addr, Ipv6Addr};
// use byteorder::{LittleEndian, WriteBytesExt};

const MIN_PVS_SIZE : usize = 4;
const PVS_VERSION : u8 = 1 << 4;
const PVS_MAGIC : u8 = 177;

impl PvsEncoding for Ipv4Addr {
    fn pvs_encode(&self) -> (u8,Vec<u8>) {
        (GeneralAddressType::IPv4 as u8, self.octets().to_vec())
    }
}

impl PvsDecoding<()> for Ipv4Addr {

    fn pvs_try_decode(b: &Vec<u8>) -> Result<Self, ()> {
        if b.len() != 4 {
            println!("Not the right length for an IPv4 Address {}", b.len());
            return Err(());
        }
        Ok(Ipv4Addr::from(<&[u8] as TryInto<[u8;4]>>::try_into(b.as_slice()).unwrap()))
    }
}

impl PvsEncoding for Ipv6Addr {
    fn pvs_encode(&self) -> (u8,Vec<u8>) {
        (GeneralAddressType::IPv6 as u8, self.octets().to_vec())
    }
}

impl PvsDecoding<()> for Ipv6Addr {

    fn pvs_try_decode(b: &Vec<u8>) -> Result<Self, ()> {
        if b.len() != 16 {
            println!("Not the right length for an IPv6 Address {}", b.len());
            return Err(())
        }
        Ok(Ipv6Addr::from(<&[u8] as TryInto<[u8;16]>>::try_into(b).unwrap()))
    }
}

impl PvsDecoding<()> for IPv4AndPort {

    fn pvs_try_decode(b: &Vec<u8>) -> Result<Self, ()> where Self: Sized {
        if b.len() != 6 {
            println!("Not the right length for an IPv4 Address + Port Tuple {}", b.len());
            return Err(());
        }
        Ok(IPv4AndPort { address: Ipv4Addr::from(<&[u8] as TryInto<[u8;4]>>::try_into(&b[0..4]).unwrap()), port: (b[4] as u16) << 8 | (b[5] as u16) })
    }
}

impl PvsEncoding for IPv4AndPort {

    fn pvs_encode(&self) -> (u8,Vec<u8>) {
        let mut a = self.address.pvs_encode().1;
        a.push((self.port >> 8) as u8);
        a.push((self.port & 0xFF) as u8);
        (GeneralAddressType::IPv4AndPort as u8, a)
    }
}

impl<T> AddressAndPort<T>
where T: PvsEncoding {

    pub 
    
    fn pvs_encode(&self) -> (u8,Vec<u8>) {
        let mut a = self.address.pvs_encode().1;
        a.push((self.port >> 8) as u8);
        a.push((self.port & 0xFF) as u8);
        (self.code, a)
    }
}

pub fn varu64_encode(datalen: u64) -> Vec<u8> {
    let mut b: Vec<u8> = vec![];
    let mut little_endian: Vec<u8> = vec![];
    if datalen < 248 {
        b.push(datalen as u8);
        return b
    }

    for i in 0..8 {
        if datalen <= ((1u64<<(8*i)) - 1) {
            break;
        }
        little_endian.push(( (datalen >> (8*i)) & 0xFF ) as u8);
    }
    
    b.push(little_endian.len() as u8 + 247);
    little_endian.reverse();
    b.append(&mut little_endian);
    b
}

pub fn varu64_decode(data: &[u8]) -> Result<(u8,u64),()> {
    let avail = data.len();
    if avail == 0 {
        println!("Empty slice passed to varu64 decoder");
        return Err(());
    }
    let len = data[0] as isize - 247isize;
    if len <= 0 {
        return Ok((0,data[0] as u64));
    }
    if len as usize > avail  {
        println!("Invalid length passed as argument. Length is less than the size of the slice: {} vs {} bytes available in the slice",len,avail);
        return Err(());
    }
    let mut val = 0u64;
    let mut shift = 0;
    for i in 0..len {
        val += (data[(len - i) as usize] as u64) << 8*shift;
        shift += 1;
    }
    Ok((len as u8,val))
}

pub fn encode_pvs_data(val: &impl PvsEncoding) -> Vec<u8> {
    let mut b : Vec<u8> = vec![];
    let mut encoding = val.pvs_encode();
    b.push(encoding.0);
    b.append(&mut varu64_encode(encoding.1.len() as u64));
    b.append(&mut encoding.1);
    b
}

pub fn encode_pvs_data_from_box(val: Box<dyn PvsEncoding>) -> Vec<u8> {
    let mut b : Vec<u8> = vec![];
    let mut encoding = val.pvs_encode();
    b.push(encoding.0);
    b.append(&mut varu64_encode(encoding.1.len() as u64));
    b.append(&mut encoding.1);
    b
}

pub fn encode_peer_entry(p: PvsPeerEntry) -> Vec<u8> {
    let mut b: Vec<u8> = vec![];
    b.push(p.addresses.len() as u8);
    b.push(p.metadata.len() as u8);
    for address in p.addresses {
        if let Some(val) = address.value_to_send {
            b.append(&mut &mut encode_pvs_data_from_box(val));
        }
    }
    for metadata in p.metadata {
        if let Some(val) = metadata.value_to_send {
            b.append(&mut &mut encode_pvs_data_from_box(val));
        }
    }
    b
}

pub fn encode_view_exchange(ve: PvsViewExchange) -> Vec<u8> {
    let mut b: Vec<u8> = vec![];
    b.push(ve.view.len() as u8);
    b.push(ve.metadata.len() as u8);
    for peer_entry in ve.view {
        b.append(&mut encode_peer_entry(peer_entry));
    }
    for metadata in ve.metadata {
        if let Some(val) = metadata.value_to_send {
            b.append(&mut val.pvs_encode().1);
        }
    }
    b

}

pub fn decode_pvs_data(b: &[u8]) -> (usize, Result<PvsData, ()>) {
    let avail = b.len();
    if avail == 0 {
        println!("Empty slice passed to pvs data decoder");
        return (0,Err(()));
    }

    let mut i = 0;
    let format = b[i];
    i += 1;    

    let v = varu64_decode(&b[i..b.len()]);
    if v.is_err() {
        return (0,Err(()));
    }
    let (addrstart,addrsize) = v.unwrap();
    if addrsize > avail as u64 {
        println!("Invalid address size passed, {} listed but only {} bytes were received",addrsize,avail);
        return (0,Err(()));
    }
    let mut v = vec![];
    v.copy_from_slice(&b[i + addrstart as usize .. i + addrstart as usize + addrsize as usize]);
    let recvd_bytes = Some(v);
    
    let p = PvsData {format, value_to_send: None, recvd_bytes};

    i += addrstart as usize + addrsize as usize;
    (i,Ok(p))
}

pub fn decode_peer(b: &[u8]) -> (usize, Result<PvsPeerEntry, ()>) {
    let avail = b.len();
    if avail == 0 {
        println!("Empty slice passed to peer decoder");
        return (0,Err(()));
    }
    let mut i = 0;
    let naddr = b[i];
    i += 1;
    let mut p = PvsPeerEntry {addresses: vec![], metadata: vec![]};
    for _ in 0..naddr {
        match decode_pvs_data(&b[i..b.len()]) {
            (read,Ok(d)) => {
                p.addresses.push(d);
                i += read;
            },
            _ => {
                println!("Error trying to decode PvsData");
                return (i,Err(()));
            },
        }
    }

    (i,Ok(p))
}

pub fn decode_view_exchange(b: &[u8]) -> Result<PvsViewExchange, ()> {
    let avail = b.len();
    if avail < MIN_PVS_SIZE {
        println!("Slice passed to view exchange decoder is too small");
        return Err(());
    }
    let mut pve = PvsViewExchange { view: vec![] , metadata: vec![]};
    let mut i = 0;
    let err = Err(());
    if b[i] & 0xF0 != PVS_VERSION {
        println!("Unexpected PVS version");
        return err;
    }
    i += 1;
    if b[i] != PVS_MAGIC {
        println!("Magic Byte is not right!");
        return err;
    }
    i += 1;

    let viewsize = b[i];
    i += 1;
    let metasize = b[i];
    i += 1;

    for j in 0..viewsize {
        match decode_peer(&b[i .. b.len()]) {
            (read,Ok(p)) => {
                pve.view.push(p);
                i += read;
            },
            (_,Err(())) => return err,
        }
    }
    for j in 0..metasize {
    }

    Ok(pve)
}

impl TryFrom<u8> for GeneralAddressType {
    type Error = ();

    fn try_from(x: u8) -> Result<Self, Self::Error> {
        match x {
            0 if x == GeneralAddressType::Reflective as u8 => Ok(GeneralAddressType::Reflective),
            1 if x == GeneralAddressType::IPv4 as u8 => Ok(GeneralAddressType::IPv4),
            2 if x == GeneralAddressType::IPv4AndPort as u8 => Ok(GeneralAddressType::IPv4AndPort),
            3 if x == GeneralAddressType::IPv6 as u8 => Ok(GeneralAddressType::IPv6),
            4 if x == GeneralAddressType::IPv6AndPort as u8 => Ok(GeneralAddressType::IPv6AndPort),
            _ => Err(()),
        }
    }
}

impl TryFrom<u8> for GeneralMetadataType {
    type Error = ();

    fn try_from(x: u8) -> Result<Self, Self::Error> {
        match x {
            0 if x == GeneralMetadataType::LogicalTimestamp as u8 => Ok(GeneralMetadataType::LogicalTimestamp),
            1 if x == GeneralMetadataType::UTCTimestamp as u8 => Ok(GeneralMetadataType::LogicalTimestamp),
            _ => Err(()),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn varu64_check_decode() {
        // decoder should ignore garbage bytes 0xFF
        let data = vec![12,0xFF];
        assert_eq!(12,varu64_decode(&data).unwrap().1);

        let data = vec![248,248,0xFF];
        assert_eq!(248,varu64_decode(&data).unwrap().1);

        let data = vec![249,0xab,0xcd,0xFF];
        assert_eq!(0xabcd,varu64_decode(&data).unwrap().1);

        let data = vec![250,0xab,0xcd,0xef,0xFF];
        assert_eq!(0xabcdef,varu64_decode(&data).unwrap().1);

        let data = vec![251,0xab,0xcd,0xef,0x12,0xFF];
        assert_eq!(0xabcdef12,varu64_decode(&data).unwrap().1);

        let data = vec![252,0xab,0xcd,0xef,0x12,0x34,0xFF,0xFF];
        assert_eq!(0xabcdef1234,varu64_decode(&data).unwrap().1);

        let data = vec![253,0xab,0xcd,0xef,0x12,0x34,0x56,0xFF];
        assert_eq!(0xabcdef123456,varu64_decode(&data).unwrap().1);

        let data = vec![254,0xab,0xcd,0xef,0x12,0x34,0x56,0x78,0xFF,0xFF];
        assert_eq!(0xabcdef12345678u64,varu64_decode(&data).unwrap().1);

        let data = vec![255,0xab,0xcd,0xef,0x12,0x34,0x56,0x78,0x99];
        assert_eq!(0xabcdef1234567899u64,varu64_decode(&data).unwrap().1);
        
    }

    #[test]
    fn varu64_check_encode() {
        let data = vec![12];
        assert_eq!(data,varu64_encode(12));

        let data = vec![248,248];
        assert_eq!(data,varu64_encode(248));

        let data = vec![249,0xab,0xcd];
        assert_eq!(data,varu64_encode(0xabcd));

        let data = vec![250,0xab,0xcd,0xef];
        assert_eq!(data,varu64_encode(0xabcdef));

        let data = vec![251,0xab,0xcd,0xef,0x12];
        assert_eq!(data,varu64_encode(0xabcdef12));

        let data = vec![252,0xab,0xcd,0xef,0x12,0x34];
        assert_eq!(data,varu64_encode(0xabcdef1234));

        let data = vec![253,0xab,0xcd,0xef,0x12,0x34,0x56];
        assert_eq!(data,varu64_encode(0xabcdef123456u64));

        let data = vec![254,0xab,0xcd,0xef,0x12,0x34,0x56,0x78];
        assert_eq!(data,varu64_encode(0xabcdef12345678u64));

        let data = vec![255,0xab,0xcd,0xef,0x12,0x34,0x56,0x78,0x99];
        assert_eq!(data,varu64_encode(0xabcdef1234567899u64));
        
    }

    #[test]
    fn encode_ipv4() {
        let addr = Ipv4Addr::from_str("192.168.0.1").unwrap();
        let data = addr.pvs_encode();
        assert_eq!(data.0,GeneralAddressType::IPv4 as u8);
        assert_eq!(data.1.len(), 4);
        assert_eq!(data.1, vec![192,168,0,1]);
    }
    
    #[test]
    fn try_decode_good_ipv4() {
        let mut data = vec![10; 4];
        let is = Ipv4Addr::pvs_try_decode(&data).unwrap();
        let should = Ipv4Addr::from_str("10.10.10.10").unwrap();
        assert_eq!(is,should);
        data[0] = 21;
        assert_eq!(is,should);
    }

    #[test]
    fn try_decode_good_ipv4_port() {
        let data = vec![2,155,169,7,0xAB,0xCD];
        let recvd = IPv4AndPort::pvs_try_decode(&data).unwrap();
        let should = Ipv4Addr::from_str("2.155.169.7").unwrap();
        assert_eq!(recvd.address,should);
        assert_eq!(recvd.port,0xABCD)
    }

    #[test]
    fn try_decode_bad_ipv4_port() {
        let data = vec![22,1];
        let r = IPv4AndPort::pvs_try_decode(&data);
        assert!(r.is_err());
    }

    #[test]
    fn try_decode_bad_ipv4() {
        let data = vec![127,14,5,66,55];
        let r = Ipv4Addr::pvs_try_decode(&data);
        assert!(r.is_err());
    }
    #[test]
    fn try_encode_ipv4_port() {
        let ip1 = IPv4AndPort { address: Ipv4Addr::from_str("1.0.0.23").unwrap(), port: 0x1234 };
        let b = ip1.pvs_encode();
        assert_eq!(b.1.len(),6);
        assert_eq!(b.0,GeneralAddressType::IPv4AndPort as u8);
        assert_eq!(b.1,vec![1,0,0,23,0x12,0x34])
    }
    
    #[test]
    fn encode_ipv6() {
        let addr = Ipv6Addr::from_str("21a5:78ab::cd02:f3e6").unwrap();
        let data = addr.pvs_encode();
        assert_eq!(data.1.len(), 16);
        assert_eq!(data.0, GeneralAddressType::IPv6 as u8);
        assert_eq!(data.1, vec![0x21,0xa5,0x78,0xab, 0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0, 0xcd,0x02,0xf3,0xe6]);
    }

    #[test]
    fn try_decode_good_ipv6() {
        let mut data = vec![0x21,0xa5,0x78,0xab, 0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0, 0xcd,0x02,0xf3,0xe6];
        let is = Ipv6Addr::pvs_try_decode(&data).unwrap();
        let should = Ipv6Addr::from_str("21a5:78ab::cd02:f3e6").unwrap();
        assert_eq!(is,should);
        data[0] = 144;
        assert_eq!(is,should);
    }
    
    #[test]
    fn try_decode_bad_ipv6() {
        let data = vec![0x1];
        let r = Ipv6Addr::pvs_try_decode(&data);
        assert!(r.is_err());
    }

    #[test]
    fn try_encode_peer_entry_two_addr_no_metadata() {
        let data = vec![2,0,2,6,34,155,169,7,0xAB,0xCD, 3,16,0xFF,0xE3,0,0,0,0,0,0,0,0,0,0,0,0,0,3];
        // TODO: addr1 - Ipv4port
        let addr1 = PvsData {
            format: GeneralAddressType::IPv4 as u8,
            value_to_send: Some(Box::new(
                IPv4AndPort {
                    address: Ipv4Addr::from_str("34.155.169.7").unwrap(),
                    port: 0xABCD
                })),
            recvd_bytes: None
        };
        let addr2 = PvsData {
            format: GeneralAddressType::IPv6 as u8,
            value_to_send: Some(Box::new(Ipv6Addr::from_str("ffe3::3").unwrap())),
            recvd_bytes: None
        };
        let pe = PvsPeerEntry {
            addresses: vec![addr1, addr2],
            metadata: vec![]
        };
        assert_eq!(encode_peer_entry(pe),data);
    }

    #[test]
    fn try_encode_multiple_addresses_with_metadata() {
        let ip1 = Box::new(IPv4AndPort { address: Ipv4Addr::from_str("1.0.0.23").unwrap(), port: 0x1234 });
        let ip2 = Box::new(Ipv6Addr::from_str("1111::0023").unwrap());
        let a1 = PvsData{ format: GeneralAddressType::IPv4AndPort as u8, value_to_send: Some(ip1), recvd_bytes: None };
        let a2 = PvsData{ format: GeneralAddressType::IPv6 as u8, value_to_send: Some(ip2), recvd_bytes: None };
        // assert!(false,"Need to add metadata to this test!");
        
        
        let pe = PvsPeerEntry {addresses: vec![a1,a2], metadata: vec![]};

        let should = vec![2,0,2,6, 1,0,0,23,0x12,0x34, 3,16,0x11,0x11,0,0,0,0,0,0,0,0,0,0,0,0,0,0x23]; // 2 entries 0 metadata, ipv4andport is type 2 length 6, ipv6 is type 3 length 16
        let is = encode_peer_entry(pe);
        assert_eq!(is,should);
        assert!(false,"Need to add metadata to this test!");
    }

    #[test]
    fn dummy_packing_and_unpacking_multiple_addresses() {
        let ip1 = Box::new(IPv4AndPort { address: Ipv4Addr::from_str("4.5.5.199").unwrap(), port: 1234 });
        let ip2 = Box::new(Ipv4Addr::from_str("167.23.9.188").unwrap());
        let a1 = PvsData{ format: GeneralAddressType::IPv4AndPort as u8, value_to_send: Some(ip1), recvd_bytes: None };
        let a2 = PvsData{ format: GeneralAddressType::IPv6 as u8, value_to_send: Some(ip2), recvd_bytes: None };
        let pe = PvsPeerEntry {addresses: vec![a1,a2], metadata: vec![]};
        
        let view = PvsViewExchange { view: vec![pe] , metadata: vec![]};


        for peer in view.view {
            for addr in peer.addresses {
                    let format = GeneralAddressType::try_from(addr.format);
                    match format {
                        Ok(GeneralAddressType::IPv4AndPort) => {
                            // let foo = Ipv4Addr::pvs_try_decode(&addr.recvd_bytes.unwrap()).unwrap();
                            // assert_eq!(foo,Ipv4Addr::from_str("1.0.0.23").unwrap());
                        },
                        Ok(GeneralAddressType::IPv6) => {
                        },
                        _ => assert!(false)
                }
            }
        }
        assert!(false,"Not finished yet");

    }

}