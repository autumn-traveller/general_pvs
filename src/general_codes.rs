use crate::*;
use std::net::{Ipv4Addr, Ipv6Addr};

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

    pub fn pvs_encode(&self) -> (u8,Vec<u8>) {
        let mut a = self.address.pvs_encode().1;
        a.push((self.port >> 8) as u8);
        a.push((self.port & 0xFF) as u8);
        (self.code, a)
    }
}

pub fn encode_peer_entry(p: PvsPeerEntry) -> Vec<u8> {
    let mut b: Vec<u8> = vec![];
    b.push(p.addresses.len() as u8);
    b.push(p.metadata.len() as u8);
    for address in p.addresses {
        if let Some(val) = address.value_to_send {
            let mut encoding = val.pvs_encode();
            b.push(encoding.0);
            b.append(&mut encoding.1);
        }
    }
    for metadata in p.metadata {
        if let Some(val) = metadata.value_to_send {
            b.append(&mut val.pvs_encode().1);
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

pub fn decode_view_exchange(b: &[u8]) -> Result<PvsViewExchange, ()> {
    //TODO: implement this properly
    Err(())
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
#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

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
        //TODO
        assert!(false,"Not finished yet");
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
        let data = vec![2,0,2,34,155,169,7,0xAB,0xCD,3,0xFF,0xE3,0,0,0,0,0,0,0,0,0,0,0,0,0,3];
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
    fn try_encode_multiple_addresses() {
        let ip1 = Box::new(IPv4AndPort { address: Ipv4Addr::from_str("1.0.0.23").unwrap(), port: 1234 });
        let ip2 = Box::new(Ipv6Addr::from_str("1::0023").unwrap());
        let a1 = PvsData{ format: GeneralAddressType::IPv4AndPort as u8, value_to_send: Some(ip1), recvd_bytes: None };
        let a2 = PvsData{ format: GeneralAddressType::IPv6 as u8, value_to_send: Some(ip2), recvd_bytes: None };
        let pe = PvsPeerEntry {addresses: vec![a1,a2], metadata: vec![]};

        //TODO: encode to bytes and check its okay
        let should = vec![0,1];
        let is = encode_peer_entry(pe);
        assert!(false,"Not finished yet");
        assert_eq!(should,is)
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