use crate::*;
// use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr};

impl PvsProtocolCoding for Ipv4Addr {
    
    fn pvs_encode(&self) -> Vec<u8> {
        self.octets().to_vec()
    }

    fn pvs_try_decode(b: &[u8]) -> Result<Self, &str> {
        if b.len() != 4 {
            println!("Not the right length for an IPv4 Address {}", b.len());
            return Err("Incorrect length for IPv4 Address");
        }
        Ok(Ipv4Addr::from(<&[u8] as TryInto<[u8;4]>>::try_into(b).unwrap()))
    }
}

impl PvsProtocolCoding for Ipv6Addr {
    fn pvs_encode(&self) -> Vec<u8> {
        self.octets().to_vec()
    }

    fn pvs_try_decode(b: &[u8]) -> Result<Self, &str> {
        if b.len() != 16 {
            println!("Not the right length for an IPv6 Address {}", b.len());
            return Err("Incorrect length for IPv6 Address");
        }
        Ok(Ipv6Addr::from(<&[u8] as TryInto<[u8;16]>>::try_into(b).unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn encode_ipv4() {
        let addr = Ipv4Addr::from_str("192.168.0.1").unwrap();
        let data = addr.pvs_encode();
        assert_eq!(data.len(), 4);
        assert_eq!(data, vec![192,168,0,1]);
    }
    
    #[test]
    fn try_decode_good_ipv4() {
        let data = vec![127,14,5,66];
        
        let is = Ipv4Addr::pvs_try_decode(&data).unwrap();
        let should = Ipv4Addr::from_str("127.14.5.66").unwrap();
        assert_eq!(is,should);
    }
    
    #[test]
    fn try_decode_bad_ipv4() {
        let data = vec![127,14,5,66,55];
        
        let r = Ipv4Addr::pvs_try_decode(&data);
        assert!(r.is_err());
    }
    
    #[test]
    fn encode_ipv6() {
        let addr = Ipv6Addr::from_str("21a5:78ab::cd02:f3e6").unwrap();
        let data = addr.pvs_encode();
        assert_eq!(data.len(), 16);
        assert_eq!(data, vec![0x21,0xa5,0x78,0xab, 0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0, 0xcd,0x02,0xf3,0xe6]);
    }
    
    #[test]
    fn try_decode_good_ipv6() {
        let data = vec![0x21,0xa5,0x78,0xab, 0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0, 0xcd,0x02,0xf3,0xe6];
        
        let is = Ipv6Addr::pvs_try_decode(&data).unwrap();
        let should = Ipv6Addr::from_str("21a5:78ab::cd02:f3e6").unwrap();
        assert_eq!(is,should);
    }
    
    #[test]
    fn try_decode_bad_ipv6() {
        let data = vec![0x1];
        
        let r = Ipv6Addr::pvs_try_decode(&data);
        assert!(r.is_err());
    }
}