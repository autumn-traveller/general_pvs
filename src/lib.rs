pub mod general_codes;
pub trait PvsProtocolCoding: Sized {
    /// The associated error which can be returned from parsing.
    /// 
    // fn pvs_try_decode(&self, length: u64, data: Vec<u8>) -> bool;
    fn pvs_try_decode(b: &[u8]) -> Result<Self, &str>;
    fn pvs_encode(&self) -> Vec<u8>;
}