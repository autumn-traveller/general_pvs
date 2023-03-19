# The Peer View Sampling Protocol

This repository serves as a library implementing the PVS protocol. The protocol's full specification is [included as a pdf in this repository](./PVS_specification_v1.pdf)

It also includes a wireshark dissector. To install the dissector copy or symlink the dissector into one of the directories listed in your wireshark settings ("Help" -> "About wireshark" -> "Folders" , or "Plugins")

## Using the library

This library exposes 2 traits. Structures which implement the `PvsEncoding` trait may be sent "on the wire", via the PVS protocol. Similarly, structures which implement the `PvsDecoding` trait can be decoded when they are received in PVS View Exchange messages. 

This library does not handle any of the sending or receiving via the transport protocol, fundamentally this is a decision and logic which a Peer Sampling Service (PSS) should do for itself. This library just enables one to use the PVS protocol over whatever transport protocol is settled on.

Users must pass in a `PvsViewExchange` structure when they wish to exchange their view, then the `encode_view_exchange` function can be used to translate it to a sequence of bytes which can be sent out to the receiving peer. Receivers must only call the `decode_view_exchange` function on received bytes, to decode it back into the `PvsViewExchange` structure.

### Traits and Structures

``` rust
pub trait PvsDecoding<E> : Sized {
    fn pvs_try_decode(b: &Vec<u8>) -> Result<Self,E>;
}

pub trait PvsEncoding {
    fn pvs_encode(&self) -> (u8,Vec<u8>); // the u8 should be a valid Address Type from the protocol specification
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
```

Since the concept of `some address : some port` is a common occurence this is also provided as a generic data types

``` rust
pub struct AddressAndPort<T : PvsEncoding> {
    pub address: T,
    pub port: u16,
    pub code: u8 
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
```

For more examples see the [general_codes.rs file](./src/general_codes.rs). Additionally- look at the [demo.rs file](./src/demo.rs) for an example of how to use the library within a Peer Sampling Service

## Building

run `cargo build`

## Testing

run `cargo test`

## Running the full demo
 If the build and test commands were successful you may start a small demo program via `start_tmux.sh`. This assumes you have `tmux` and `bash` installed on your system.

 The demo works by spawning 16 peers, in 4 almost separate clusters. Initially peers only know the other members of their cluster, and each cluster has one member who knows one member of each the other clusters/cliques. Over time the peers find out about other members of other cliques via Peer View Sampling, via the PVS protocol.

## Execution

run `cargo run` to spawn a single instance of the demo peer