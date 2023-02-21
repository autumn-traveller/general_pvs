// use std::cmp::Ordering;
use std::io::{Write, Read, Cursor, ErrorKind};
use byteorder::{NetworkEndian, ReadBytesExt};
use std::net::{Ipv4Addr, TcpStream, TcpListener};
use std::str::FromStr;
use std::{env, vec};
use chrono::Utc;

use general_pvs::{*,general_codes::*};

const SAMPLE_FREQUENCY: i64 = 3; // perform sampling every 3 seconds 
const SAMPLE_FREQUENCY_MILLIS: i64 = SAMPLE_FREQUENCY * 1000;

const VIEW_SIZE: usize = 8;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct DemoPeer {
    // all peers are listening on ipv4 loopback (127.0.0.1)
    pub port: u16,
    pub timestamp: u32
}

type DemoView = Vec<DemoPeer>;

fn print_recvd_view(pve: PvsViewExchange) {
    for peer in pve.view {
        for addr in peer.addresses {
            let format = GeneralAddressType::try_from(addr.format);
            match format {
                Ok(GeneralAddressType::IPv4AndPort) => {
                    let p = IPv4AndPort::pvs_try_decode(&addr.recvd_bytes.unwrap()).unwrap();
                    println!("Received peer entry: {}:{}",p.address,p.port);
                },
                _ => println!("unknown format for peer addr: {}", addr.format)
            }
        }
        for meta in peer.metadata {
            let format = GeneralMetadataType::try_from(meta.format);
            match format {
                Ok(GeneralMetadataType::LogicalTimestamp) => {
                    let bytes = meta.recvd_bytes.unwrap();
                    let mut rdr = Cursor::new(bytes);
                    let val = rdr.read_u32::<NetworkEndian>().unwrap();
                    println!("Associated peer metadata is: {} (logical timestamp)",val);
                }
                _ => println!("unknown format for peer metadata: {}", meta.format)
            }
        }
    }
    for meta in pve.metadata {
        let format = GeneralMetadataType::try_from(meta.format);
        match format {
            Ok(GeneralMetadataType::LogicalTimestamp) => {
                let bytes = meta.recvd_bytes.unwrap();
                let mut rdr = Cursor::new(bytes);
                let val = rdr.read_u32::<NetworkEndian>().unwrap();
                println!("Message metadata is: {} (logical timestamp)",val);
            }
            _ => println!("unknown format for message metadata: {}", meta.format)
        }
    }
}

fn send_view_exchange(conn: &mut TcpStream, view: PvsViewExchange, is_response: bool) -> std::io::Result<usize> {
    let bytes = encode_view_exchange(view, if is_response {PVS_VIEW_EXCHANGE_RESPONSE} else {PVS_VIEW_EXCHANGE_REQUEST});
    conn.write(bytes.as_slice())
}

fn translate_pvs_to_demo_view(view: PvsViewExchange) -> DemoView {
    let mut v = vec![];
    if view.view.len() == 0 {
        return v;
    }
    for peer in view.view {
        let mut port = 0;
        let addrformat = GeneralAddressType::try_from(peer.addresses[0].format);
        match addrformat {
            Ok(GeneralAddressType::IPv4AndPort) => {
                let p = IPv4AndPort::pvs_try_decode(&peer.addresses[0].recvd_bytes.as_ref().unwrap()).unwrap();
                port = p.port;
            },
            _ => println!("unknown format for peer addr: {}", peer.addresses[0].format)
        }
        let mut timestamp = 0;
        let metaformat = GeneralMetadataType::try_from(peer.metadata[0].format);
        match metaformat {
            Ok(GeneralMetadataType::LogicalTimestamp) => {
                let bytes = peer.metadata[0].recvd_bytes.as_ref().unwrap();
                let mut rdr = Cursor::new(bytes);
                timestamp = rdr.read_u32::<NetworkEndian>().unwrap();
            }
            _ => println!("unknown format for peer metadata: {}", peer.metadata[0].format)
        }
        if port > 0 {
            v.push(DemoPeer { port, timestamp });
        }
    }
    v
}

fn translate_demo_view_to_pvs(view: DemoView) -> PvsViewExchange {
    let mut v: Vec<PvsPeerEntry> = vec![];
    for p in view {
        let addr = Box::new(IPv4AndPort { address: Ipv4Addr::from_str("127.0.0.1").unwrap(), port: p.port});
        let pvsdata = PvsData {format: GeneralAddressType::IPv4AndPort as u8, value_to_send: Some(addr), recvd_bytes: None};
        let lt = PvsData {format: GeneralMetadataType::LogicalTimestamp as u8, value_to_send: Some(Box::new(p.timestamp)), recvd_bytes: None};
        v.push(PvsPeerEntry { addresses: vec![pvsdata], metadata: vec![lt] })
    }
    PvsViewExchange { view: v, metadata: vec![] }
} 

fn perform_demo_view_exchange(conn: &mut TcpStream, view: DemoView, is_response: bool) {
    let v = translate_demo_view_to_pvs(view);
    let bytes = encode_view_exchange(v, if is_response {PVS_VIEW_EXCHANGE_RESPONSE} else {PVS_VIEW_EXCHANGE_REQUEST});
    conn.write(bytes.as_slice());
}

fn send_peer_list(conn: &mut TcpStream, view: Vec<PvsPeerEntry>, is_response: bool) -> std::io::Result<usize> {
    let p = PvsViewExchange{ view, metadata: vec![]};
    send_view_exchange(conn, p, is_response) 
}

// fn compare_peers(a: &PvsPeerEntry, b: &PvsPeerEntry) -> Ordering{
//     let mut aval: u32 = 0;
//     let mut bval: u32 = 0;

//     for m in &a.metadata {
//         if m.format == GeneralMetadataType::LogicalTimestamp as u8{
//             let bytes = m.recvd_bytes.as_ref().unwrap();
//             let mut rdr = Cursor::new(bytes);
//             aval = rdr.read_u32::<NetworkEndian>().unwrap();
//             break;
//         }
//     }
//     for m in &b.metadata {
//         if m.format == GeneralMetadataType::LogicalTimestamp as u8 {
//             let bytes = m.recvd_bytes.as_ref().unwrap();
//             let mut rdr = Cursor::new(bytes);
//             bval = rdr.read_u32::<NetworkEndian>().unwrap();
//             break;
//         }
//     }
//     aval.cmp(&bval)
// }

// fn sort_view(view: &mut Vec<PvsPeerEntry>) {
//     view.sort_unstable_by(|a,b| compare_peers(a,b))
// }

// fn merge_views(incoming: &mut Vec<PvsPeerEntry>, view: &mut Vec<PvsPeerEntry>, maxsize: usize) {
//     view.append(incoming);
//     sort_view(view);
//     while view.len() > maxsize {
//         view.remove(0); // remove the oldest entries (smallest logical timestamp)
//     }
// }

fn merge_demo_views(incoming: &mut DemoView, view: &mut DemoView, us: u16, maxsize: usize) {
    view.append(incoming);
    //TODO: remove duplicates, remove our own entry
    view.sort_unstable_by(|a,b| a.timestamp.cmp(&b.timestamp));
    while view.len() > maxsize {
        view.remove(0); // remove the oldest entries (smallest logical timestamp)
    }
}

fn peer_sample(view: &mut DemoView) {
    // TODO:
    // pick a random peer
    // try to send them the view minus their own entry
    // remove their entry if it fails
    // increment their timestamp if it succeeds
    // merge their response into our list
    
    if let Ok(mut stream) = TcpStream::connect("") {
        println!("Connected to the server!");
    } else {
        println!("Couldn't connect to server...");
    }
}

fn handle_peer_conn(conn: &mut TcpStream, view: &mut DemoView, us: u16) {
    let mut buf = [0u8;1400];
    if let Ok(nread) = conn.read(&mut buf) {
        println!("Recvd {} bytes",nread);
        let p = decode_view_exchange(&buf);
        if p.is_err() {
            return;
        }
        let pve = p.unwrap();
        // print_recvd_view(pve);
        let mut incoming = translate_pvs_to_demo_view(pve);
        println!("Received view: {:?}",incoming);
        merge_demo_views(&mut incoming,  view, us, VIEW_SIZE);
    }

}

fn init_view(view: &mut Vec<PvsPeerEntry>, id: u16, start: u16, num_clusters: u16, cid: u16, csize: u16, cdist: u16) {
    let peers_start = start + (cid-1)*cdist;
    let us = peers_start + id;
    for i in 0..csize {
        let port = peers_start + i + 1;
        if port != us {
            println!("Adding peer from cluster: localhost {}",port);
            let addr = Box::new(IPv4AndPort { address: Ipv4Addr::from_str("127.0.0.1").unwrap(), port});
            let lt = PvsData {format: GeneralMetadataType::LogicalTimestamp as u8, value_to_send: Some(Box::new(0u32)), recvd_bytes: None};
            let pvs1 = PvsData {format: GeneralAddressType::IPv4AndPort as u8, value_to_send: Some(addr), recvd_bytes: None};
            let peer = PvsPeerEntry { addresses: vec![pvs1], metadata: vec![lt] };
            view.push(peer);
        } else {
            println!("Skipping myself: localhost {}",port);
        }
    }


    if id == 1 {
        println!("I am the connector within this cluster (cluster {}), adding connections to other clusters ({} others)",cid,num_clusters-1);
        
        for i in 0..num_clusters {
            let port = start + (i)*cdist + 1;
            if port != us {
                println!("Adding connection to other cluster: localhost {}",port);
            } else {
                println!("Skipping myself: localhost {}",port);
            }
        }
    }
}

fn init_demo_view(view: &mut DemoView, id: u16, start: u16, num_clusters: u16, cid: u16, csize: u16, cdist: u16) {
    let peers_start = start + (cid-1)*cdist;
    let us = peers_start + id;
    for i in 0..csize {
        let port = peers_start + i + 1;
        if port != us {
            println!("Adding peer from cluster: localhost {}",port);
            let timestamp = 0;
            view.push(DemoPeer {port, timestamp});
        } else {
            println!("Skipping myself: localhost {}",port);
        }
    }


    if id == 1 {
        println!("I am the connector within this cluster (cluster {}), adding connections to other clusters ({} others)",cid,num_clusters-1);
        
        for i in 0..num_clusters {
            let port = start + (i)*cdist + 1;
            if port != us {
                println!("Adding connection to other cluster: localhost {}",port);
                let timestamp = 0;
                view.push(DemoPeer {port, timestamp});
            } else {
                println!("Skipping myself: localhost {}",port);
            }
        }
    }
}

fn main() -> std::io::Result<()> {
    // Parse args
    let mut args = env::args();
    let a0 = args.next().unwrap();
    let size = args.size_hint().1.unwrap();

    if size < 4 {
        println!("Usage: {} ID starting_port_number num_clusters cluster_id cluster_size cluster_port_distance",a0);
        return Ok(());
    }
    let id : u16 = args.next().unwrap_or(String::from_str("0").unwrap()).parse().unwrap_or(0);
    let start_port : u16 = args.next().unwrap_or(String::from_str("0").unwrap()).parse().unwrap_or(0);
    let num_clusters : u16 = args.next().unwrap_or(String::from_str("0").unwrap()).parse().unwrap_or(0);
    let cluster_id : u16 = args.next().unwrap_or(String::from_str("0").unwrap()).parse().unwrap_or(0);
    let cluster_size : u16 = args.next().unwrap_or(String::from_str("0").unwrap()).parse().unwrap_or(0);
    let cluster_distance : u16 = args.next().unwrap_or(String::from_str("0").unwrap()).parse().unwrap_or(0);
    
    
    if id <= 0 || start_port <= 0 || cluster_size <= 0 || cluster_distance < cluster_size || cluster_distance <= 0 || cluster_id <= 0 || num_clusters <= 0 {
        println!("Invalid parameters passed. Please supply a cluster starting port number >= 5000, an ID > 0 and a valid cluster_size, cluster id, total cluster count, and cluster_distance (cluster distance should always be larger than cluster size)");
        return Ok(());
    }
    let myport = id + start_port + (cluster_id-1)*cluster_distance;
    println!("Parameters: ID {}, Starting Port {}, Total Clusters {}, Cluster ID {}, Cluster Size {}, Cluster distance {}",id,start_port,num_clusters, cluster_id,cluster_size,cluster_distance);
    
    // Now calculate the initial neighbours (lets use the DemoView structure)
    let mut view : DemoView = vec![];
    init_demo_view(&mut view, id, start_port, num_clusters, cluster_id, cluster_size, cluster_distance);
    
    let addrbase = String::from_str("127.0.0.1:").unwrap();
    let mut addr = addrbase.clone();
    addr.push_str(format!("{}",myport).as_str());
    println!("Preparing to listen on {}",addr);
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true).expect("Failed to set nonblocking");

    let mut last : i64 = Utc::now().timestamp_millis();
    for s in listener.incoming() {
        match s {
            Ok(mut stream) => handle_peer_conn(&mut stream, &mut view, myport),
            
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                // do other stuff
                let now : i64 = Utc::now().timestamp_millis();
                if now - last > SAMPLE_FREQUENCY_MILLIS {
                    println!("Performing peer sampling, old view is {:?}",&view);
                    peer_sample(&mut view);
                    last = now;
                }
            }

            Err(e) => panic!("encountered IO error: {e}"),
        }
    }

    Ok(())
}
