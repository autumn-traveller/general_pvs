use core::num;
use std::cmp::Ordering;
use std::io::{Write, Read, Cursor};
use byteorder::{NetworkEndian, ReadBytesExt};
use std::net::{Ipv4Addr, TcpStream, TcpListener};
use std::str::FromStr;
use general_pvs::{*,general_codes::*};

use std::env;

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

fn handle_peer_conn(conn: &mut TcpStream) {
    let mut buf = [0u8;1400];
    if let Ok(nread) = conn.read(&mut buf) {
        println!("Recvd {} bytes",nread);
        let p = decode_view_exchange(&buf);
        if p.is_err() {
            return;
        }
        print_recvd_view(p.unwrap());

    }

}

fn perform_view_exchange(conn: &mut TcpStream, view: PvsViewExchange, is_response: bool) {
    let bytes = encode_view_exchange(view, if is_response {PVS_VIEW_EXCHANGE_RESPONSE} else {PVS_VIEW_EXCHANGE_REQUEST});
    conn.write(bytes.as_slice());
}

fn send_peer_list(conn: &mut TcpStream, view: Vec<PvsPeerEntry>, is_response: bool) {
    let p = PvsViewExchange{ view, metadata: vec![]};
    perform_view_exchange(conn, p, is_response) 
}

fn compare_views(a: &PvsPeerEntry, b: &PvsPeerEntry) -> Ordering{
    let r: Option<Ordering> = None;
    let aval: u64 = 0;
    let bval: u64 = 0;

    for m in &a.metadata {
        if m.format == GeneralMetadataType::UTCTimestamp as u8{
            break;
        }
    }
    for m in &b.metadata {
        if m.format == GeneralMetadataType::UTCTimestamp as u8 {
            break;
        }
    }
    r.unwrap_or(Ordering::Equal)    
}

fn sort_view(view: &mut Vec<PvsPeerEntry>) {
    view.sort_unstable_by(|a,b| compare_views(a,b))
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
    // Now calculate the initial neighbours
    let mut view : Vec<PvsPeerEntry> = vec![];
    init_view(&mut view, id, start_port, num_clusters, cluster_id, cluster_size, cluster_distance);

    let tmpport = 7777;
    let addrbase = String::from_str("127.0.0.1:").unwrap();
    let mut addr = addrbase.clone();
    addr.push_str(format!("{}",tmpport).as_str());
    
    let mut myaddr = addrbase.clone();
    myaddr.push_str(format!("{}",tmpport).as_str());
    
    println!("Preparing to listen on {}",myaddr);
    if id == 1  {
        // TODO: send/recv a message
        println!("Starting a tcp conn. with localhost:{}",tmpport);
        if let Ok(mut stream) = TcpStream::connect(addr) {
            println!("Connected to the server!");
            send_peer_list(&mut stream, view, false);
        } else {
            println!("Couldn't connect to server...");
            return Ok(());
        }
    } else {
        println!("Listening on tcp on port {}",tmpport);
        let listener = TcpListener::bind(addr)?;
        for stream in listener.incoming() {
            handle_peer_conn(&mut stream?);
        }
    }

    //TODO: networking based on peers
    Ok(())
}
