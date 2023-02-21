use std::cmp::min;
use std::io::{Write, Read, Cursor, ErrorKind};
use byteorder::{NetworkEndian, ReadBytesExt};
use std::net::{SocketAddr, IpAddr, Ipv4Addr, TcpStream, TcpListener};
use std::str::FromStr;
use std::{env, vec};
use std::time::Duration;
use chrono::Utc;

use general_pvs::{*,general_codes::*};

const SAMPLE_FREQUENCY: i64 = 3; // perform sampling every 3 seconds 
const SAMPLE_FREQUENCY_MILLIS: i64 = SAMPLE_FREQUENCY * 1000;

const VIEW_SIZE: usize = 8;

const TIMEOUT: u64 = 2;

const RANDOM_OFFSET_RANGE: u32 = 3;
const RANDOM_OFFSET_RANGE_MILLIS: u32 = RANDOM_OFFSET_RANGE * 1000;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct DemoPeer {
    // all peers are listening on ipv4 loopback (127.0.0.1)
    pub port: u16,
    pub timestamp: u32
}

type DemoView = Vec<DemoPeer>;

fn translate_pvs_to_demo_view(view: PvsViewExchange, us: u16) -> DemoView {
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
        if port == us {
            continue; // we dont need our own entry in our view
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

fn translate_demo_view_to_pvs(view: &[DemoPeer]) -> PvsViewExchange {
    let mut v: Vec<PvsPeerEntry> = vec![];
    for p in view {
        let addr = Box::new(IPv4AndPort { address: Ipv4Addr::from_str("127.0.0.1").unwrap(), port: p.port});
        let pvsdata = PvsData {format: GeneralAddressType::IPv4AndPort as u8, value_to_send: Some(addr), recvd_bytes: None};
        let lt = PvsData {format: GeneralMetadataType::LogicalTimestamp as u8, value_to_send: Some(Box::new(p.timestamp)), recvd_bytes: None};
        v.push(PvsPeerEntry { addresses: vec![pvsdata], metadata: vec![lt] })
    }
    PvsViewExchange { view: v, metadata: vec![] }
} 

fn merge_demo_views(incoming: &mut DemoView, view: &mut DemoView, maxsize: usize) {
    view.append(incoming);
    // sort by port and remove duplicates
    view.sort_unstable_by(|a,b| a.port.cmp(&b.port));
    let mut i = 0;
    while i < view.len() {
        let port = view[i].port;
        let mut j  = i+1;
        while j < view.len() {
            if view[j].port == port {
                view.remove(if view[j].timestamp > view[i].timestamp {i} else {j});
                j += 1;
            }
            else {
                break;
            }
        }
        i += 1;
    }
    // now sort by timestamp for removal if the view is too big
    view.sort_unstable_by(|a,b| a.timestamp.cmp(&b.timestamp));
    while view.len() > maxsize {
        view.remove(0); // remove the oldest entries (smallest logical timestamp)
    }
}

fn handle_peer_conn(conn: &mut TcpStream, view: &mut DemoView, us: u16, send_resp: bool) -> Result<(),()> {
    let mut buf = [0u8;1400];
    if let Ok(nread) = conn.read(&mut buf) {
        println!("Recvd {} bytes",nread);
        let p = decode_view_exchange(&buf);
        if p.is_err() {
            return Err(())
        }
        let pve = p.unwrap();
        if send_resp {
            if let Ok(_) = send_demo_view_exchange(conn, view, us, true) {
                conn.shutdown(std::net::Shutdown::Both);
            }
            view.remove(0); // always call this after send_demo...
        }
        // print_recvd_view(pve);
        let mut incoming = translate_pvs_to_demo_view(pve, us);
        println!("Received view: {:?}",incoming);
        merge_demo_views(&mut incoming,  view, VIEW_SIZE);
        return Ok(())
    }
    Err(())
}

fn slice_view(view: &mut DemoView, us: u16) -> &[DemoPeer] {
    let to_send = min(view.len() + 1,VIEW_SIZE);
    view.insert(0, DemoPeer { port: us, timestamp: 0 });
    &view[0..to_send]
}

fn send_demo_view_exchange(conn: &mut TcpStream, view: &mut DemoView, us: u16, is_response: bool) -> std::io::Result<usize>{
    let v = translate_demo_view_to_pvs(slice_view(view, us));
    view.remove(0); // always call this after send_demo...
    let bytes = encode_view_exchange(v, if is_response {PVS_VIEW_EXCHANGE_RESPONSE} else {PVS_VIEW_EXCHANGE_REQUEST});
    conn.write(bytes.as_slice())
}

fn peer_sample(view: &mut DemoView, us: u16) {
    if view.is_empty() {
        return;
    }
    let ind = rand::random::<usize>() % view.len();
    let peer = view[ind];
    let err;
    if let Ok(mut stream) = TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),peer.port), Duration::new(TIMEOUT,0)) {
        println!("Connected to peer at {:?} !",peer);
        err = send_demo_view_exchange(&mut stream, view, us, false).is_err() && handle_peer_conn(&mut stream, view, us, false).is_err();
    } else {
        println!("Couldn't reach peer at {:?}...",peer);
        err = true;
    }

    if err {
        view.remove(ind);
    } else {
        for p in view {
            if peer.port == p.port {
                p.timestamp += 1;
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

    let mut last : i64 = Utc::now().timestamp_millis() + (rand::random::<u32>() % RANDOM_OFFSET_RANGE_MILLIS) as i64;
    for s in listener.incoming() {
        match s {
            Ok(mut stream) => {
                handle_peer_conn(&mut stream, &mut view, myport, true);
            },
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                // do other stuff
                let now : i64 = Utc::now().timestamp_millis();
                if now - last > SAMPLE_FREQUENCY_MILLIS {
                    println!("Performing peer sampling, old view is {:?}",&view);
                    peer_sample(&mut view, myport);
                    last = now;
                }
            }

            Err(e) => panic!("encountered IO error: {e}"),
        }
    }

    Ok(())
}
