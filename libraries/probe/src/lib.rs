use anyhow::{Error, Ok, Result, anyhow};
use geoip::{IpGeoInfo, geo_lookup};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::thread;
use std::time::Duration;
use tracert::ping::{PingResult, PingStatus, Pinger};
use tracert::trace::{TraceResult, TraceStatus, Tracer};

#[derive(Debug, Clone)]
pub enum ProbeStatus {
    Done,
    Error,
    Timeout,
}

impl ProbeStatus {
    pub fn from_ping(v: PingStatus) -> Self {
        match v {
            PingStatus::Done => Self::Done,
            PingStatus::Error => Self::Error,
            PingStatus::Timeout => Self::Error,
        }
    }

    pub fn from_tracert(v: TraceStatus) -> Self {
        match v {
            TraceStatus::Done => Self::Done,
            TraceStatus::Error => Self::Error,
            TraceStatus::Timeout => Self::Timeout,
        }
    }
}

#[derive(Debug)]
pub struct PingStat {
    pub dst_ip: IpAddr,
    pub num_sent: u8,
    pub num_received: u8,
    pub num_lost: u8,
    pub loss: f32,
    pub shortest: Duration,
    pub longest: Duration,
    pub average: Duration,
    pub probe_time: Duration,
    pub geo_info: Option<IpGeoInfo>,
}

impl PingStat {
    pub fn from_ping_result(pr: &PingResult) -> Result<PingStat> {
        match pr.status {
            PingStatus::Done => {
                // Let's pray for tracrt crate will give us non-empty Vec
                let dst_ip = pr.results[0].ip_addr;

                let num_sent = pr.results.len() as u8;
                let mut num_received: u8 = 0;
                let mut shortest = Duration::MAX;
                let mut longest = Duration::ZERO;
                let mut total = Duration::ZERO;

                for node in &pr.results {
                    // consider a node "received" if its rtt is non-zero (adjust if you use Option)
                    if node.rtt > Duration::ZERO {
                        num_received = num_received.saturating_add(1);
                        if node.rtt < shortest {
                            shortest = node.rtt;
                        }
                        if node.rtt > longest {
                            longest = node.rtt;
                        }
                        total += node.rtt;
                    }
                }

                // If no received packets, set shortest/longest to zero to avoid Duration::MAX leaking out
                if num_received == 0 {
                    shortest = Duration::ZERO;
                    longest = Duration::ZERO;
                }

                let average = if num_received > 0 {
                    total / (num_received as u32)
                } else {
                    Duration::ZERO
                };

                let num_lost = num_sent.saturating_sub(num_received);
                let loss = if num_sent > 0 {
                    (num_lost as f32) / (num_sent as f32) * 100.0
                } else {
                    0.0
                };
                let geo_info = match geo_lookup(&dst_ip) {
                    std::result::Result::Ok(a) => Some(a),
                    Err(_) => None,
                };

                Ok(PingStat {
                    dst_ip,
                    num_sent,
                    num_received,
                    num_lost,
                    loss,
                    shortest,
                    longest,
                    average,
                    probe_time: pr.probe_time,
                    geo_info,
                })
            }
            PingStatus::Error => Err(anyhow!("Ping error")),
            PingStatus::Timeout => Err(anyhow!("Ping timed out")),
        }
    }
}

pub fn ping(dst_ip: IpAddr) -> Result<PingStat> {
    let pinger: Pinger = Pinger::new(dst_ip).unwrap();
    let rx = pinger.get_progress_receiver();
    let handle = thread::spawn(move || pinger.ping());
    match handle.join().unwrap() {
        std::result::Result::Ok(r) => PingStat::from_ping_result(&r),
        std::result::Result::Err(e) => Err(anyhow!(e)),
    }
}

pub fn traceroute(dst_ip: IpAddr) {
    let tracer: Tracer = Tracer::new(dst_ip).unwrap();
    let rx = tracer.get_progress_receiver();
    // Run trace
    let handle = thread::spawn(move || tracer.trace());
    // Print progress
    println!("Progress:");
    while let std::result::Result::Ok(msg) = rx.lock().unwrap().recv() {
        println!("{} {} {:?} {:?}", msg.seq, msg.ip_addr, msg.hop, msg.rtt);
    }
    // Print final result
    println!("Result:");
    match handle.join().unwrap() {
        std::result::Result::Ok(r) => {
            println!("Status: {:?}", r.status);
            for node in r.nodes {
                println!("{:?}", node);
            }
            println!("Trace Time: {:?}", r.probe_time);
        }
        Err(e) => {
            print!("{}", e);
        }
    }
}
