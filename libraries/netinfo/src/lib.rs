use anyhow::{Result, anyhow};
use local_ip_address::list_afinet_netifas;
use netstat2::{
    self, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState, get_sockets_info,
};
use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

pub struct SensitiveSocket {
    pub address_type: AddrType,
    pub port: u16,
    pub pids: Vec<u32>,
    pub protocol: L4Protocol,
    pub state: Option<TState>,
    pub local_addr: String,
}

pub enum AddrType {
    IPv4,
    IPv6,
}

#[derive(Debug)]
pub enum L4Protocol {
    TCP,
    UDP,
}

#[derive(Debug, Default, Clone)]
pub struct PortSet {
    // keep separate sets for TCP and UDP ports
    tcp: BTreeSet<u16>,
    udp: BTreeSet<u16>,
}

impl PortSet {
    pub fn contains(&self, proto: &L4Protocol, port: u16) -> bool {
        match proto {
            L4Protocol::TCP => self.tcp.contains(&port),
            L4Protocol::UDP => self.udp.contains(&port),
        }
    }
}

/// Redefined TcpState in netstat2 to avoid introducing it multiple times
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown,
}

impl FromStr for L4Protocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(L4Protocol::TCP),
            "udp" => Ok(L4Protocol::UDP),
            other => Err(anyhow!("invalid L4 protocol: {}", other)),
        }
    }
}

impl fmt::Display for TState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TState::Closed => "CLOSED",
                TState::Listen => "LISTEN",
                TState::SynSent => "SYN_SENT",
                TState::SynReceived => "SYN_RCVD",
                TState::Established => "ESTABLISHED",
                TState::FinWait1 => "FIN_WAIT_1",
                TState::FinWait2 => "FIN_WAIT_2",
                TState::CloseWait => "CLOSE_WAIT",
                TState::Closing => "CLOSING",
                TState::LastAck => "LAST_ACK",
                TState::TimeWait => "TIME_WAIT",
                TState::DeleteTcb => "DELETE_TCB",
                TState::Unknown => "__UNKNOWN",
            }
        )
    }
}

impl From<u8> for TState {
    fn from(tcp_state: u8) -> TState {
        match tcp_state {
            1 => TState::Established,
            2 => TState::SynSent,
            3 => TState::SynReceived,
            4 => TState::FinWait1,
            5 => TState::FinWait2,
            6 => TState::TimeWait,
            7 => TState::Closed,
            8 => TState::CloseWait,
            9 => TState::LastAck,
            10 => TState::Listen,
            11 => TState::Closing,
            _ => TState::Unknown,
        }
    }
}

pub fn map_tcp_state(s: TcpState) -> TState {
    use netstat2::TcpState as N;
    match s {
        N::Closed => TState::Closed,
        N::Listen => TState::Listen,
        N::SynSent => TState::SynSent,
        N::SynReceived => TState::SynReceived,
        N::Established => TState::Established,
        N::FinWait1 => TState::FinWait1,
        N::FinWait2 => TState::FinWait2,
        N::CloseWait => TState::CloseWait,
        N::Closing => TState::Closing,
        N::LastAck => TState::LastAck,
        N::TimeWait => TState::TimeWait,
        N::DeleteTcb => TState::DeleteTcb,
        _ => TState::Unknown,
    }
}

pub fn print_interfaces() {
    let network_interfaces = list_afinet_netifas().unwrap();

    for (name, ip) in network_interfaces.iter() {
        println!("{}:\t{:?}", name, ip);
    }
}

pub fn print_ports() {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets_info = get_sockets_info(af_flags, proto_flags).unwrap();

    for si in sockets_info {
        match si.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp_si) => {
                println!(
                    "TCP {}:{} -> {}:{} {:?} - {}",
                    tcp_si.local_addr,
                    tcp_si.local_port,
                    tcp_si.remote_addr,
                    tcp_si.remote_port,
                    si.associated_pids,
                    tcp_si.state
                )
            }
            ProtocolSocketInfo::Udp(udp_si) => {
                println!(
                    "UDP {}:{} -> *:* {:?}",
                    udp_si.local_addr, udp_si.local_port, si.associated_pids,
                )
            }
        }
    }
}
