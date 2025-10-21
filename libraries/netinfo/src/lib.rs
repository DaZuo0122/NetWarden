use anyhow::Ok;
use anyhow::{Result, anyhow};
use local_ip_address::list_afinet_netifas;
use netstat2::{
    self, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState, get_sockets_info,
};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

#[cfg(target_os = "windows")]
use dunce;

#[derive(Debug, Clone)]
pub struct SensitiveSocket {
    pub address_type: AddrType,
    pub port: u16,
    pub pids: Vec<u32>,
    pub protocol: L4Protocol,
    pub state: Option<TState>,
    pub local_addr: String,
}

#[derive(Debug, Clone)]
pub enum AddrType {
    IPv4,
    IPv6,
}

#[derive(Debug, Clone)]
pub enum L4Protocol {
    TCP,
    UDP,
}

#[derive(Debug, Clone)]
pub struct PortSet {
    // keep separate sets for TCP and UDP ports
    tcp: BTreeSet<u16>,
    udp: BTreeSet<u16>,
}

pub fn list_sensitve_sockets(port_set: &PortSet) -> Result<Vec<SensitiveSocket>> {
    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets = get_sockets_info(af, proto)?;

    let mut sockets_list = Vec::new();
    for si in sockets {
        match si.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => {
                if is_any_addr(&tcp.local_addr)
                    && port_set.contains(&L4Protocol::TCP, tcp.local_port)
                {
                    let addr_type = match tcp.local_addr {
                        IpAddr::V4(_) => AddrType::IPv4,
                        IpAddr::V6(_) => AddrType::IPv6,
                    };
                    sockets_list.push(SensitiveSocket {
                        address_type: addr_type,
                        port: tcp.local_port,
                        pids: si.associated_pids,
                        protocol: L4Protocol::TCP,
                        state: Some(map_tcp_state(tcp.state)),
                        local_addr: addr_to_string(&tcp.local_addr),
                    });
                }
            }
            ProtocolSocketInfo::Udp(udp) => {
                if is_any_addr(&udp.local_addr)
                    && port_set.contains(&L4Protocol::UDP, udp.local_port)
                {
                    let addr_type = match udp.local_addr {
                        IpAddr::V4(_) => AddrType::IPv4,
                        IpAddr::V6(_) => AddrType::IPv6,
                    };
                    sockets_list.push(SensitiveSocket {
                        address_type: addr_type,
                        port: udp.local_port,
                        pids: si.associated_pids,
                        protocol: L4Protocol::UDP,
                        state: None,
                        local_addr: addr_to_string(&udp.local_addr),
                    });
                }
            }
        }
    }
    Ok(sockets_list)
}

impl PortSet {
    pub fn contains(&self, proto: &L4Protocol, port: u16) -> bool {
        match proto {
            L4Protocol::TCP => self.tcp.contains(&port),
            L4Protocol::UDP => self.udp.contains(&port),
        }
    }
}

impl Default for PortSet {
    fn default() -> Self {
        let mut port_set = PortSet {
            tcp: BTreeSet::new(),
            udp: BTreeSet::new(),
        };
        let possible_paths = gen_default_path().unwrap();
        for path in &possible_paths {
            if path.exists() {
                // Load ports from the first existing file found
                if load_ports_from_file(path, &mut port_set).is_ok() {
                    break; // Exit after successfully loading from the first existing file
                }
            }
        }
        port_set // Return the port_set after attempting to load from files
    }
}

fn gen_default_path() -> Result<[PathBuf; 3]> {
    let exec_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|p| p.to_path_buf()))
        .unwrap_or(std::env::current_dir().unwrap_or_default());

    // Use dunce for path canonicalization on Windows to handle junctions and symlinks properly
    #[cfg(target_os = "windows")]
    let possible_paths = [
        dunce::canonicalize(exec_dir.join("data").join("sensitive-ports.txt"))
            .unwrap_or_else(|_| exec_dir.join("data").join("sensitive-ports.txt")), // For distribution
        dunce::canonicalize(
            std::env::current_dir()
                .unwrap_or_default()
                .join("data")
                .join("sensitive-ports.txt"),
        )
        .unwrap_or_else(|_| {
            std::env::current_dir()
                .unwrap_or_default()
                .join("data")
                .join("sensitive-ports.txt")
        }), // For development
        dunce::canonicalize(Path::new("data").join("sensitive-ports.txt"))
            .unwrap_or_else(|_| Path::new("data").join("sensitive-ports.txt")), // Relative path
    ];

    #[cfg(target_os = "linux")]
    let possible_paths = [
        exec_dir.join("data").join("sensitive-ports.txt"), // For distribution
        std::env::current_dir()
            .unwrap_or_default()
            .join("data")
            .join("sensitive-ports.txt"), // For development
        Path::new("data").join("sensitive-ports.txt"),     // Relative path
    ];

    Ok(possible_paths)
}

fn load_ports_from_file<P: AsRef<Path>>(path: P, port_set: &mut PortSet) -> Result<()> {
    let content = fs::read_to_string(path)?;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((port_range, protocol_str)) = line.rsplit_once('/') {
            let protocol = L4Protocol::from_str(protocol_str)?;

            // Handle both single ports (e.g., "80") and port ranges (e.g., "40000-50000")
            if let Some((start, end)) = port_range.split_once('-') {
                let start_port: u16 = start.trim().parse()?;
                let end_port: u16 = end.trim().parse()?;

                for port in start_port..=end_port {
                    match protocol {
                        L4Protocol::TCP => {
                            port_set.tcp.insert(port);
                        }
                        L4Protocol::UDP => {
                            port_set.udp.insert(port);
                        }
                    }
                }
            } else {
                let port: u16 = port_range.parse()?;
                match protocol {
                    L4Protocol::TCP => {
                        port_set.tcp.insert(port);
                    }
                    L4Protocol::UDP => {
                        port_set.udp.insert(port);
                    }
                }
            }
        }
    }

    Ok(())
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

fn is_any_addr(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.octets() == [0, 0, 0, 0],
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

fn addr_to_string(addr: &IpAddr) -> String {
    if addr.is_unspecified() {
        match addr {
            IpAddr::V4(_) => "0.0.0.0".into(),
            IpAddr::V6(_) => "::".into(),
        }
    } else {
        addr.to_string()
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
