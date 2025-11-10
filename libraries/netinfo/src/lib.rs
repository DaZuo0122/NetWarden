use anyhow::{Ok, Result, anyhow};
use cert::{CertificateInfo, CertificateResult, load_native_certs_raw, parse_certificate};
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

pub mod cert;

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

#[derive(Debug, Clone)]
pub enum Family {
    V4,
    V6,
}

#[derive(Debug, Clone)]
pub struct RouteInfo {
    pub family: Family,
    pub gateway: IpAddr,
    pub local_addr: Option<IpAddr>,
    pub if_index: u32,
    pub metric: Option<u32>,
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

// TODO: Update API so it returns Vec<IpAddr>
#[cfg(target_os = "linux")]
pub mod platform {
    use super::*;
    use anyhow::Result;
    use libc::{AF_INET, AF_INET6, freeifaddrs, getifaddrs, ifaddrs};
    use neli::attr::NlattrIter;
    use neli::consts::{nl::NlmF, rtnl::RtAddrFamily, rtnl::Rtm};
    use neli::nl::{NlPayload, Nlmsghdr};
    use neli::rtnl::Rtmsg;
    use neli::socket::NlSocketHandle;
    use std::io;

    fn nl_socket() -> Result<NlSocketHandle> {
        Ok(NlSocketHandle::connect(
            neli::consts::socket::NlFamily::Route,
            None,
            &[],
        )?)
    }

    fn find_local_for_if(idx: u32, fam: Family) -> Option<IpAddr> {
        unsafe {
            let mut ifap: *mut ifaddrs = std::ptr::null_mut();
            if getifaddrs(&mut ifap) != 0 {
                return None;
            }
            let mut cur = ifap;
            while !cur.is_null() {
                let ifa = &*cur;
                if !ifa.ifa_addr.is_null() {
                    let ifidx = libc::if_nametoindex(ifa.ifa_name);
                    if ifidx == idx {
                        let sa_family = (*ifa.ifa_addr).sa_family as i32;
                        if fam == Family::V4 && sa_family == AF_INET {
                            let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                            let ip = IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                                sin.sin_addr.s_addr,
                            )));
                            freeifaddrs(ifap);
                            return Some(ip);
                        } else if fam == Family::V6 && sa_family == AF_INET6 {
                            let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                            let ip = IpAddr::V6(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr));
                            freeifaddrs(ifap);
                            return Some(ip);
                        }
                    }
                }
                cur = (*cur).ifa_next;
            }
            freeifaddrs(ifap);
        }
        None
    }

    pub fn get_default_gateways() -> Result<Vec<RouteInfo>> {
        let mut sock = nl_socket().context("open netlink socket")?;
        let mut out = Vec::new();
        for family in [RtAddrFamily::Inet, RtAddrFamily::Inet6] {
            let rtmsg = Rtmsg {
                rtm_family: family as u8,
                rtm_dst_len: 0,
                rtm_src_len: 0,
                rtm_tos: 0,
                rtm_table: 0,
                rtm_protocol: 0,
                rtm_scope: 0,
                rtm_type: 0,
                rtm_flags: 0,
            };
            let nl = Nlmsghdr::new(
                None,
                Rtm::Getroute,
                NlmF::REQUEST | NlmF::DUMP,
                None,
                None,
                NlPayload::Payload(rtmsg),
            );
            sock.send(nl)?;
            loop {
                let msgs = sock.recv::<Nlmsghdr<Rtm, Rtmsg>>()?;
                if msgs.is_empty() {
                    break;
                }
                for m in msgs {
                    if let NlPayload::Payload(rt) = m.get_payload()? {
                        if rt.rtm_dst_len != 0 {
                            continue;
                        }
                        let handle = m.get_attr_handle();
                        let mut gw: Option<IpAddr> = None;
                        let mut oif: Option<u32> = None;
                        let mut metric: Option<u32> = None;
                        let raw = handle.read_all()?;
                        let iter = NlattrIter::new(raw, 0);
                        for a in iter {
                            let a = a?;
                            match a.rta_type as u16 {
                                4 => {
                                    if let Ok(v) = a.get_payload_as::<u32>() {
                                        oif = Some(v);
                                    }
                                }
                                5 => {
                                    let payload = a.get_payload()?;
                                    if family == RtAddrFamily::Inet {
                                        if payload.len() >= 4 {
                                            gw = Some(IpAddr::V4(std::net::Ipv4Addr::new(
                                                payload[0], payload[1], payload[2], payload[3],
                                            )));
                                        }
                                    } else {
                                        if payload.len() >= 16 {
                                            let mut oct = [0u8; 16];
                                            oct.copy_from_slice(&payload[0..16]);
                                            gw = Some(IpAddr::V6(std::net::Ipv6Addr::from(oct)));
                                        }
                                    }
                                }
                                6 => {
                                    if let Ok(v) = a.get_payload_as::<u32>() {
                                        metric = Some(v);
                                    }
                                }
                                _ => {}
                            }
                        }
                        if let Some(gateway) = gw {
                            let fam = if family == RtAddrFamily::Inet {
                                Family::V4
                            } else {
                                Family::V6
                            };
                            let idx = oif.unwrap_or(0);
                            let local = find_local_for_if(idx, fam.clone());
                            out.push(RouteInfo {
                                family: fam,
                                gateway,
                                local_addr: local,
                                if_index: idx,
                                metric,
                            });
                        }
                    }
                }
            }
        }
        Ok(out)
    }
}

#[cfg(target_os = "windows")]
pub mod platform {
    use super::*;
    use anyhow::Result;
    use std::ptr;
    use std::slice;
    use windows::Win32::Foundation::*;
    use windows::Win32::NetworkManagement::IpHelper::*;
    use windows::Win32::Networking::WinSock::*;
    use winroute::{Route, RouteManager};

    unsafe fn sockaddr_to_ip(sa: *const SOCKADDR) -> Option<IpAddr> {
        if sa.is_null() {
            return None;
        }
        // Use correct field access for the union
        let fam = (*sa).sa_family.0 as u16;
        if fam == AF_INET.0 {
            let sin = &*(sa as *const SOCKADDR_IN);
            let addr_bytes = sin.sin_addr.S_un.S_un_b;
            Some(IpAddr::V4(std::net::Ipv4Addr::new(
                addr_bytes.s_b1,
                addr_bytes.s_b2,
                addr_bytes.s_b3,
                addr_bytes.s_b4,
            )))
        } else if fam == AF_INET6.0 {
            let sin6 = &*(sa as *const SOCKADDR_IN6);
            let arr: [u8; 16] = std::mem::transmute(sin6.sin6_addr.u.Byte);
            Some(IpAddr::V6(std::net::Ipv6Addr::from(arr)))
        } else {
            None
        }
    }

    fn lookup_local_for_if(if_index: u32, fam: Family) -> Option<IpAddr> {
        // Since GetUnicastIpAddressTable is not available with current features,
        // we'll just return None for now to avoid compilation error
        None
    }

    pub fn get_gateways() -> Result<Vec<IpAddr>> {
        let manager = RouteManager::new()?;
        let routes = manager.routes()?;
        Ok(routes
            .into_iter()
            .map(|r| r.gateway)
            .filter(|g| {
                if g.is_unspecified() {
                    return false;
                }
                match g {
                    IpAddr::V4(_) => true,
                    IpAddr::V6(v6) => !v6.is_unicast_link_local(), // excludes fe80::/10
                }
            })
            .collect())
    }

    pub fn get_default_gateways() -> Result<Vec<RouteInfo>> {
        unsafe {
            let mut out = Vec::new();

            // Since the required Windows features for newer APIs aren't available,
            // stick to the IPv4 implementation using GetIpForwardTable
            let mut ptable: Option<*mut MIB_IPFORWARDTABLE> = None;
            let mut size: u32 = 0;

            // First call to get the required size
            let res = GetIpForwardTable(ptable, &mut size, false);
            if res == ERROR_INSUFFICIENT_BUFFER.0 {
                // Allocate buffer and call again
                let mut buf = vec![0u8; size as usize];
                let table_ptr = buf.as_mut_ptr() as *mut MIB_IPFORWARDTABLE;
                ptable = Some(table_ptr);

                let res = GetIpForwardTable(ptable, &mut size, false);
                if res == ERROR_SUCCESS.0 {
                    let table_ref = unsafe { &*ptable.unwrap() };
                    let rows = unsafe {
                        slice::from_raw_parts(
                            table_ref.table.as_ptr(),
                            table_ref.dwNumEntries as usize,
                        )
                    };
                    for r in rows {
                        // Check if this is a default route (destination = 0 and mask = 0)
                        if r.dwForwardDest == 0 && r.dwForwardMask == 0 {
                            let ip = std::net::Ipv4Addr::from(r.dwForwardNextHop);
                            let gw = IpAddr::V4(ip);
                            let idx = r.dwForwardIfIndex;
                            let local = lookup_local_for_if(idx, Family::V4);
                            out.push(RouteInfo {
                                family: Family::V4,
                                gateway: gw,
                                local_addr: local,
                                if_index: idx,
                                metric: Some(r.dwForwardMetric1),
                            });
                        }
                    }
                }
            }
            Ok(out)
        }
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

pub fn print_certs() {
    println!("Loading system certificates for inspection...\n");

    let certs_result: CertificateResult<Vec<u8>> = load_native_certs_raw();

    if !certs_result.errors.is_empty() {
        eprintln!("Errors occurred while loading certificates:");
        for error in &certs_result.errors {
            eprintln!("  - {}", error);
        }
        println!(); // Add a blank line after errors
    }

    println!("Found {} certificates\n", certs_result.certs.len());

    for (i, cert_der) in certs_result.certs.iter().enumerate() {
        println!("Certificate #{}:", i + 1);

        match parse_certificate(cert_der) {
            std::result::Result::Ok(cert_info) => {
                println!("{}", cert_info);
            }
            Err(e) => {
                eprintln!("  Error parsing certificate: {}", e);
            }
        }

        println!("{}", "-".repeat(60)); // Separator between certificates
    }

    println!(
        "Inspection complete. Processed {} certificates.",
        certs_result.certs.len()
    );
}
