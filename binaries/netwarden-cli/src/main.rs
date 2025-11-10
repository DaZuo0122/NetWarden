use anyhow::Result;
use geoip::{GeoDbReader, geo_lookup};
#[cfg(target_os = "windows")]
use netinfo::platform::get_gateways;
use netinfo::{
    PortSet, SensitiveSocket, list_sensitve_sockets, print_certs, print_interfaces, print_ports,
};
use probe::{PingStat, ping, traceroute};
use std::net::{IpAddr, Ipv4Addr};

fn main() -> Result<()> {
    print_interfaces();
    // print_ports();
    println!("Start constructing PortSet");
    let port_set = PortSet::default();
    let ss_list = list_sensitve_sockets(&port_set)?;
    for s_socket in ss_list {
        println!("Found sensitive socket: {:?}", s_socket);
    }
    #[cfg(target_os = "windows")]
    let gateways = get_gateways()?;
    for ip in gateways {
        // println!("{}", ip);
        let _ = match ping(ip) {
            std::result::Result::Ok(a) => println!("{:#?}", a),
            Err(e) => println!("Error: {}", e),
        };
    }
    let reader = GeoDbReader::default();
    let _ = match reader.lookup("8.8.8.8") {
        std::result::Result::Ok(a) => println!("{:#?}", a),
        Err(e) => println!("Error: {}", e),
    };
    traceroute(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    // print_certs();
    Ok(())
}
