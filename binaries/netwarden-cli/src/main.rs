use anyhow::Result;
#[cfg(target_os = "windows")]
use netinfo::platform::get_gateways;
use netinfo::{
    PortSet, SensitiveSocket, list_sensitve_sockets, print_certs, print_interfaces, print_ports,
};

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
        println!("Gateway ip: {:?}", ip);
    }
    print_certs();
    Ok(())
}
