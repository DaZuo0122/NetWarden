use anyhow::Result;
use netinfo::{PortSet, SensitiveSocket, list_sensitve_sockets, print_interfaces, print_ports};

fn main() -> Result<()> {
    print_interfaces();
    // print_ports();
    println!("Start constructing PortSet");
    let port_set = PortSet::default();
    let ss_list = list_sensitve_sockets(&port_set)?;
    for s_socket in ss_list {
        println!("Found sensitive socket: {:?}", s_socket);
    }
    Ok(())
}
