use std::net::{IpAddr, Ipv4Addr};
use clap::Parser;
use local_ip_address::list_afinet_netifas;
use regex::Regex;
use std::io::{stdin, BufRead};
use std::collections::HashMap;
use std::hash::Hash;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Mode to run the program in
    #[arg(short, long, required = true)]
    mode: String,
}


fn is_valid_ip_address(ip: &str) -> bool {
    let ip_regex = Regex::new(r#"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"#).unwrap();
    ip_regex.is_match(ip)
}

fn main() {
    let args = Args::parse();
    let network_interfaces = list_afinet_netifas().unwrap();
    let mut valid_ip_addresses: HashMap<String, IpAddr> = HashMap::new();
    for (name, ip) in network_interfaces.iter() {
        if !is_valid_ip_address(  ip.to_string().as_str()) {
            continue;
        }
        // let ip = ip.to_string().parse::<Ipv4Addr>().unwrap();
        valid_ip_addresses.insert(name.to_string(), ip.clone());
    }
    println!("I found following Interfaces on your system. Please enter the name of the interface you want to use.");
    for (name, ip) in valid_ip_addresses.iter() {
        println!("{}: {}", name, ip);
    }
    let stdin = stdin();
    let mut input = String::new();
    stdin.lock().read_line(&mut input).unwrap();
    // let input = input.trim();
    while(!valid_ip_addresses.contains_key(input.trim())) {
        println!("Invalid interface selected. Please try again.");
        input = String::new();
        stdin.lock().read_line(&mut input).unwrap();
        let input = input.trim();
    }
    let ip = valid_ip_addresses.get(input.trim()).unwrap();
    println!("You selected: {}", ip);
}
