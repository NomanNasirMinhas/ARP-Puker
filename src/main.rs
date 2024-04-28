use clap::Parser;
use ipnet::Ipv4Net;
use local_ip_address::list_afinet_netifas;
use netscan::blocking::HostScanner;
use netscan::setting::{Destination, ScanType};
use regex::Regex;
use std::collections::HashMap;
use std::hash::Hash;
use std::io::{self, Write};
use std::io::{stdin, BufRead};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::thread;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Mode to run the program in
    #[arg(short, long, required = false)]
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
        if !is_valid_ip_address(ip.to_string().as_str()) {
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
    let mut iface = String::new();
    stdin.lock().read_line(&mut iface).unwrap();
    // let input = input.trim();
    while !valid_ip_addresses.contains_key(iface.trim()) {
        println!("Invalid interface selected. Please try again.");
        iface = String::new();
        stdin.lock().read_line(&mut iface).unwrap();
        iface = iface.trim().to_owned();
    }
    let ip = valid_ip_addresses.get(iface.trim()).unwrap();
    println!("You selected interface {} with IP {}", iface, ip);

    let all_devices = scan_devices(iface.as_str().trim());
    println!("Found {} hosts in the network\n", all_devices.len());
    // println!("=================================================================");
    for (idx, host) in all_devices.iter().enumerate() {
        println!("{}- {} with MAC {}",idx+1, host.0.to_owned(), host.1);
        println!("------------------------------------------------------------");
    }
    // println!("=================================================================");
    println!("Enter the comma separated index number of targets or type 'all' to launch attack for all devices");
    let mut targets = String::new();
    stdin.lock().read_line(&mut targets).unwrap();
    let targets = targets.trim();
    let mut target_devices: Vec<(String, String)> = Vec::new();
    if targets == "all" {
        target_devices = all_devices;
    } else {
        let target_indices: Vec<&str> = targets.split(",").collect();
        for idx in target_indices {
            let idx = idx.trim().parse::<usize>().unwrap();
            target_devices.push(all_devices[idx-1].clone());
        }
    }
    println!("{:?} devices selected for attack \n", target_devices.len());
    println!("Starting ARP Spoofing Attack");

}

// scans for devices on a given interface and returns a vector of IP addresses
fn scan_devices(interface: &str) -> Vec<(String, String)> {
    println!("Scanning on Iface {:?}", interface);

    // Run arp on the given interface and parse the output
    let stdout = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("Get-NetNeighbor")
        .arg("-InterfaceAlias")
        .arg(interface)
        .output()
        .expect("failed to execute process");

    let stdout = String::from_utf8_lossy(&stdout.stdout);
    
    let mut devices: Vec<(String, String)> = Vec::new();
    for line in stdout.lines() {
        let tokens: Vec<&str> = line.split_ascii_whitespace().collect();

        if tokens.len() < 4 || (tokens[1].split(".").count() != 4 && tokens[2].split("-").count() != 6) {
            continue;
        }
        // println!("Line: {:?}", tokens);
        let ip = tokens[1].trim().to_owned();
        let mac = tokens[2].trim().to_owned();
        devices.push((ip.to_string(), mac.to_string()));
    }

    devices
}
