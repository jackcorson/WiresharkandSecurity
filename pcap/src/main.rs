use pcap::{Capture, Device};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::collections::HashSet;
use reqwest::header::{HeaderMap, HeaderValue};
use std::fs;
use tokio;
use serde_json::Value;
use mail_send::{mail_builder::MessageBuilder, SmtpClientBuilder};

#[derive(Debug)]
enum TransportProtocol {
    TCP,
    UDP,
    Unknown,
}

struct PacketData {
    ip: IPData,
}

struct IPData {
    source_ip: IpAddr,
    next_header: TransportProtocol,
}

impl PacketData {
    fn display_contents(&self) {
        println!("Packet from {:?} using {:?} protocol", self.ip.source_ip, self.ip.next_header);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    check_packet_arrival().await?;
    Ok(())
}

async fn check_packet_arrival() -> Result<(), Box<dyn std::error::Error>> {
    let mut seen_ips: HashSet<IpAddr> = HashSet::new();
    let main_device = Device::lookup().unwrap().unwrap();
    let mut cap = Capture::from_device(main_device).unwrap()
                    .promisc(true)
                    .snaplen(5000)
                    .open().unwrap();

    while let Ok(packet) = cap.next_packet() {
        println!("\nreceived packet!");
        let packet = parse_packet(&seen_ips, packet.data).await?;
        if let Some(packet_data) = packet {
            if !seen_ips.contains(&packet_data.ip.source_ip) {
                seen_ips.insert(packet_data.ip.source_ip);
            }
        }
    }
    Ok(())
}

async fn parse_packet(seen_ips: &HashSet<IpAddr>, data: &[u8]) -> Result<Option<PacketData>, Box<dyn std::error::Error>>{
    let ether_type = &data[12..14];
    let packet = match ether_type {
        &[134, 221] => { // IPv6 bytes 12-13 = 86DD
            println!("This packet is IPv6");
            Some(parse_v6(&data[14..54]))
        },
        &[8, 0] => { // IPv4 bytes 12-13 = 0800
            println!("This packet is IPv4");
            Some(parse_v4(&data[0..20]))
        },
        _ => {
            println!("Other etherType");
            None
        }
    };

    if let Some(packet_info) = &packet {
        packet_info.display_contents();
        // Virus Total logic
        if !seen_ips.contains(&packet_info.ip.source_ip) {
            let response = virus_total(packet_info).await?;
            let malicious = check_malicious(response);
            if malicious {
                // Send email
                send_email_warning(&packet_info).await?;
            }
        }
    }
    else {
        println!("Part of the packet used an unknown protocol");
    }
    Ok(packet)
} 

fn parse_v6(data: &[u8]) -> PacketData {
    let trans_pro = match &data[6..7] {
        &[6] => TransportProtocol::TCP,
        &[17] => TransportProtocol::UDP,
        _ => TransportProtocol::Unknown,
    };

    let ip_bytes: [u8; 16] = data[8..24].try_into().expect("Could not cast to [u8; 16]");

    let source_addr: Ipv6Addr = Ipv6Addr::from(ip_bytes);

    let ip_header_info: IPData = IPData {
        source_ip: IpAddr::V6(source_addr),
        next_header: trans_pro,
    };
    
    let packet_data_info: PacketData = PacketData {
        ip: ip_header_info,
    };

    packet_data_info
}

fn parse_v4(data: &[u8]) -> PacketData {
    let trans_pro = match &data[9..10] {
        &[6] => TransportProtocol::TCP,
        &[17] => TransportProtocol::UDP,
        _ => TransportProtocol::Unknown,
    };

    let ip_bytes: [u8; 4] = data[12..16].try_into().expect("Could not cast to [u8; 4]");

    let source_addr = Ipv4Addr::from(ip_bytes);

    let ip_header_info: IPData = IPData {
        source_ip: IpAddr::V4(source_addr),
        next_header: trans_pro,
    };

    let packet_data_info: PacketData = PacketData {
        ip: ip_header_info,
    };

    packet_data_info
} 

async fn virus_total(packet_info: &PacketData) -> Result<String, Box<dyn std::error::Error>> {
    let ip_addr_string = packet_info.ip.source_ip.to_string();

    let url = format!(
        "https://www.virustotal.com/api/v3/ip_addresses/{}",
        ip_addr_string
    );

    let file_path = "VirusTotal.txt";
    let contents = fs::read_to_string(file_path)
        .expect("Should have been able to read the file");

    let key = contents.trim();

    let mut headers = HeaderMap::new();
    headers.insert(
        "x-apikey",
        HeaderValue::from_str(&key).expect("Error in API key header val"),
    );

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .headers(headers)
        .send()
        .await?
        .text()
        .await?;

    Ok(response)
}

fn check_malicious(response: String) -> bool {
    let json: Value = serde_json::from_str(&response)
        .expect("Invalid JSON");

    let malicious = json["data"]["attributes"]["last_analysis_stats"]["malicious"]
        .as_u64()
        .unwrap_or(0);

    return malicious > 0
}

async fn send_email_warning(packet_info: &PacketData) -> Result<(), Box<dyn std::error::Error>>   {
    let body = String::from("Malicious packet detected from source ") + &packet_info.ip.source_ip.to_string();

    let file_path = "email.txt";
    let contents = fs::read_to_string(file_path)
        .expect("Should have been able to read the file");

    let contents_list: Vec<&str> = contents.split(",").collect();
    let email = *contents_list.get(0).unwrap();
    let psswrd = *contents_list.get(1).unwrap();

    let message = MessageBuilder::new()
        .from(("Jack Corson", email))
        .to(vec![
            ("Jack Corson", email),
        ])
        .subject("Malicious packet detected")
        .text_body(body);

    SmtpClientBuilder::new("smtp.gmail.com", 587)
        .implicit_tls(false)
        .credentials((email, psswrd))
        .connect()
        .await
        .unwrap()
        .send(message)
        .await
        .unwrap();

    Ok(())
}