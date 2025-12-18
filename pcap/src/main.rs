use pcap::{Capture, Device};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

fn main() {
    check_packet_arrival();
}

fn check_packet_arrival() {
    let main_device = Device::lookup().unwrap().unwrap();
    let mut cap = Capture::from_device(main_device).unwrap()
                    .promisc(true)
                    .snaplen(5000)
                    .open().unwrap();

    while let Ok(packet) = cap.next_packet() {
        println!("\nreceived packet!");
        parse_packet(packet.data);
    }
}

fn parse_packet(data: &[u8]) {
    let ether_type = &data[12..14];
    let packet = match ether_type {
        &[134, 221] => { // IPv6 bytes 12-13 = 86DD
            println!("This packet is IPv6");
            Some(parse_IPv6(&data[14..54]))
        },
        &[8, 0] => { // IPv4 bytes 12-13 = 0800
            println!("This packet is IPv4");
            Some(parse_IPv4(&data[0..20]))
        },
        _ => {
            println!("Other etherType");
            None
        }
    };

    if let Some(packet_info) = packet {
        packet_info.display_contents();
    }
    else {
        println!("Part of the packet used an unknown protocol");
    }

} 

fn parse_IPv6(data: &[u8]) -> PacketData {
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

fn parse_IPv4(data: &[u8]) -> PacketData {
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