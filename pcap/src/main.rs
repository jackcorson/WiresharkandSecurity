use pcap::{Device, Capture};

#[derive(Debug)]
enum Transport_Protocol {
    TCP,
    UDP,
    Unknown,
}

struct Packet_Data<'a> {
    ip: IP_Data<'a>,
    transport: Transport_Data,
}

struct IP_Data<'a> {
    source_ip: &'a [i32],
    next_header: Transport_Protocol,
}

struct Transport_Data {

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
        println!("received packet!");
        parse_packet(packet.data);
    }
}

fn parse_packet(data: &[u8]) {
    let ether_type = &data[12..14];
    match ether_type {
        &[134, 221] => { // IPv6 bytes 12-13 = 86DD
            println!("This packet is IPv6");
            println!("{:?}", data);
            parse_IPv6(&data[14..54]);
        },
        &[8, 0] => { // IPv4 bytes 12-13 = 0800
            println!("This packet is IPv4")
        },
        _ => println!("Other etherType")
    }
} 

fn parse_IPv6(data: &[u8]) {
    let trans_pro = match &data[6..7] {
        &[6] => Transport_Protocol::TCP,
        &[17] => Transport_Protocol::UDP,
        _ => Transport_Protocol::Unknown,
    };

    println!("{:?}", trans_pro);

    // let ip_header_info: IP_Data = IP_Data {
        
    // };
    
    // let packet_data_info: Packet_Data = Packet_Data {
        
    // };
}