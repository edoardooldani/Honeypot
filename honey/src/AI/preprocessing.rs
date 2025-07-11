use pnet::packet::ethernet::{EthernetPacket, EtherType, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

#[derive(Debug)]
pub struct PacketHeaders {
    pub ethertype: EtherType,
    pub ethernet_src: String,
    pub ethernet_dst: String,
    pub ethernet_size: usize,
    pub ip_version: Option<u8>,
    pub ip_src: Option<String>,
    pub ip_dst: Option<String>,
    pub ip_size: Option<usize>,
    pub ip_header_len: Option<u8>,
    pub transport_protocol: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub transport_size: Option<usize>,
    pub tcp_flags: Option<u8>,
    pub tcp_window_size: Option<u16>,
    pub tcp_header_len: Option<u8>,
}

pub fn extract_packet_headers(packet: &EthernetPacket) -> PacketHeaders {
    let ethertype = packet.get_ethertype();
    let ethernet_src = packet.get_source().to_string();
    let ethernet_dst = packet.get_destination().to_string();
    let ethernet_size = packet.packet().len();

    let mut ip_version = None;
    let mut ip_src = None;
    let mut ip_dst = None;
    let mut ip_size = None;
    let mut ip_header_len = None;
    let mut transport_protocol = None;
    let mut src_port = None;
    let mut dst_port = None;
    let mut transport_size = None;
    let mut tcp_flags = None;
    let mut tcp_window_size = None;
    let mut tcp_header_len = None;

    match ethertype {
        EtherTypes::Ipv4 => {
            if let Some(ipv4) = Ipv4Packet::new(packet.payload()) {
                ip_version = Some(4);
                ip_src = Some(ipv4.get_source().to_string());
                ip_dst = Some(ipv4.get_destination().to_string());
                ip_size = Some(ipv4.packet().len());
                ip_header_len = Some(ipv4.get_header_length());

                match ipv4.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        transport_protocol = Some("TCP".to_string());
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            src_port = Some(tcp.get_source());
                            dst_port = Some(tcp.get_destination());
                            transport_size = Some(tcp.packet().len());
                            tcp_flags = Some(tcp.get_flags());
                            tcp_window_size = Some(tcp.get_window());
                            tcp_header_len = Some(tcp.get_data_offset() * 4); // in bytes
                        }
                    }
                    IpNextHeaderProtocols::Udp => {
                        transport_protocol = Some("UDP".to_string());
                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                            src_port = Some(udp.get_source());
                            dst_port = Some(udp.get_destination());
                            transport_size = Some(udp.packet().len());
                        }
                    }
                    _ => {}
                }
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6) = Ipv6Packet::new(packet.payload()) {
                ip_version = Some(6);
                ip_src = Some(ipv6.get_source().to_string());
                ip_dst = Some(ipv6.get_destination().to_string());
                ip_size = Some(ipv6.packet().len());

                match ipv6.get_next_header() {
                    IpNextHeaderProtocols::Tcp => {
                        transport_protocol = Some("TCP".to_string());
                        if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                            src_port = Some(tcp.get_source());
                            dst_port = Some(tcp.get_destination());
                            transport_size = Some(tcp.packet().len());
                            tcp_flags = Some(tcp.get_flags());
                            tcp_window_size = Some(tcp.get_window());
                            tcp_header_len = Some(tcp.get_data_offset() * 4); // in bytes
                        }
                    }
                    IpNextHeaderProtocols::Udp => {
                        transport_protocol = Some("UDP".to_string());
                        if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                            src_port = Some(udp.get_source());
                            dst_port = Some(udp.get_destination());
                            transport_size = Some(udp.packet().len());
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }

    PacketHeaders {
        ethertype,
        ethernet_src,
        ethernet_dst,
        ethernet_size,
        ip_version,
        ip_src,
        ip_dst,
        ip_size,
        ip_header_len,
        transport_protocol,
        src_port,
        dst_port,
        transport_size,
        tcp_flags,
        tcp_window_size,
        tcp_header_len,
    }
}