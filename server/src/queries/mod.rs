pub mod user_queries;
pub mod device_queries;
pub mod network_queries;
pub mod process_queries;
pub mod arp_alert_queries;
pub mod tcp_alert_queries;


pub fn format_mac_address(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}