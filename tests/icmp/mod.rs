use std::net::Ipv4Addr;

use pnet::datalink::dummy;
use pnet::util::MacAddr;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::icmp::icmp_types;
use pnet::packet::Packet;
use rips::ethernet::Ethernet;
use rips::arp::Arp;
use rips::ipv4::{Ipv4, Ipv4Conf};
use rips::icmp::{Ping};

#[test]
fn test_ping() {
    let source_ip = Ipv4Addr::new(10, 1, 2, 3);
    let target_ip = Ipv4Addr::new(10, 1, 2, 2);
    let target_mac = MacAddr::new(9, 0, 0, 4, 0, 0);

    let iface = dummy::dummy_interface(7);
    let source_mac = iface.mac.unwrap();

    let mut config = dummy::Config::default();
    let read_handle = config.read_handle().unwrap();
    let channel = dummy::channel(&iface, config).unwrap();
    let ethernet = Ethernet::new(source_mac, channel);

    let mut arp = Arp::new(ethernet.clone());
    arp.insert(target_ip, target_mac);

    let ip_config = Ipv4Conf::new(source_ip, 24, Ipv4Addr::new(10, 1, 2, 1))
        .unwrap();
    let ipv4 = Ipv4::new(ethernet, arp, ip_config);

    let mut ping = Ping::new(ipv4);

    ping.send(target_ip, &[9, 55]).expect("None!!!").expect("Err!!!");

    let pkg = read_handle.recv().unwrap();
    let eth_pkg = EthernetPacket::new(&pkg[..]).unwrap();
    let ip_pkg = Ipv4Packet::new(eth_pkg.payload()).unwrap();
    let echo_pkg = EchoRequestPacket::new(ip_pkg.payload()).unwrap();
    assert_eq!(echo_pkg.get_icmp_type(), icmp_types::EchoRequest);
    assert_eq!(echo_pkg.get_icmp_code().0, 0);
    assert_eq!(echo_pkg.get_checksum(), 61128);
    assert_eq!(echo_pkg.payload(), [9, 55]);
}
