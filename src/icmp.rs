use std::net::Ipv4Addr;
use std::io;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::SystemTime;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::icmp::{IcmpPacket, IcmpType, MutableIcmpPacket, checksum, icmp_types};
use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket, icmp_codes};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{MutablePacket, Packet};

use TxResult;
use ipv4::{Ipv4, Ipv4Listener};

pub trait IcmpListener: Send {
    fn recv(&mut self, time: SystemTime, packet: &Ipv4Packet);
}

pub type IcmpListenerLookup = HashMap<IcmpType, Vec<Box<IcmpListener>>>;

pub struct IcmpIpv4Listener {
    listeners: Arc<Mutex<IcmpListenerLookup>>,
}

impl IcmpIpv4Listener {
    pub fn new(listeners: Arc<Mutex<IcmpListenerLookup>>) -> Box<Ipv4Listener> {
        Box::new(IcmpIpv4Listener { listeners: listeners }) as Box<Ipv4Listener>
    }
}

impl Ipv4Listener for IcmpIpv4Listener {
    fn recv(&mut self, time: SystemTime, ip_pkg: Ipv4Packet) {
        let (icmp_type, _icmp_code) = {
            let icmp_pkg = IcmpPacket::new(ip_pkg.payload()).unwrap();
            (icmp_pkg.get_icmp_type(), icmp_pkg.get_icmp_code())
        };
        println!("Icmp got a packet with {} bytes!", ip_pkg.payload().len());
        let mut listeners = self.listeners.lock().unwrap();
        if let Some(type_listeners) = listeners.get_mut(&icmp_type) {
            for listener in type_listeners {
                listener.recv(time, &ip_pkg);
            }
        } else {
            println!("Icmp, no listener for type {:?}", icmp_type);
        }
    }
}

/// An Icmp communication struct.
pub struct Icmp {
    ipv4: Ipv4,
}

impl Icmp {
    /// !
    pub fn new(ipv4: Ipv4) -> Icmp {
        Icmp { ipv4: ipv4 }
    }

    /// !
    pub fn send<T>(&mut self, dst_ip: Ipv4Addr, payload_size: u16, mut builder: T) -> TxResult
        where T: FnMut(&mut MutableIcmpPacket)
    {
        let total_size = IcmpPacket::minimum_packet_size() as u16 + payload_size;
        let mut builder_wrapper = |ip_pkg: &mut MutableIpv4Packet| {
            ip_pkg.set_next_level_protocol(IpNextHeaderProtocols::Icmp);

            let mut icmp_pkg = MutableIcmpPacket::new(ip_pkg.payload_mut()).unwrap();
            builder(&mut icmp_pkg);
            let checksum = checksum(&icmp_pkg.to_immutable());
            icmp_pkg.set_checksum(checksum);
        };
        self.ipv4.send(dst_ip, total_size, &mut builder_wrapper)
    }

    pub fn send_echo(&mut self, dst_ip: Ipv4Addr, payload: &[u8]) -> TxResult {
        let total_size = (EchoRequestPacket::minimum_packet_size() -
                          IcmpPacket::minimum_packet_size() +
                          payload.len()) as u16;
        let mut builder_wrapper = |icmp_pkg: &mut MutableIcmpPacket| {
            icmp_pkg.set_icmp_type(icmp_types::EchoRequest);
            icmp_pkg.set_icmp_code(icmp_codes::NoCode);
            let mut echo_pkg = MutableEchoRequestPacket::new(icmp_pkg.packet_mut()).unwrap();
            echo_pkg.set_payload(payload);
        };
        self.send(dst_ip, total_size, &mut builder_wrapper)
    }
}

// pub struct PingSocket {
//     echo: Echo,
//     reader: Option<Receiver<Box<[u8]>>>,
//     identifier: u16,
//     sequence_number: u16,
// }

// impl PingSocket {
//     pub fn bind(str, stack?) -> PingSocket {
//
//     }
//
//     pub fn send_to();
//
//     pub fn recv();
//
//     pub fn take_recv() -> Result<Receiver<Box<[u8]>>, ()>;
// }
