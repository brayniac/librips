use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::arp::ArpPacket;
use pnet::packet::arp::ArpOperations::*;
use pnet::packet::Packet;

use {RxError, RxResult, VersionedTx};
use ethernet::EthernetListener;
use super::TableData;

/// Receiver and parser of Arp packets. Shares table instance with the
/// `ArpTable` that created it. Upon valid incoming Arp packet the table will
/// be updated and the `VersionedTx` referenced in the struct will have its
/// revision bumped.
pub struct ArpRx {
    data: Arc<Mutex<TableData>>,
    vtx: Arc<Mutex<VersionedTx>>,
}

impl ArpRx {
    pub fn new(data: Arc<Mutex<TableData>>, vtx: Arc<Mutex<VersionedTx>>) -> Self {
        ArpRx {
            data: data,
            vtx: vtx,
        }
    }
}

#[allow(non_upper_case_globals)]
impl EthernetListener for ArpRx {
    fn recv(&mut self, _time: SystemTime, pkg: &EthernetPacket) -> RxResult {
        let arp_pkg = ArpPacket::new(pkg.payload()).unwrap();


        match arp_pkg.get_operation() {
            Request => {
                let tgt_ip = arp_pkg.get_target_proto_addr();
                let src_ip = arp_pkg.get_sender_proto_addr();
                debug!("ARP, Request who-has {} tell {}", tgt_ip, src_ip);
                let data = try!(self.data.lock().or(Err(RxError::PoisonedLock)));
                if let Some(_) = data.listeners.get(&tgt_ip) {
                    debug!("ARP, should respond");
                }
            }
            Reply => {
                let ip = arp_pkg.get_sender_proto_addr();
                let mac = arp_pkg.get_sender_hw_addr();

                let mut data = try!(self.data.lock().or(Err(RxError::PoisonedLock)));
                let old_mac = data.table.insert(ip, mac);
                if old_mac.is_none() || old_mac != Some(mac) {
                    // The new MAC is different from the old one, bump tx VersionedTx
                    debug!("ARP, Learned {} is-at {}", ip, mac);
                    try!(self.vtx.lock().or(Err(RxError::PoisonedLock))).inc();
                }
                if let Some(listeners) = data.listeners.remove(&ip) {
                    for listener in listeners {
                        listener.send(mac).unwrap_or(());
                    }
                }
            }
            _ => {}
        }

        
        Ok(())
    }

    fn get_ethertype(&self) -> EtherType {
        EtherTypes::Arp
    }
}
