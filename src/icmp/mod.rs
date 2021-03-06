mod icmp_rx;
mod icmp_tx;

pub use self::icmp_rx::{IcmpListener, IcmpListenerLookup, IcmpRx};
pub use self::icmp_tx::{BasicIcmpProtocol, IcmpBuilder, IcmpProtocol, IcmpTx, PingBuilder};


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

#[cfg(all(test, feature = "unit-tests"))]
mod tests {
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::icmp::icmp_types;
    use pnet::packet::icmp::echo_request::EchoRequestPacket;
    use pnet::packet::Packet;

    use super::*;
    use testing::ipv4::Ipv4Tx;

    #[test]
    fn test_ping() {
        let (ipv4, read_handle) = Ipv4Tx::new();
        let mut icmp = IcmpTx::new(ipv4);
        icmp.send_echo(&[9, 55]).unwrap();

        let (next_level_protocol, data) = read_handle.recv().unwrap();
        assert_eq!(next_level_protocol, IpNextHeaderProtocols::Icmp);
        let echo_pkg = EchoRequestPacket::new(&data).unwrap();
        assert_eq!(echo_pkg.get_icmp_type(), icmp_types::EchoRequest);
        assert_eq!(echo_pkg.get_icmp_code().0, 0);
        assert_eq!(echo_pkg.get_checksum(), 61128);
        assert_eq!(echo_pkg.payload(), [9, 55]);
    }
}
