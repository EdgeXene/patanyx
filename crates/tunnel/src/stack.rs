//! The smoltcp half of the bridge: an `Interface` over a virtual device
//! whose receive side is fed by the WireGuard session and whose transmit
//! side is what the session encapsulates. IPv4 only in this pass.
//!
//! WHY IP MEDIUM AND NOT ETHERNET. A TUN device carries bare IP packets,
//! which is exactly what boringtun decrypts to. Faking an Ethernet segment
//! would mean faking ARP and a peer MAC to no end: there is no L2 here.
//!
//! MTU CONTRACT. The device reports `Medium::Ip` and an MTU of 1420 --
//! WireGuard's conventional allowance (1500 minus IPv4+UDP+WireGuard
//! overhead) -- and smoltcp sizes TCP's MSS from it. The bounded queues on
//! both sides mimic a NIC ring: full means drop, because TCP (not this
//! device) owns retransmission.
//!
//! TYPE NOTE, so nobody "fixes" it backwards: smoltcp 0.13's
//! `wire::Ipv4Address` IS `core::net::Ipv4Addr` (`pub use core::net::Ipv4Addr
//! as Address` in its wire/ipv4.rs), so std addresses flow straight in with
//! no conversion layer. Pre-0.12 code carried `from_bytes` conversions;
//! adding them back is drift, not compatibility.
//!
//! WHAT IS DELIBERATELY NOT HERE. No listening sockets for production use
//! (`tcp_listen` exists for the in-crate loopback peer harness -- a real
//! tunnel terminates CONNECTs, it never serves them). No IPv6: the config's
//! v6 addresses are kept for display, and v6 packets decapsulated by the
//! session are dropped in session.rs, not here.

use std::collections::VecDeque;
use std::net::Ipv4Addr;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{dns, tcp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{DnsQueryType, HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Cidr};

use crate::TunnelError;

/// WireGuard's conventional MTU: 1500 minus 20 (IPv4) minus 8 (UDP) minus
/// 60 (WireGuard overhead with headroom). smoltcp derives TCP's MSS from
/// the device MTU, so this number is what keeps inner packets inside one
/// outer datagram.
pub(crate) const TUNNEL_MTU: usize = 1420;

/// Bound on both device queues, like a NIC ring: full means drop. TCP owns
/// retransmission; an unbounded queue here would be a memory bug wearing a
/// throughput costume.
const MAX_DEVICE_QUEUE: usize = 256;

/// Per-connection smoltcp TCP buffers. Small on purpose: the proxy drains
/// them every core tick, and TCP backpressure (not buffer size) is the
/// honest flow control.
const TCP_RX_BUF: usize = 16 * 1024;
const TCP_TX_BUF: usize = 16 * 1024;

/// Local ports for outbound CONNECTs, allocated upward from here and
/// wrapping. Collisions would need tens of thousands of simultaneous
/// connections; the SOCKS layer caps at MAX_CLIENTS long before that.
const FIRST_EPHEMERAL_PORT: u16 = 49152;

/// The virtual device. Plain queues, not channels: the core thread owns
/// both ends, so synchronization would be theater. `pub(crate)` so the
/// test harness can build the peer's end of the tunnel from the same parts.
#[derive(Default)]
pub(crate) struct VirtDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

impl VirtDevice {
    /// A packet from the WireGuard session, destined for the stack.
    pub(crate) fn push_rx(&mut self, packet: Vec<u8>) {
        if self.rx.len() < MAX_DEVICE_QUEUE {
            self.rx.push_back(packet);
        }
    }

    /// The next packet the stack emitted, destined for encapsulation.
    pub(crate) fn pop_tx(&mut self) -> Option<Vec<u8>> {
        self.tx.pop_front()
    }
}

pub(crate) struct VirtRxToken(Vec<u8>);

impl RxToken for VirtRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

pub(crate) struct VirtTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl TxToken for VirtTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        if self.0.len() < MAX_DEVICE_QUEUE {
            self.0.push_back(buf);
        }
        result
    }
}

impl Device for VirtDevice {
    type RxToken<'a> = VirtRxToken;
    type TxToken<'a> = VirtTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((VirtRxToken(packet), VirtTxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(VirtTxToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = TUNNEL_MTU;
        caps
    }
}

/// Outcome of one look at an in-flight DNS query.
pub(crate) enum DnsVerdict {
    Pending,
    Answer(Ipv4Addr),
    Failed,
}

/// `Stack::tcp_connect` failed. Mapped to a SOCKS reply by the caller; the
/// smoltcp error itself says nothing a SOCKS client could use.
#[derive(Debug)]
pub(crate) struct TcpConnectError;

pub(crate) struct Stack {
    device: VirtDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    dns_handle: Option<SocketHandle>,
    next_local_port: u16,
}

impl Stack {
    pub(crate) fn new(addr: Ipv4Cidr, dns_server: Option<Ipv4Addr>) -> Result<Self, TunnelError> {
        let mut device = VirtDevice::default();
        let mut config = Config::new(HardwareAddress::Ip);
        // Feeds TCP initial-sequence randomization. The clock is good
        // enough here; this is not key material.
        config.random_seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x5eed_5eed);
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());
        iface.update_ip_addrs(|addrs| {
            // The address list is a heapless Vec with a small fixed
            // capacity; the first push into an empty list cannot fail. If a
            // future smoltcp shrinks it to zero, every connect fails loudly
            // -- the right failure, not a silent wrong address.
            let _ = addrs.push(IpCidr::Ipv4(addr));
        });
        // WHY a default route on an IP-medium interface: smoltcp consults
        // the route table when dispatching outbound packets. The gateway is
        // nominal -- an IP-medium device emits the packet unchanged and the
        // WireGuard peer is the next hop no matter what it says -- but the
        // table must say "everywhere is reachable". The interface's own
        // address is the only gateway guaranteed inside the configured
        // prefix (a /32 has no other). The cross-connected-stacks test
        // fails loudly if this assumption is wrong.
        iface
            .routes_mut()
            .add_default_ipv4_route(addr.address())
            .map_err(|_| TunnelError::InterfaceSetup("default route table is full"))?;

        let mut sockets = SocketSet::new(Vec::new());
        let dns_handle = dns_server.map(|server| sockets.add(dns_socket_for(server)));

        Ok(Self {
            device,
            iface,
            sockets,
            dns_handle,
            next_local_port: FIRST_EPHEMERAL_PORT,
        })
    }

    pub(crate) fn feed(&mut self, packet: Vec<u8>) {
        self.device.push_rx(packet);
    }

    pub(crate) fn poll(&mut self) {
        self.iface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
    }

    pub(crate) fn pop_outbound(&mut self) -> Option<Vec<u8>> {
        self.device.pop_tx()
    }

    fn alloc_local_port(&mut self) -> u16 {
        let port = self.next_local_port;
        self.next_local_port = if self.next_local_port == u16::MAX {
            FIRST_EPHEMERAL_PORT
        } else {
            self.next_local_port + 1
        };
        port
    }

    /// Open a TCP connection THROUGH the tunnel. This is the only place in
    /// the crate where a connection toward a destination is created.
    pub(crate) fn tcp_connect(
        &mut self,
        dst: Ipv4Addr,
        port: u16,
    ) -> Result<SocketHandle, TcpConnectError> {
        let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF]);
        let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF]);
        let mut socket = tcp::Socket::new(rx, tx);
        // A proxy relays latency-sensitive streams; Nagle has nothing to
        // batch here that the caller did not already batch.
        socket.set_nagle_enabled(false);
        let local = self.alloc_local_port();
        socket
            .connect(
                self.iface.context(),
                IpEndpoint::new(IpAddress::Ipv4(dst), port),
                local,
            )
            .map_err(|_| TcpConnectError)?;
        Ok(self.sockets.add(socket))
    }

    /// A listening socket. Used by the in-crate loopback peer harness; a
    /// real tunnel never serves connections -- which is why this only
    /// exists in test builds at all.
    #[cfg(test)]
    pub(crate) fn tcp_listen(&mut self, port: u16) -> Result<SocketHandle, TunnelError> {
        let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF]);
        let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF]);
        let mut socket = tcp::Socket::new(rx, tx);
        socket
            .listen(port)
            .map_err(|_| TunnelError::InterfaceSetup("listen failed"))?;
        Ok(self.sockets.add(socket))
    }

    pub(crate) fn tcp(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(handle)
    }

    pub(crate) fn tcp_remove(&mut self, handle: SocketHandle) {
        self.sockets.remove(handle);
    }

    /// Start resolving `name` to an A record, against the configured DNS
    /// server, with the query itself travelling INSIDE the tunnel. `None`
    /// when the config named no usable DNS server: in that case DOMAIN
    /// requests are refused (0x01), never resolved through the host.
    pub(crate) fn dns_start(&mut self, name: &str) -> Option<dns::QueryHandle> {
        let handle = self.dns_handle?;
        let socket = self.sockets.get_mut::<dns::Socket>(handle);
        socket
            .start_query(self.iface.context(), name, DnsQueryType::A)
            .ok()
    }

    pub(crate) fn dns_poll_result(&mut self, query: dns::QueryHandle) -> DnsVerdict {
        let Some(handle) = self.dns_handle else {
            return DnsVerdict::Failed;
        };
        let socket = self.sockets.get_mut::<dns::Socket>(handle);
        match socket.get_query_result(query) {
            Ok(addrs) => addrs
                .iter()
                .find_map(|a| match a {
                    IpAddress::Ipv4(v4) => Some(*v4),
                    #[allow(unreachable_patterns)] // no proto-ipv6 today
                    _ => None,
                })
                .map(DnsVerdict::Answer)
                .unwrap_or(DnsVerdict::Failed),
            Err(dns::GetQueryResultError::Pending) => DnsVerdict::Pending,
            Err(_) => DnsVerdict::Failed,
        }
    }

    pub(crate) fn dns_cancel(&mut self, query: dns::QueryHandle) {
        if let Some(handle) = self.dns_handle {
            self.sockets
                .get_mut::<dns::Socket>(handle)
                .cancel_query(query);
        }
    }
}

/// Build the DNS socket pinned to one server: the config's, reached through
/// the tunnel. (`new` takes the server list as a slice and copies it out;
/// the queries storage is Vec-backed under std, hence `'static`.)
fn dns_socket_for(server: Ipv4Addr) -> dns::Socket<'static> {
    dns::Socket::new(&[IpAddress::Ipv4(server)], Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn the_virtual_device_reports_ip_medium_and_the_wireguard_mtu() {
        let device = VirtDevice::default();
        let caps = device.capabilities();
        assert_eq!(caps.medium, Medium::Ip);
        assert_eq!(caps.max_transmission_unit, TUNNEL_MTU);
        assert_eq!(TUNNEL_MTU, 1420);
    }

    #[test]
    fn outbound_frames_are_queued_and_the_queue_is_bounded() {
        let mut device = VirtDevice::default();
        for i in 0..MAX_DEVICE_QUEUE + 10 {
            let token = device.transmit(SmolInstant::now()).unwrap();
            token.consume(4, |buf| buf.copy_from_slice(&(i as u32).to_be_bytes()));
        }
        let mut seen = 0;
        while device.pop_tx().is_some() {
            seen += 1;
        }
        assert_eq!(seen, MAX_DEVICE_QUEUE, "a full ring drops, like a NIC");
    }

    /// Two stacks joined at the device: each one's tx becomes the other's
    /// rx. Proves the whole stack wiring -- connect, listen, data both
    /// ways -- without WireGuard in the picture, so a stack bug cannot hide
    /// behind a session bug.
    #[test]
    fn tcp_flows_between_two_stacks_joined_at_the_device() {
        let mut a = Stack::new("10.0.0.2/32".parse().unwrap(), None).unwrap();
        let mut b = Stack::new("10.0.0.1/32".parse().unwrap(), None).unwrap();
        let listener = b.tcp_listen(7).unwrap();
        let connector = a
            .tcp_connect(Ipv4Addr::new(10, 0, 0, 1), 7)
            .expect("connect is accepted by the stack");

        let join = |a: &mut Stack, b: &mut Stack| {
            while let Some(p) = a.pop_outbound() {
                b.feed(p);
            }
            while let Some(p) = b.pop_outbound() {
                a.feed(p);
            }
        };

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut received = Vec::new();
        let mut sent = false;
        let mut echoed = false;
        loop {
            a.poll();
            b.poll();
            join(&mut a, &mut b);

            if a.tcp(connector).state() == tcp::State::Established && !sent {
                let n = a.tcp(connector).send_slice(b"ping").unwrap();
                assert_eq!(n, 4);
                sent = true;
            }
            if sent && b.tcp(listener).can_recv() {
                let mut buf = [0u8; 16];
                let n = b.tcp(listener).recv_slice(&mut buf).unwrap();
                received.extend_from_slice(&buf[..n]);
                let _ = b.tcp(listener).send_slice(&buf[..n]);
            }
            if !received.is_empty() && a.tcp(connector).can_recv() {
                let mut buf = [0u8; 16];
                let n = a.tcp(connector).recv_slice(&mut buf).unwrap();
                assert_eq!(&buf[..n], b"ping");
                echoed = true;
            }
            if echoed {
                break;
            }
            assert!(Instant::now() < deadline, "the joined stacks never echoed");
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(received, b"ping");
    }
}
