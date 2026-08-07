//! The SOCKS5 front door: an RFC 1928 server on 127.0.0.1 that turns
//! loopback TCP connections into smoltcp sockets through the WireGuard
//! stack.
//!
//! WHAT IS DELIBERATELY REFUSED. Authentication methods other than NO AUTH
//! (the listener is loopback-only; credentials would protect nothing and
//! would invite the config to grow a password store). Every command except
//! CONNECT (0x07): a browser proxy CONNECTs, and UDP ASSOCIATE would need a
//! UDP relay this pass does not build. IPv6 targets (0x08): the stack is
//! IPv4-only; pretending otherwise would hang connects instead of refusing
//! them. And above all: any connection when the tunnel session is not
//! established (0x01), and any connection to anything other than through
//! the tunnel. There is no code path from this module to the host network.
//!
//! FAIL CLOSED, STRUCTURALLY. A `Client` owns a loopback `TcpStream` and
//! gets, per step, a `&mut Stack` and an `up: bool`. It cannot see the
//! host's sockets because nothing hands it any. The `up` check in
//! `step_request` is therefore not one guard among many -- it is the only
//! door, and the tests in lib.rs say which line to break to prove they can
//! fail.
//!
//! Nonblocking throughout: the core thread steps every client on every
//! tick, and every buffer below is bounded, so a stalled or flooding
//! client cannot take the others (or the tunnel) with it.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use smoltcp::iface::SocketHandle;
use smoltcp::socket::{dns, tcp};

use crate::stack::{DnsVerdict, Stack};

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;

const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// Longest greeting+request we will buffer. A real preamble tops out near
/// 262 bytes (domain form); anything longer is not a client we serve.
const MAX_SOCKS_PREAMBLE: usize = 512;

/// Per-direction queue bounds. When `out` is full we stop draining the
/// tunnel socket (its window closes -- TCP backpressure does the rest);
/// when `to_tunnel` is full we stop reading the client (same mechanism).
const MAX_TO_CLIENT: usize = 64 * 1024;
const MAX_TO_TUNNEL: usize = 64 * 1024;

/// Most bytes one client may move in one direction per core tick, so one
/// busy stream cannot starve the others between polls.
const IO_CAP_PER_TICK: usize = 64 * 1024;

/// A tunnel-side connect that has not completed by now is not completing.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A DNS answer that has not arrived by now is not arriving.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// A refusal or trailing bytes the client will not read: how long the flush
/// is allowed to take before the slot is reclaimed. A client that stopped
/// reading must not hold one of MAX_CLIENTS slots forever.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Simultaneous proxied connections. Bounded so a loopback connect flood
/// is a refusal, not a memory problem.
pub(crate) const MAX_CLIENTS: usize = 64;

/// The listener: loopback, and ONLY loopback, on an ephemeral port. This
/// proxy exists for this browser; binding 0.0.0.0 would make it a service
/// for the LAN, which is the one thing a "fail closed" feature must never
/// accidentally become.
pub(crate) fn bind_listener() -> io::Result<TcpListener> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Accepts and hands off, nothing more: the SOCKS handshake happens on the
/// core thread, so a slow client cannot stall acceptance.
pub(crate) fn accept_loop(
    listener: TcpListener,
    accepted: SyncSender<TcpStream>,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let _ = stream.set_nodelay(true);
                let _ = stream.set_nonblocking(true);
                match accepted.try_send(stream) {
                    Ok(()) => {}
                    // A full queue means the core is saturated: drop THIS
                    // client, keep accepting. Blocking here would make
                    // shutdown() unable to join this thread.
                    Err(TrySendError::Full(_)) => {}
                    Err(TrySendError::Disconnected(_)) => return,
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            // Transient accept errors (fd pressure, ...) must not kill the
            // listener.
            Err(_) => thread::sleep(Duration::from_millis(500)),
        }
    }
}

/// Accepts and immediately drops, nothing more: the proxy's state while no
/// tunnel configuration exists yet (the vault holding it is still locked).
/// The engine treats a closed proxy connection as a failed request, which
/// is precisely the fail-closed behaviour wanted in that window -- it never
/// hangs and it never falls back to a direct route. Same cadence as
/// `accept_loop` so `BoundProxy::drop` joins quickly.
pub(crate) fn refuse_loop(listener: TcpListener, shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _addr)) => drop(stream),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            // Transient accept errors must not kill the listener, exactly
            // as in accept_loop.
            Err(_) => thread::sleep(Duration::from_millis(500)),
        }
    }
}

/// What a CONNECT asks for. IPv6 is not here because it is refused at parse
/// time with 0x08 (see the module docs), not carried.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Target {
    V4(Ipv4Addr, u16),
    Domain(String, u16),
}

pub(crate) enum Greeting {
    NeedMore,
    Accept { consumed: usize },
    RefuseMethods,
    NotSocks,
}

fn parse_greeting(buf: &[u8]) -> Greeting {
    if buf.len() < 2 {
        return Greeting::NeedMore;
    }
    if buf[0] != SOCKS_VERSION {
        return Greeting::NotSocks;
    }
    let nmethods = buf[1] as usize;
    if buf.len() < 2 + nmethods {
        return Greeting::NeedMore;
    }
    if buf[2..2 + nmethods].contains(&METHOD_NO_AUTH) {
        Greeting::Accept { consumed: 2 + nmethods }
    } else {
        Greeting::RefuseMethods
    }
}

pub(crate) enum Request {
    NeedMore,
    Connect { target: Target, consumed: usize },
    Reject { reply: u8 },
    NotSocks,
}

fn parse_request(buf: &[u8]) -> Request {
    if buf.len() < 4 {
        return Request::NeedMore;
    }
    if buf[0] != SOCKS_VERSION {
        return Request::NotSocks;
    }
    if buf[1] != CMD_CONNECT {
        return Request::Reject { reply: REP_CMD_NOT_SUPPORTED };
    }
    // buf[2] (RSV) is read and tolerated rather than enforced: refusing a
    // nonzero RSV buys nothing and costs a real client someday.
    match buf[3] {
        ATYP_IPV4 => {
            if buf.len() < 10 {
                return Request::NeedMore;
            }
            let addr = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Request::Connect { target: Target::V4(addr, port), consumed: 10 }
        }
        ATYP_DOMAIN => {
            if buf.len() < 5 {
                return Request::NeedMore;
            }
            let len = buf[4] as usize;
            if buf.len() < 5 + len + 2 {
                return Request::NeedMore;
            }
            let port = u16::from_be_bytes([buf[5 + len], buf[6 + len]]);
            match std::str::from_utf8(&buf[5..5 + len]).ok().filter(|n| plausible_dns_name(n)) {
                Some(name) => Request::Connect {
                    target: Target::Domain(name.to_string(), port),
                    consumed: 5 + len + 2,
                },
                None => Request::Reject { reply: REP_GENERAL_FAILURE },
            }
        }
        // IPv6 and every unknown ATYP: the RFC's answer is 0x08.
        _ => Request::Reject { reply: REP_ATYP_NOT_SUPPORTED },
    }
}

/// Conservative DNS-name check: letters, digits, hyphens, dots, sane
/// length. This is not validation for the resolver (smoltcp does its own);
/// it keeps garbage out of a query packet.
fn plausible_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

fn reply_bytes(code: u8) -> [u8; 10] {
    // BND.ADDR/BND.PORT are zero: for a CONNECT terminated inside a
    // userspace tunnel there is no meaningful bound address to report, and
    // RFC 1928 leaves the server the choice.
    [SOCKS_VERSION, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]
}

/// Whether the core keeps this client around after its step.
pub(crate) enum Step {
    Keep,
    Remove,
}

#[derive(Clone, Copy)]
enum Phase {
    Greeting,
    Request,
    Resolving,
    Connecting,
    Relay,
    Draining,
}

enum ClientState {
    Greeting { buf: Vec<u8> },
    Request { buf: Vec<u8> },
    Resolving { query: dns::QueryHandle, port: u16, deadline: Instant },
    Connecting { handle: SocketHandle, deadline: Instant },
    Relay { handle: SocketHandle, client_eof: bool, fin_sent: bool },
    /// Flush `out`, then go away. Deadline-bounded: see `DRAIN_TIMEOUT`.
    Draining { deadline: Instant },
}

impl ClientState {
    fn draining() -> Self {
        ClientState::Draining { deadline: Instant::now() + DRAIN_TIMEOUT }
    }
}

pub(crate) struct Client {
    stream: TcpStream,
    state: ClientState,
    /// Bytes queued toward the loopback client (replies + tunneled data).
    out: VecDeque<u8>,
    /// Bytes read from the client, queued toward the tunnel socket.
    to_tunnel: VecDeque<u8>,
}

impl Client {
    pub(crate) fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            state: ClientState::Greeting { buf: Vec::new() },
            out: VecDeque::new(),
            to_tunnel: VecDeque::new(),
        }
    }

    fn phase(&self) -> Phase {
        match self.state {
            ClientState::Greeting { .. } => Phase::Greeting,
            ClientState::Request { .. } => Phase::Request,
            ClientState::Resolving { .. } => Phase::Resolving,
            ClientState::Connecting { .. } => Phase::Connecting,
            ClientState::Relay { .. } => Phase::Relay,
            ClientState::Draining { .. } => Phase::Draining,
        }
    }

    /// One core tick of this client's life. `up` is the fail-closed gate;
    /// see the module docs for why it is shaped this way.
    pub(crate) fn step(&mut self, stack: &mut Stack, up: bool) -> Step {
        if self.flush_out().is_err() {
            self.discard_tunnel_side(stack);
            return Step::Remove;
        }
        let result = match self.phase() {
            Phase::Greeting => self.step_greeting(),
            Phase::Request => self.step_request(stack, up),
            Phase::Resolving => self.step_resolving(stack),
            Phase::Connecting => self.step_connecting(stack),
            Phase::Relay => self.step_relay(stack),
            Phase::Draining => self.step_draining(),
        };
        match result {
            Ok(()) => Step::Keep,
            Err(()) => {
                self.discard_tunnel_side(stack);
                Step::Remove
            }
        }
    }

    fn flush_out(&mut self) -> io::Result<()> {
        while !self.out.is_empty() {
            match self.stream.write(self.out.make_contiguous()) {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    self.out.drain(..n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Read whatever is waiting into `buf`. Err means the stream is dead or
    /// the preamble overflowed: the client is done either way.
    fn read_into(&mut self, buf: &mut Vec<u8>) -> Result<(), ()> {
        let mut tmp = [0u8; 4096];
        loop {
            if buf.len() >= MAX_SOCKS_PREAMBLE {
                return Err(());
            }
            match self.stream.read(&mut tmp) {
                Ok(0) => return Err(()), // EOF mid-handshake
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(_) => return Err(()),
            }
        }
    }

    fn step_greeting(&mut self) -> Result<(), ()> {
        let mut buf = match std::mem::replace(&mut self.state, ClientState::draining()) {
            ClientState::Greeting { buf } => buf,
            other => {
                self.state = other;
                return Ok(());
            }
        };
        self.read_into(&mut buf)?;
        match parse_greeting(&buf) {
            Greeting::NeedMore => {
                self.state = ClientState::Greeting { buf };
                Ok(())
            }
            Greeting::NotSocks => Err(()),
            Greeting::RefuseMethods => {
                self.out.extend([SOCKS_VERSION, METHOD_NO_ACCEPTABLE]);
                self.state = ClientState::draining();
                Ok(())
            }
            Greeting::Accept { consumed } => {
                self.out.extend([SOCKS_VERSION, METHOD_NO_AUTH]);
                // Bytes past the greeting belong to the request.
                let rest = buf.split_off(consumed);
                self.state = ClientState::Request { buf: rest };
                Ok(())
            }
        }
    }

    fn step_request(&mut self, stack: &mut Stack, up: bool) -> Result<(), ()> {
        let mut buf = match std::mem::replace(&mut self.state, ClientState::draining()) {
            ClientState::Request { buf } => buf,
            other => {
                self.state = other;
                return Ok(());
            }
        };
        self.read_into(&mut buf)?;
        match parse_request(&buf) {
            Request::NeedMore => {
                self.state = ClientState::Request { buf };
                Ok(())
            }
            Request::NotSocks => Err(()),
            Request::Reject { reply } => {
                self.out.extend(reply_bytes(reply));
                self.state = ClientState::draining();
                Ok(())
            }
            Request::Connect { target, consumed } => {
                // Bytes past the request are already payload (RFC 1928
                // clients may pipeline); keep them for the relay.
                let rest = buf.split_off(consumed);
                self.to_tunnel.extend(rest);

                // FAIL CLOSED. This is the one property the whole feature
                // exists for: with no established session the request dies
                // HERE with general failure. There is deliberately no other
                // code path that opens a connection -- `stack` is the only
                // egress this module can see, and it emits into the tunnel
                // or nowhere. The lib.rs tests name this check as the line
                // to break when proving they can fail.
                if !up {
                    self.out.extend(reply_bytes(REP_GENERAL_FAILURE));
                    self.state = ClientState::draining();
                    return Ok(());
                }

                match target {
                    Target::V4(addr, port) => self.begin_connect(stack, addr, port),
                    Target::Domain(name, port) => match stack.dns_start(&name) {
                        Some(query) => {
                            self.state = ClientState::Resolving {
                                query,
                                port,
                                deadline: Instant::now() + RESOLVE_TIMEOUT,
                            };
                            Ok(())
                        }
                        // No in-tunnel resolver (the config named no DNS
                        // server, or the query table is full): refuse.
                        // Resolving through the HOST would leak exactly what
                        // the tunnel exists to protect.
                        None => {
                            self.out.extend(reply_bytes(REP_GENERAL_FAILURE));
                            self.state = ClientState::draining();
                            Ok(())
                        }
                    },
                }
            }
        }
    }

    fn begin_connect(&mut self, stack: &mut Stack, addr: Ipv4Addr, port: u16) -> Result<(), ()> {
        match stack.tcp_connect(addr, port) {
            Ok(handle) => {
                self.state = ClientState::Connecting {
                    handle,
                    deadline: Instant::now() + CONNECT_TIMEOUT,
                };
            }
            Err(_) => {
                self.out.extend(reply_bytes(REP_CONNECTION_REFUSED));
                self.state = ClientState::draining();
            }
        }
        Ok(())
    }

    fn step_resolving(&mut self, stack: &mut Stack) -> Result<(), ()> {
        let (query, port, deadline) = match &self.state {
            ClientState::Resolving { query, port, deadline } => (*query, *port, *deadline),
            _ => return Ok(()),
        };
        match stack.dns_poll_result(query) {
            DnsVerdict::Pending => {
                if Instant::now() >= deadline {
                    stack.dns_cancel(query);
                    self.out.extend(reply_bytes(REP_GENERAL_FAILURE));
                    self.state = ClientState::draining();
                }
                Ok(())
            }
            DnsVerdict::Failed => {
                self.out.extend(reply_bytes(REP_GENERAL_FAILURE));
                self.state = ClientState::draining();
                Ok(())
            }
            DnsVerdict::Answer(addr) => self.begin_connect(stack, addr, port),
        }
    }

    fn step_connecting(&mut self, stack: &mut Stack) -> Result<(), ()> {
        let (handle, deadline) = match &self.state {
            ClientState::Connecting { handle, deadline } => (*handle, *deadline),
            _ => return Ok(()),
        };
        match stack.tcp(handle).state() {
            tcp::State::Established => {
                self.out.extend(reply_bytes(REP_SUCCESS));
                self.state = ClientState::Relay {
                    handle,
                    client_eof: false,
                    fin_sent: false,
                };
            }
            tcp::State::Closed => {
                // The far end (through the tunnel) refused or reset.
                stack.tcp_remove(handle);
                self.out.extend(reply_bytes(REP_CONNECTION_REFUSED));
                self.state = ClientState::draining();
            }
            _ => {
                if Instant::now() >= deadline {
                    stack.tcp(handle).abort();
                    stack.tcp_remove(handle);
                    self.out.extend(reply_bytes(REP_GENERAL_FAILURE));
                    self.state = ClientState::draining();
                }
            }
        }
        Ok(())
    }

    fn step_relay(&mut self, stack: &mut Stack) -> Result<(), ()> {
        let (handle, mut client_eof, mut fin_sent) = match &self.state {
            ClientState::Relay { handle, client_eof, fin_sent } => {
                (*handle, *client_eof, *fin_sent)
            }
            _ => return Ok(()),
        };

        // 1. client -> to_tunnel (bounded).
        if !client_eof {
            let mut tmp = [0u8; 8192];
            let mut budget = IO_CAP_PER_TICK;
            while self.to_tunnel.len() < MAX_TO_TUNNEL && budget > 0 {
                match self.stream.read(&mut tmp) {
                    Ok(0) => {
                        client_eof = true;
                        break;
                    }
                    Ok(n) => {
                        self.to_tunnel.extend(&tmp[..n]);
                        budget = budget.saturating_sub(n);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => return Err(()),
                }
            }
        }

        // 2. to_tunnel -> the tunnel socket.
        while !self.to_tunnel.is_empty() {
            let sent = {
                let socket = stack.tcp(handle);
                if !socket.can_send() {
                    0
                } else {
                    socket.send_slice(self.to_tunnel.make_contiguous()).unwrap_or(0)
                }
            };
            if sent == 0 {
                break;
            }
            self.to_tunnel.drain(..sent);
        }

        // 3. The client's EOF is real only once its last bytes are queued
        //    on the socket; then we FIN the tunnel side.
        if client_eof && !fin_sent && self.to_tunnel.is_empty() {
            stack.tcp(handle).close();
            fin_sent = true;
        }

        // 4. the tunnel socket -> out (bounded; backpressure does the rest).
        {
            let mut budget = IO_CAP_PER_TICK;
            while self.out.len() < MAX_TO_CLIENT && budget > 0 {
                let mut tmp = [0u8; 8192];
                let n = {
                    let socket = stack.tcp(handle);
                    if !socket.can_recv() {
                        0
                    } else {
                        socket.recv_slice(&mut tmp).unwrap_or(0)
                    }
                };
                if n == 0 {
                    break;
                }
                self.out.extend(&tmp[..n]);
                budget = budget.saturating_sub(n);
            }
        }

        // 5. When the tunnel side can receive no more (peer FIN'd or
        //    closed), everything it had is already drained above: close our
        //    side, flush what we hold, and let Draining end it.
        if !stack.tcp(handle).may_recv() {
            if !fin_sent {
                stack.tcp(handle).close();
            }
            stack.tcp_remove(handle);
            self.state = ClientState::draining();
            return Ok(());
        }

        self.state = ClientState::Relay { handle, client_eof, fin_sent };
        Ok(())
    }

    fn step_draining(&mut self) -> Result<(), ()> {
        // `out` was already flushed at the top of step(); empty means done,
        // and a client that will not read its refusal is not waited on
        // forever.
        let expired = match &self.state {
            ClientState::Draining { deadline } => Instant::now() >= *deadline,
            _ => false,
        };
        if self.out.is_empty() || expired {
            Err(())
        } else {
            Ok(())
        }
    }

    /// Best-effort teardown of whatever tunnel-side resource this client
    /// holds. Every step error path goes through here.
    fn discard_tunnel_side(&mut self, stack: &mut Stack) {
        match self.state {
            ClientState::Connecting { handle, .. } | ClientState::Relay { handle, .. } => {
                stack.tcp(handle).abort();
                stack.tcp_remove(handle);
            }
            ClientState::Resolving { query, .. } => stack.dns_cancel(query),
            _ => {}
        }
        self.state = ClientState::draining();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greetings_parse_incrementally_and_accept_no_auth() {
        assert!(matches!(parse_greeting(&[]), Greeting::NeedMore));
        assert!(matches!(parse_greeting(&[0x05]), Greeting::NeedMore));
        assert!(matches!(parse_greeting(&[0x05, 0x02, 0x00]), Greeting::NeedMore));
        match parse_greeting(&[0x05, 0x02, 0x02, 0x00, 0xAA]) {
            Greeting::Accept { consumed } => assert_eq!(consumed, 4),
            _ => panic!("NO AUTH among the methods must be accepted"),
        }
        assert!(matches!(
            parse_greeting(&[0x05, 0x01, 0x02]),
            Greeting::RefuseMethods
        ));
        assert!(matches!(parse_greeting(&[0x04, 0x01, 0x00]), Greeting::NotSocks));
    }

    #[test]
    fn requests_parse_ipv4_domain_and_truncation() {
        assert!(matches!(parse_request(&[0x05, 0x01]), Request::NeedMore));
        match parse_request(&[0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x00, 0x50]) {
            Request::Connect { target, consumed } => {
                assert_eq!(target, Target::V4(Ipv4Addr::new(93, 184, 216, 34), 80));
                assert_eq!(consumed, 10);
            }
            _ => panic!("a well-formed IPv4 CONNECT must parse"),
        }
        let mut domain = vec![0x05, 0x01, 0x00, 0x03, 11];
        domain.extend_from_slice(b"example.com");
        domain.extend_from_slice(&443u16.to_be_bytes());
        match parse_request(&domain) {
            Request::Connect { target, consumed } => {
                assert_eq!(target, Target::Domain("example.com".into(), 443));
                assert_eq!(consumed, domain.len());
            }
            _ => panic!("a well-formed DOMAIN CONNECT must parse"),
        }
        assert!(matches!(parse_request(&domain[..8]), Request::NeedMore));
    }

    #[test]
    fn refused_requests_carry_the_rfc_1928_reply_codes() {
        // IPv6 target -> 0x08, even though the stack never sees it.
        match parse_request(&[0x05, 0x01, 0x00, 0x04]) {
            Request::Reject { reply } => assert_eq!(reply, 0x08),
            _ => panic!("IPv6 must be rejected with 0x08"),
        }
        // Unknown ATYP -> 0x08 as well.
        match parse_request(&[0x05, 0x01, 0x00, 0x77]) {
            Request::Reject { reply } => assert_eq!(reply, 0x08),
            _ => panic!("unknown ATYP must be rejected with 0x08"),
        }
        // UDP ASSOCIATE -> 0x07.
        match parse_request(&[0x05, 0x03, 0x00, 0x01]) {
            Request::Reject { reply } => assert_eq!(reply, 0x07),
            _ => panic!("non-CONNECT must be rejected with 0x07"),
        }
        // Not SOCKS at all.
        assert!(matches!(parse_request(&[0x04, 0x01, 0x00, 0x01]), Request::NotSocks));
        // A domain name that is not one -> general failure, not a query.
        let mut bad = vec![0x05, 0x01, 0x00, 0x03, 3, b'f', 0x01, b'o'];
        bad.extend_from_slice(&80u16.to_be_bytes());
        match parse_request(&bad) {
            Request::Reject { reply } => assert_eq!(reply, 0x01),
            _ => panic!("an implausible name must be refused"),
        }
    }

    #[test]
    fn replies_are_shaped_like_rfc_1928_says() {
        let reply = reply_bytes(REP_SUCCESS);
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x00);
        assert_eq!(reply[2], 0x00, "RSV");
        assert_eq!(reply.len(), 10, "IPv4-shaped BND");
    }

    #[test]
    fn the_listener_binds_loopback_and_only_loopback() {
        let listener = bind_listener().expect("binds");
        let addr = listener.local_addr().unwrap();
        assert_eq!(addr.ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(addr.port(), 0, "an ephemeral port was assigned");
    }
}
