//! BEHAVIOURAL proof that a message is delivered, acknowledged, and reported
//! honestly — over real sockets, between two independent transports.
//!
//! This is the gap the unit tests cannot close. They drive `Core` methods
//! directly: no threads, no sockets, no discovery, and a substituted clock.
//! That is the right way to test the decision rules, and it is not evidence
//! that two transports on a network agree. The project's own record is that
//! 254 passing tests proved none of 59 defects absent.
//!
//! What this exercises that nothing else does: mDNS discovery finding a peer,
//! a TCP link dialled to the address it announced, a handshake over that
//! link, a message sealed and sent, and an acknowledgement coming back from
//! the peer's own key — end to end, with the transport's real timers.
//!
//! It is still ONE host. Two machines remain outstanding, and this does not
//! substitute for them: it cannot catch anything that depends on a real
//! network (MTU, NAT, multicast that a switch drops, interface selection).
//! It catches everything that depends on the code.
//!
//! Run: cargo run -p patanyx-chat --example delivery-probe

use std::sync::mpsc;
use std::time::{Duration, Instant};

use patanyx_chat::{Delivery, Identity, Transport, TransportConfig, TransportEvent};

/// Long enough for mDNS to announce and be browsed on a quiet host; short
/// enough that a broken run fails rather than hangs. A probe that hangs is a
/// probe nobody runs twice.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(20);
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(15);

fn main() {
    let mut failures: Vec<String> = Vec::new();

    let alice_id = Identity::generate();
    let bob_id = Identity::generate();
    let alice_fp = alice_id.fingerprint();
    let bob_fp = bob_id.fingerprint();
    println!("alice {}", alice_fp.to_hash_number());
    println!("bob   {}", bob_fp.to_hash_number());

    let (alice_tx, alice_events) = mpsc::channel();
    let (bob_tx, bob_events) = mpsc::channel();

    let alice = Transport::start(
        TransportConfig {
            identities: vec![alice_id],
            relay: None,
            relay_token: None,
            lan_port: 0,
            expected_peer_key: None,
        },
        move |event| {
            let _ = alice_tx.send(event);
        },
    )
    .expect("alice transport");
    let bob = Transport::start(
        TransportConfig {
            identities: vec![bob_id],
            relay: None,
            relay_token: None,
            lan_port: 0,
            expected_peer_key: None,
        },
        move |event| {
            let _ = bob_tx.send(event);
        },
    )
    .expect("bob transport");

    // --- discovery -----------------------------------------------------------
    //
    // The one thing that had silently never worked before it was fixed: an
    // empty address string yields addr_auto: false, and the daemon then
    // refuses to answer TYPE_SRV queries at all. Nothing but a real
    // announcement proves it.
    println!("\n=== discovery ===");
    let found = wait_for(&alice_events, DISCOVERY_TIMEOUT, |event| {
        matches!(event, TransportEvent::PeerAppeared { fingerprint, .. } if *fingerprint == bob_fp)
    });
    if found.is_none() {
        println!("PROBE FAIL: alice never discovered bob over mDNS");
        println!("  Nothing below can run. On a host with no multicast (many");
        println!("  containers), that is the environment and not the browser —");
        println!("  but it is also not a pass, and must not be recorded as one.");
        std::process::exit(1);
    }
    println!("  alice discovered bob");

    // --- session -------------------------------------------------------------
    println!("\n=== session ===");
    alice.open_session(alice_fp, bob_fp).expect("open_session");
    let established = wait_for(&alice_events, SESSION_TIMEOUT, |event| {
        matches!(event, TransportEvent::SessionEstablished { peer, .. } if *peer == bob_fp)
    });
    if established.is_none() {
        println!("PROBE FAIL: no session was established");
        println!("  Both transports are up and alice found bob, so this is a");
        println!("  dial or handshake failure. Re-run with PATANYX_PROBE_TRACE=1");
        println!("  to print every event both sides saw.");
        std::process::exit(1);
    }
    println!("  session established over a dialled TCP link");

    // --- the message ---------------------------------------------------------
    println!("\n=== delivery ===");
    let text = "probe: did this arrive?";
    let mid = alice.send_text(bob_fp, text).expect("send_text");
    println!("  sent, id {}", hex(&mid));

    // Bob must SHOW it...
    match wait_for(&bob_events, DELIVERY_TIMEOUT, |event| {
        matches!(event, TransportEvent::Message { text: got, .. } if got == text)
    }) {
        Some(_) => println!("  bob received the text"),
        None => failures.push("bob never received the message".into()),
    }

    // ...and alice must learn that from bob's own key, not from having sent it.
    let mut states: Vec<Delivery> = Vec::new();
    let deadline = Instant::now() + DELIVERY_TIMEOUT;
    while Instant::now() < deadline {
        match alice_events.recv_timeout(Duration::from_millis(200)) {
            Ok(TransportEvent::Delivery { mid: got, state, .. }) if got == mid => {
                println!("  delivery: {}", state.as_str());
                states.push(state);
                if state.is_terminal() {
                    break;
                }
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
    match states.last() {
        Some(Delivery::Delivered) => println!("  acknowledged by bob's key"),
        other => failures.push(format!(
            "expected Delivered, observed {:?}",
            other.map(|s| s.as_str())
        )),
    }
    if states.first() != Some(&Delivery::Sending) {
        failures.push(format!(
            "a message must be reported Sending before anything confirms it; observed {:?}",
            states.iter().map(|s| s.as_str()).collect::<Vec<_>>()
        ));
    }

    // --- the negative control ------------------------------------------------
    //
    // Without this the run above proves only that a working path works. The
    // property that matters is the other one: when the peer is GONE, the
    // sender must be told, and must never be told Delivered.
    println!("\n=== negative control: the peer goes away ===");
    bob.shutdown();
    // Let the link die and the transport notice.
    std::thread::sleep(Duration::from_secs(2));
    while alice_events.try_recv().is_ok() {}

    let orphan = alice.send_text(bob_fp, "probe: nobody is listening");
    match orphan {
        Ok(mid) => {
            let mut final_state = None;
            let deadline = Instant::now() + DELIVERY_TIMEOUT + Duration::from_secs(15);
            while Instant::now() < deadline {
                if let Ok(TransportEvent::Delivery { mid: got, state, .. }) =
                    alice_events.recv_timeout(Duration::from_millis(200))
                {
                    if got == mid {
                        println!("  delivery: {}", state.as_str());
                        if state.is_terminal() {
                            final_state = Some(state);
                            break;
                        }
                    }
                }
            }
            match final_state {
                Some(Delivery::Delivered) => failures
                    .push("a message to a departed peer was reported DELIVERED".into()),
                Some(Delivery::Failed(reason)) => {
                    println!("  failed honestly: {}", reason.as_str())
                }
                _ => failures.push(
                    "a message to a departed peer never reached a verdict; it would sit at \
                     Sending forever"
                        .into(),
                ),
            }
        }
        Err(e) => println!("  refused synchronously: {e}"),
    }

    alice.shutdown();

    println!();
    if failures.is_empty() {
        println!("DELIVERY PROBE OK");
    } else {
        for failure in &failures {
            println!("PROBE FAIL: {failure}");
        }
        std::process::exit(1);
    }
}

fn wait_for(
    events: &mpsc::Receiver<TransportEvent>,
    timeout: Duration,
    predicate: impl Fn(&TransportEvent) -> bool,
) -> Option<TransportEvent> {
    let trace = std::env::var_os("PATANYX_PROBE_TRACE").is_some();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match events.recv_timeout(Duration::from_millis(200)) {
            Ok(event) => {
                if trace {
                    eprintln!("    {event:?}");
                }
                if predicate(&event) {
                    return Some(event);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
    None
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
