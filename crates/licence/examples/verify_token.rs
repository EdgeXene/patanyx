//! Verify a Premium token against THIS BUILD's compiled-in key ring, from
//! the command line: the ops-side answer to "is this token real, and what
//! state would the browser show for it today?"
//!
//! ```text
//! cargo run -p patanyx-licence --example verify_token -- ptx1-...
//! ```
//!
//! Exit code 0 when the token verifies (Active or Lapsed both count: a
//! lapsed token is still a REAL token), 1 when it does not, 2 on usage
//! errors. The token text is an argument, not stdin, because a token is a
//! bearer credential the caller already holds; nothing here stores or
//! prints more of it than its first characters.

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [token_text] = args.as_slice() else {
        eprintln!("usage: verify_token <ptx1-...>");
        return ExitCode::from(2);
    };

    let keys = match patanyx_licence::licence_keys() {
        Ok(keys) => keys,
        Err(error) => {
            eprintln!("this build's key ring does not construct: {error}");
            return ExitCode::from(2);
        }
    };

    let token = match patanyx_licence::Token::parse(token_text, &keys) {
        Ok(token) => token,
        Err(error) => {
            eprintln!("REFUSED: {error}");
            return ExitCode::FAILURE;
        }
    };

    let today = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the system clock is set after 1970")
        .as_secs()
        / 86_400) as u32;
    match patanyx_licence::evaluate(Some(&token), today) {
        patanyx_licence::LicenceState::Active { days_left } => {
            println!("VERIFIED: Active, {days_left} day(s) left");
        }
        patanyx_licence::LicenceState::Lapsed { expires_day } => {
            println!("VERIFIED: Lapsed (expired on day {expires_day}); the token is real");
        }
        patanyx_licence::LicenceState::Free => unreachable!("a parsed token is never Free"),
    }
    ExitCode::SUCCESS
}
