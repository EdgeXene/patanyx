use thiserror::Error;

#[derive(Debug, Error)]
pub enum IntegrityError {
    /// Refused rather than allocated against: this parser consumes bytes
    /// from the open web, so input size is capped. Framing/parsing problems
    /// never reach this enum because the tokenizer is a total function —
    /// malformed HTML is normalized, not rejected.
    #[error("input too large: {len} bytes (max {max})")]
    InputTooLarge { len: usize, max: usize },
}
