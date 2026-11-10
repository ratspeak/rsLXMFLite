//! Resumable LXMF proof of work adapted from `lxmf-core::stamper`.
//!
//! Stream the trusted workblock's HKDF chunks into an unfinalized SHA-256 state,
//! instead of retaining up to 768,000 workblock bytes. Each candidate clones that
//! state, preserving its byte count and the exact `SHA256(workblock || stamp)`.
//! The caller owns scheduling, wall-clock limits and entropy; no call searches
//! indefinitely or allocates. Work budgets are operation counts, not durations.
//!
//! Values and costs are fixed point with 8 fractional bits (1.0 is 256), using
//! the `rns_lite_core::stamps` primitives.

use hkdf::Hkdf;
use rns_lite_core::stamps::{
    STAMP_COST_CAP_FP, StampError, StampTarget, stamp_hash, stamp_value_fp_from_hash,
    target_from_fp,
};
use sha2::{Digest, Sha256};

/// Ticket length in bytes; also the length of a ticket stamp.
pub const TICKET_LENGTH: usize = 16;

/// Recipient stamp from a ticket the recipient issued: `truncated_hash(ticket || message_id)`.
///
/// Adapted from `lxmf_core` `SignedLxMessage::generate_recipient_stamp`. Append it with
/// [`crate::propagation::append_recipient_stamp`]; it replaces proof of work entirely.
pub fn ticket_stamp(ticket: &[u8; TICKET_LENGTH], message_id: &[u8; 32]) -> [u8; TICKET_LENGTH] {
    let digest = Sha256::new()
        .chain_update(ticket)
        .chain_update(message_id)
        .finalize();
    let mut stamp = [0; TICKET_LENGTH];
    stamp.copy_from_slice(&digest[..TICKET_LENGTH]);
    stamp
}

/// Protocol-defined workblock sizes, including peering for parity validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StampKind {
    Message,
    Propagation,
    Peering,
}

impl StampKind {
    pub const fn rounds(self) -> u16 {
        match self {
            Self::Message => 3000,
            Self::Propagation => 1000,
            Self::Peering => 25,
        }
    }
}

/// Incrementally constructed prefix, also usable for validating received stamps.
pub struct Workblock {
    material: [u8; 32],
    prefix: Sha256,
    completed: u16,
    rounds: u16,
}

impl Workblock {
    pub fn new(material: [u8; 32], kind: StampKind) -> Self {
        Self {
            material,
            prefix: Sha256::new(),
            completed: 0,
            rounds: kind.rounds(),
        }
    }

    pub fn completed(&self) -> u16 {
        self.completed
    }

    pub fn ready(&self) -> bool {
        self.completed == self.rounds
    }

    /// Perform at most `budget` complete HKDF rounds; zero is a no-op.
    /// Start with a budget of one when qualifying latency on a new target.
    pub fn advance(&mut self, budget: u16) -> bool {
        for _ in 0..budget.min(self.rounds - self.completed) {
            let mut packed = [0; 3];
            let n = pack_round(self.completed, &mut packed);
            let mut salt = Sha256::new();
            salt.update(self.material);
            salt.update(&packed[..n]);
            let hkdf = Hkdf::<Sha256>::new(Some(&salt.finalize()), &self.material);
            let mut chunk = [0; 256];
            // The fixed 256 bytes are below HKDF-SHA256's 8160-byte limit.
            hkdf.expand(&[], &mut chunk).expect("fixed HKDF length");
            self.prefix.update(chunk);
            self.completed += 1;
        }
        self.ready()
    }

    fn hash(&self, stamp: &[u8; 32]) -> Option<[u8; 32]> {
        self.ready().then(|| stamp_hash(&self.prefix, stamp))
    }

    /// Fixed-point stamp value (`0..=65536`, 256 per unit of cost), once
    /// preparation completes.
    pub fn value(&self, stamp: &[u8; 32]) -> Option<u32> {
        self.hash(stamp).map(|hash| stamp_value_fp_from_hash(&hash))
    }

    /// Whether `stamp` meets a fixed-point cost, once preparation completes.
    /// Costs above 25600 (cost 100) are checked as 25600, and 0 always passes.
    pub fn valid(&self, stamp: &[u8; 32], cost_fp: u16) -> Option<bool> {
        let target = target_from_fp(cost_fp.min(STAMP_COST_CAP_FP)).expect("clamped to the cap");
        self.hash(stamp).map(|hash| target.accepts(&hash))
    }
}

// All protocol round counts fit u16. Canonical MessagePack unsigned integers.
fn pack_round(round: u16, out: &mut [u8; 3]) -> usize {
    if round <= 0x7f {
        out[0] = round as u8;
        1
    } else if round <= 0xff {
        out[..2].copy_from_slice(&[0xcc, round as u8]);
        2
    } else {
        out[0] = 0xcd;
        out[1..].copy_from_slice(&round.to_be_bytes());
        3
    }
}

/// In `Complete`, `value` is the stamp's real fixed-point value, not the cost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    Preparing { completed: u16, total: u16 },
    Searching { attempts: u64 },
    Complete { stamp: [u8; 32], value: u32 },
    Exhausted,
    Cancelled,
}

/// One caller-owned search. Firmware must also impose its own cost and elapsed
/// time policy. The explicit attempt limit bounds even an impossible advertised
/// cost; it is never expanded from an untrusted cost via a shift.
pub struct StampSearch {
    workblock: Workblock,
    nonce: [u8; 32],
    target: StampTarget,
    attempts: u64,
    limit: u64,
    progress: Progress,
}

impl StampSearch {
    /// `seed` must be 32 fresh bytes from the caller's cryptographic RNG. The
    /// search visits distinct successive 256-bit nonces from that random start.
    /// Material is the message ID (recipient stamp) or transient ID (PN stamp).
    /// `cost` is an integer cost; integer costs above 100 cannot be generated,
    /// as upstream rejects them, so such a search is exhausted at once.
    pub fn new(
        material: [u8; 32],
        kind: StampKind,
        cost: u8,
        seed: [u8; 32],
        attempt_limit: u64,
    ) -> Self {
        let cost_fp = u16::from(cost) << 8;
        if cost_fp > STAMP_COST_CAP_FP {
            let target = target_from_fp(STAMP_COST_CAP_FP).expect("the cap is in range");
            return Self::build(material, kind, target, seed, 0);
        }
        Self::build(
            material,
            kind,
            target_from_fp(cost_fp).expect("checked against the cap"),
            seed,
            attempt_limit,
        )
    }

    /// Like [`Self::new`] with a fixed-point cost; above 25600 is an error.
    /// Cost zero still prepares the workblock and completes with the seed and
    /// its real value.
    pub fn new_fp(
        material: [u8; 32],
        kind: StampKind,
        cost_fp: u16,
        seed: [u8; 32],
        attempt_limit: u64,
    ) -> Result<Self, StampError> {
        Ok(Self::build(
            material,
            kind,
            target_from_fp(cost_fp)?,
            seed,
            attempt_limit,
        ))
    }

    fn build(
        material: [u8; 32],
        kind: StampKind,
        target: StampTarget,
        seed: [u8; 32],
        attempt_limit: u64,
    ) -> Self {
        Self {
            workblock: Workblock::new(material, kind),
            nonce: seed,
            target,
            attempts: 0,
            limit: attempt_limit,
            progress: if attempt_limit == 0 {
                Progress::Exhausted
            } else {
                Progress::Preparing {
                    completed: 0,
                    total: kind.rounds(),
                }
            },
        }
    }

    pub fn progress(&self) -> Progress {
        self.progress
    }

    pub fn attempts(&self) -> u64 {
        self.attempts
    }

    /// Cancel active preparation or searching. Terminal results remain stable.
    pub fn cancel(&mut self) {
        if matches!(
            self.progress,
            Progress::Preparing { .. } | Progress::Searching { .. }
        ) {
            self.progress = Progress::Cancelled;
        }
    }

    /// One bounded scheduling slice. Preparation and search never occur in the
    /// same call, so callers can measure and budget their different costs.
    pub fn step(&mut self, round_budget: u16, attempt_budget: u32) -> Progress {
        match self.progress {
            Progress::Preparing { total, .. } => {
                self.progress = if self.workblock.advance(round_budget) {
                    Progress::Searching {
                        attempts: self.attempts,
                    }
                } else {
                    Progress::Preparing {
                        completed: self.workblock.completed(),
                        total,
                    }
                };
            }
            Progress::Searching { .. } => {
                for _ in 0..u64::from(attempt_budget).min(self.limit - self.attempts) {
                    let hash = self.workblock.hash(&self.nonce).expect("prepared prefix");
                    self.attempts += 1;
                    if self.target.accepts(&hash) {
                        self.progress = Progress::Complete {
                            stamp: self.nonce,
                            value: stamp_value_fp_from_hash(&hash),
                        };
                        return self.progress;
                    }
                    for byte in self.nonce.iter_mut().rev() {
                        let (next, carry) = byte.overflowing_add(1);
                        *byte = next;
                        if !carry {
                            break;
                        }
                    }
                }
                self.progress = if self.attempts == self.limit {
                    Progress::Exhausted
                } else {
                    Progress::Searching {
                        attempts: self.attempts,
                    }
                };
            }
            _ => {}
        }
        self.progress
    }
}
