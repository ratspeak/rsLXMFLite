//! Resumable LXMF proof of work adapted from `lxmf-core::stamper`.
//!
//! Stream the trusted workblock's HKDF chunks into an unfinalized SHA-256 state,
//! instead of retaining 256–768 KiB of workblock. Each candidate clones that
//! state, preserving its byte count and the exact `SHA256(workblock || stamp)`.
//! The caller owns scheduling, wall-clock limits and entropy; no call searches
//! indefinitely or allocates. Work budgets are operation counts, not durations.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

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

    /// Leading zero bits of the exact protocol hash, once preparation completes.
    pub fn value(&self, stamp: &[u8; 32]) -> Option<u32> {
        if !self.ready() {
            return None;
        }
        let mut digest = self.prefix.clone();
        digest.update(stamp);
        let mut value = 0;
        for byte in digest.finalize() {
            value += byte.leading_zeros();
            if byte != 0 {
                break;
            }
        }
        Some(value)
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
    cost: u8,
    attempts: u64,
    limit: u64,
    progress: Progress,
}

impl StampSearch {
    /// `seed` must be 32 fresh bytes from the caller's cryptographic RNG. The
    /// search visits distinct successive 256-bit nonces from that random start.
    /// Material is the message ID (recipient stamp) or transient ID (PN stamp).
    /// Cost zero completes immediately, retaining the required 32-byte stamp.
    pub fn new(
        material: [u8; 32],
        kind: StampKind,
        cost: u8,
        seed: [u8; 32],
        attempt_limit: u64,
    ) -> Self {
        Self {
            workblock: Workblock::new(material, kind),
            nonce: seed,
            cost,
            attempts: 0,
            limit: attempt_limit,
            progress: if cost == 0 {
                Progress::Complete {
                    stamp: [0; 32],
                    value: 0,
                }
            } else if attempt_limit == 0 {
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
                    let value = self.workblock.value(&self.nonce).expect("prepared prefix");
                    self.attempts += 1;
                    if value >= u32::from(self.cost) {
                        self.progress = Progress::Complete {
                            stamp: self.nonce,
                            value,
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
