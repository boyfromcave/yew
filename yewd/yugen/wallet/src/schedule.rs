// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The fixed sync schedule of spec 0.5.2 §17.8 item 1 (addendum ruling 16): a wallet syncs with
//! its hosts once per `SYNC_PERIOD_BLOCKS` (16) blocks, at heights `h ≡ 0 (mod 16)` (one phase for
//! every wallet), after a delay drawn afresh from 0 to 60 seconds; opening the app or asking for a
//! balance never triggers a session. A wallet that was offline covers the missed periods at its
//! next scheduled time, at most `MAX_CATCH_UP_PERIODS` (96) periods in one sync.

use yugen_ref::params::SYNC_PERIOD_BLOCKS;

/// §17.8 item 1: at most 96 periods in one sync, the rest in following syncs.
pub const MAX_CATCH_UP_PERIODS: u32 = 96;
/// §17.8 item 1: the delay after the boundary block, uniform in `[0, 60]` seconds.
pub const MAX_DELAY_SECS: u64 = 60;

/// The last sync boundary at or below `tip`.
pub fn boundary(tip: u32) -> u32 {
    tip / SYNC_PERIOD_BLOCKS * SYNC_PERIOD_BLOCKS
}

/// The boundary after `tip`: when the next session is due.
pub fn next_boundary(tip: u32) -> u32 {
    boundary(tip) + SYNC_PERIOD_BLOCKS
}

/// The boundary a session run now syncs to, or `None` when no session is due: the latest
/// boundary at or below `tip`, at or above activation, past the last session's, and at most
/// `MAX_CATCH_UP_PERIODS` periods past it.
pub fn due(last: Option<u32>, tip: u32, activation: u32) -> Option<u32> {
    let b = boundary(tip);
    if b < activation {
        return None;
    }
    match last {
        Some(l) if l >= b => None,
        Some(l) => Some(b.min(l + MAX_CATCH_UP_PERIODS * SYNC_PERIOD_BLOCKS)),
        None => Some(b),
    }
}

/// The delay before a session, uniform in `[0, max]` seconds, from 8 bytes of OS randomness.
pub fn delay_secs(max: u64) -> u64 {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("os random");
    u64::from_le_bytes(b) % (max + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_only_at_boundaries_once_each() {
        assert_eq!(boundary(127), 112);
        assert_eq!(next_boundary(112), 128);
        assert_eq!(due(None, 111, 112), None, "below activation");
        assert_eq!(due(None, 112, 112), Some(112));
        assert_eq!(due(Some(112), 127, 112), None, "one session per period");
        assert_eq!(due(Some(112), 128, 112), Some(128));
        assert_eq!(due(Some(112), 200, 112), Some(192), "the latest boundary covers the missed periods");
    }

    #[test]
    fn catch_up_capped_at_96_periods() {
        let far = 112 + 300 * 16;
        assert_eq!(due(Some(112), far, 112), Some(112 + 96 * 16));
        assert_eq!(due(Some(112 + 96 * 16), far, 112), Some(112 + 192 * 16));
    }

    #[test]
    fn delay_within_bound() {
        for _ in 0..1000 {
            assert!(delay_secs(MAX_DELAY_SECS) <= 60);
        }
        assert_eq!(delay_secs(0), 0);
    }
}
