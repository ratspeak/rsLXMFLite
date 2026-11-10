use lxmf_lite_core::stamp::{Progress, StampKind, StampSearch, Workblock};

const MATERIAL: [u8; 32] = [0x59; 32];

#[test]
fn streamed_prefix_matches_trusted_workblock_all_kinds_and_boundaries() {
    for kind in [
        StampKind::Peering,
        StampKind::Propagation,
        StampKind::Message,
    ] {
        let reference = lxmf_core::stamper::stamp_workblock(&MATERIAL, kind.rounds() as usize);
        let mut workblock = Workblock::new(MATERIAL, kind);
        assert_eq!(workblock.value(&[0; 32]), None);
        assert!(!workblock.advance(0));
        // Single-round stepping crosses the MessagePack 127/128 and 255/256
        // boundaries; state updates must not finalize/reset the prefix hash.
        for round in 1..=kind.rounds() {
            assert_eq!(workblock.advance(1), round == kind.rounds());
            assert_eq!(workblock.completed(), round);
        }
        assert!(workblock.advance(u16::MAX));
        for nonce in 0..32 {
            let stamp = [nonce; 32];
            assert_eq!(
                workblock.value(&stamp),
                Some(rns_identity::stamps::stamp_value_fp(&reference, &stamp))
            );
            assert_eq!(
                workblock.valid(&stamp, 0),
                Some(true),
                "cost 0 always passes"
            );
        }
    }
}

#[test]
fn resumable_search_emits_trusted_valid_stamp_with_identical_scheduling_results() {
    let run = |slice| {
        let mut search =
            StampSearch::new(MATERIAL, StampKind::Propagation, 8.0, [0xfe; 32], 10000).unwrap();
        assert!(matches!(
            search.step(1000, u32::MAX),
            Progress::Searching { attempts: 0 }
        ));
        loop {
            match search.step(0, slice) {
                Progress::Searching { .. } => continue,
                Progress::Complete { stamp, value } => {
                    assert!(value >= 8 * 256);
                    assert!(lxmf_core::stamper::validate_stamp(
                        &MATERIAL, &stamp, 8.0, 1000
                    ));
                    return (stamp, value, search.attempts());
                }
                other => panic!("unexpected {other:?}"),
            }
        }
    };
    assert_eq!(run(1), run(4096));
}

#[test]
fn zero_cost_zero_budgets_exhaustion_and_terminal_states() {
    // Cost zero accepts the first candidate with its real value, as upstream does.
    let mut zero = StampSearch::new(MATERIAL, StampKind::Peering, 0.0, [7; 32], 1).unwrap();
    assert_eq!(zero.step(25, 0), Progress::Searching { attempts: 0 });
    let complete = zero.step(0, 1);
    let reference = lxmf_core::stamper::stamp_workblock(&MATERIAL, 25);
    assert_eq!(
        complete,
        Progress::Complete {
            stamp: [7; 32],
            value: rns_identity::stamps::stamp_value_fp(&reference, &[7; 32]),
        }
    );
    zero.cancel();
    assert_eq!(zero.step(u16::MAX, u32::MAX), complete);
    // Upstream generate_stamp refuses costs outside 0..=100 and NaN.
    for refused in [100.25, 101.0, -0.5, f64::NAN, f64::INFINITY] {
        assert!(StampSearch::new(MATERIAL, StampKind::Peering, refused, [7; 32], 99).is_none());
    }
    let mut empty = StampSearch::new(MATERIAL, StampKind::Propagation, 16.0, [7; 32], 0).unwrap();
    assert_eq!(empty.step(u16::MAX, u32::MAX), Progress::Exhausted);
    let mut hard = StampSearch::new(MATERIAL, StampKind::Peering, 100.0, [0xff; 32], 3).unwrap();
    let start = hard.progress();
    assert_eq!(hard.step(0, 999), start);
    assert_eq!(hard.step(25, 999), Progress::Searching { attempts: 0 });
    assert_eq!(hard.step(0, 0), Progress::Searching { attempts: 0 });
    assert_eq!(hard.step(0, 2), Progress::Searching { attempts: 2 });
    assert_eq!(hard.step(0, u32::MAX), Progress::Exhausted);
    assert_eq!(hard.attempts(), 3);
    hard.cancel();
    assert_eq!(hard.step(25, 999), Progress::Exhausted);
}

#[test]
fn cancellation_stops_both_preparation_and_search() {
    for prepare in [0, 1, 999, 1000] {
        let mut search =
            StampSearch::new(MATERIAL, StampKind::Propagation, 100.0, [7; 32], 99).unwrap();
        search.step(prepare, 0);
        search.cancel();
        assert_eq!(search.step(u16::MAX, u32::MAX), Progress::Cancelled);
        assert_eq!(search.attempts(), 0);
    }
}

#[test]
fn stamp_owner_does_not_retain_workblock_storage() {
    assert!(core::mem::size_of::<Workblock>() <= 256);
    assert!(core::mem::size_of::<StampSearch>() <= 384);
}
