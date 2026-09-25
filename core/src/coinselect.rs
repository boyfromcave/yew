//! The floor-aware YED coin selector: EXACT, SINGLE, GREEDY, SEARCH for a TRANSFER, plus BURN
//! for a REDEEM or CLAIM; and `NearestWorkable`, the two amounts a `change-floor` refusal names.
//!
//! Translation source (plan §3.6, §3.7): `ycash-dd/src/yellowback/coinselect.{h,cpp}`
//! (`feature/yellowback-price-attest`), verbatim — same stages, same ranking, same tie-breaks,
//! same search budget — so the wallet's selection equals the node's `yed_estimatesend`
//! input-for-input on the same coins (W2 acceptance). Pure: amounts in, indexes out; no wallet,
//! no clock, no randomness. The tables of `src/test/yellowback_coinselect_tests.cpp` are the
//! tests below.
//!
//! Why it exists (`coinselect.h:14-39`): a YED output must be assigned at least `MIN_OUTPUT`
//! ($1.00) cents by the payload (XFER-1), so change in `(0, MIN_OUTPUT)` cannot be assigned and
//! would burn. Smallest-first accumulation hits that band whenever the overshoot is under a
//! dollar, so a user with a single $100.00 coin could not send $99.50.

/// `SelectStage` (`coinselect.h:44`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectStage {
    /// No selection.
    None,
    /// A subset summing exactly to the target (change 0).
    Exact,
    /// One input whose change is `>= minOutput` (the smallest such).
    Single,
    /// Smallest-first accumulation, extended while the change lies in the forbidden band.
    Greedy,
    /// The bounded depth-first search for the smallest valid change, then the fewest inputs.
    Search,
    /// A sub-dollar remainder burned (REDEEM / CLAIM only).
    Burn,
}

impl SelectStage {
    /// `SelectStageName` (`coinselect.cpp:12-23`): the contract's `yed_estimatesend.stage`.
    pub fn name(self) -> &'static str {
        match self {
            SelectStage::Exact => "exact",
            SelectStage::Single => "single",
            SelectStage::Greedy => "greedy",
            SelectStage::Search => "search",
            SelectStage::Burn => "burn",
            SelectStage::None => "none",
        }
    }
}

/// `Selection` (`coinselect.h:49-61`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    /// A usable selection was found.
    pub ok: bool,
    /// `!ok` because the coins do not reach the target at all.
    pub insufficient: bool,
    /// `!ok` because reaching the target would need more than `max_inputs` coins (H11).
    pub too_many_inputs: bool,
    /// The stage that produced it.
    pub stage: SelectStage,
    /// Indexes into the `coins` slice passed in, ascending.
    pub inputs: Vec<usize>,
    /// Sum of the selected coins.
    pub selected: i64,
    /// `selected - target - extra_burn`; 0 or `>= min_output`.
    pub change: i64,
    /// H4 only: cents burned on top of the target, in `[0, min_output)`.
    pub extra_burn: i64,
}

impl Default for Selection {
    fn default() -> Self {
        Selection {
            ok: false,
            insufficient: false,
            too_many_inputs: false,
            stage: SelectStage::None,
            inputs: Vec::new(),
            selected: 0,
            change: 0,
            extra_burn: 0,
        }
    }
}

/// `Alternatives` (`coinselect.h:64-68`): the nearest amounts that *are* workable (H2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Alternatives {
    /// The largest workable amount strictly below the target.
    pub below: Option<i64>,
    /// The smallest workable amount strictly above it.
    pub above: Option<i64>,
}

/// `SELECT_SEARCH_BUDGET` (`coinselect.h:88`): the node budget of stage 4 and of
/// `NearestWorkable` (a bound, never a source of non-determinism).
pub const SELECT_SEARCH_BUDGET: i64 = 200_000;

/// `RankDescending` (`coinselect.cpp:27-42`): descending by cents, ties by position in the
/// caller's slice — what makes the selector independent of the order coins were listed in.
fn rank_descending(coins: &[i64]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..coins.len()).collect();
    order.sort_by(|&a, &b| coins[b].cmp(&coins[a]).then(a.cmp(&b)));
    order
}

/// `RankAscending` (`coinselect.cpp:45-55`): the documented `(cents, index)` order.
fn rank_ascending(coins: &[i64]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..coins.len()).collect();
    order.sort_by(|&a, &b| coins[a].cmp(&coins[b]).then(a.cmp(&b)));
    order
}

/// `Goal` (`coinselect.cpp:58-64`): what a depth-first walk is looking for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Goal {
    /// `sum == target`, fewest inputs.
    Exact,
    /// `sum == target` or `sum >= target + minOutput`, smallest change then fewest inputs.
    ValidChange,
    /// `sum >= target`, smallest sum (H4: the cheapest remainder to burn).
    Overshoot,
    /// `sum > target`, smallest sum (H2).
    Above,
    /// `sum < target`, largest sum (H2).
    Below,
}

/// `Walk` (`coinselect.cpp:66-169`).
struct Walk<'a> {
    coins: &'a [i64],
    order: &'a [usize],
    /// `suffix[i]` = sum of `order[i..]` (the reachability bound).
    suffix: Vec<i64>,
    target: i64,
    min_output: i64,
    max_inputs: usize,
    goal: Goal,
    budget: i64,
    found: bool,
    best_sum: i64,
    /// Positions in `order`.
    best_pick: Vec<usize>,
    pick: Vec<usize>,
}

impl<'a> Walk<'a> {
    fn new(
        coins: &'a [i64],
        order: &'a [usize],
        target: i64,
        min_output: i64,
        max_inputs: usize,
        goal: Goal,
        budget: i64,
    ) -> Walk<'a> {
        let mut suffix = vec![0i64; order.len() + 1];
        for i in (0..order.len()).rev() {
            suffix[i] = suffix[i + 1] + coins[order[i]];
        }
        Walk {
            coins,
            order,
            suffix,
            target,
            min_output,
            max_inputs,
            goal,
            budget,
            found: false,
            best_sum: 0,
            best_pick: Vec::new(),
            pick: Vec::new(),
        }
    }

    fn better(&self, sum: i64, count: usize) -> bool {
        if !self.found {
            return true;
        }
        match self.goal {
            Goal::Exact => count < self.best_pick.len(),
            Goal::ValidChange | Goal::Overshoot => {
                sum < self.best_sum || (sum == self.best_sum && count < self.best_pick.len())
            }
            Goal::Above => sum < self.best_sum,
            Goal::Below => sum > self.best_sum,
        }
    }

    fn record(&mut self, sum: i64) {
        if !self.better(sum, self.pick.len()) {
            return;
        }
        self.found = true;
        self.best_sum = sum;
        self.best_pick = self.pick.clone();
    }

    /// True when the goal can no longer be improved (and the whole walk may stop).
    fn done(&self) -> bool {
        self.found
            && ((self.goal == Goal::Exact && self.best_pick.len() == 1)
                || ((self.goal == Goal::ValidChange || self.goal == Goal::Overshoot)
                    && self.best_sum == self.target))
    }

    fn descend(&mut self, pos: usize, sum: i64) {
        if self.budget <= 0 || self.done() {
            return;
        }
        self.budget -= 1;
        for i in pos..self.order.len() {
            if self.budget <= 0 || self.done() {
                return;
            }
            let value = self.coins[self.order[i]];
            let next = sum + value;
            // Reachability: even taking every remaining coin cannot reach the target.
            if self.goal != Goal::Below && sum + self.suffix[i] < self.target {
                return;
            }
            self.pick.push(i);
            let mut descend = self.pick.len() < self.max_inputs;
            match self.goal {
                Goal::Exact => {
                    if next == self.target {
                        self.record(next);
                        descend = false;
                    } else if next > self.target {
                        descend = false; // positive coins: no way back down
                    }
                }
                Goal::ValidChange => {
                    if next == self.target || next >= self.target + self.min_output {
                        self.record(next);
                        descend = false;
                    }
                    // else if next > target: a crossing that lands in the forbidden band can
                    // only be fixed by adding more — keep descending.
                }
                Goal::Overshoot => {
                    if next >= self.target {
                        self.record(next);
                        descend = false;
                    }
                }
                Goal::Above => {
                    if next > self.target {
                        self.record(next);
                        descend = false;
                    }
                }
                Goal::Below => {
                    if next < self.target {
                        self.record(next);
                    } else {
                        descend = false;
                    }
                }
            }
            if descend {
                self.descend(i + 1, next);
            }
            self.pick.pop();
        }
    }

    /// The selected coin indexes (into the caller's slice), ascending.
    fn result(&self) -> Vec<usize> {
        let mut out: Vec<usize> = self.best_pick.iter().map(|&p| self.order[p]).collect();
        out.sort_unstable();
        out
    }
}

/// `Make` (`coinselect.cpp:171-183`).
fn make(
    stage: SelectStage,
    coins: &[i64],
    idx: Vec<usize>,
    target: i64,
    extra_burn: i64,
) -> Selection {
    let selected: i64 = idx.iter().map(|&i| coins[i]).sum();
    Selection {
        ok: true,
        insufficient: false,
        too_many_inputs: false,
        stage,
        inputs: idx,
        selected,
        change: selected - target - extra_burn,
        extra_burn,
    }
}

/// `Reachable` (`coinselect.cpp:186-191`): the sum of the `max_inputs` largest coins.
fn reachable(coins: &[i64], desc: &[usize], max_inputs: usize) -> i64 {
    desc.iter().take(max_inputs).map(|&i| coins[i]).sum()
}

/// `SelectFloorAware` (`coinselect.cpp:195-263`): select for `target` cents out of `coins`
/// (each `> 0`). `min_output` is `MIN_OUTPUT`, `max_inputs` the H11 cap (250). With
/// `allow_sub_dollar_burn` (REDEEM / CLAIM, H4) a selection whose remainder lies in
/// `(0, min_output)` is accepted as stage BURN when and only when no stage 1-4 selection exists.
pub fn select_floor_aware(
    coins: &[i64],
    target: i64,
    min_output: i64,
    max_inputs: usize,
    allow_sub_dollar_burn: bool,
) -> Selection {
    let mut none = Selection::default();
    if target < 0 {
        return none;
    }
    if target == 0 {
        none.ok = true;
        none.stage = SelectStage::Exact;
        return none;
    }
    let total: i64 = coins.iter().filter(|&&c| c > 0).sum();
    if total < target {
        none.insufficient = true;
        return none;
    }
    let desc = rank_descending(coins);
    if reachable(coins, &desc, max_inputs) < target {
        none.too_many_inputs = true;
        return none;
    }

    // 1. Exact match: change 0 needs no floor at all.
    {
        let mut w = Walk::new(
            coins,
            &desc,
            target,
            min_output,
            max_inputs,
            Goal::Exact,
            SELECT_SEARCH_BUDGET,
        );
        w.descend(0, 0);
        if w.found {
            return make(SelectStage::Exact, coins, w.result(), target, 0);
        }
    }

    // 2. One input whose change clears the floor: the smallest such coin.
    let asc = rank_ascending(coins);
    for &i in &asc {
        if coins[i] >= target + min_output {
            return make(SelectStage::Single, coins, vec![i], target, 0);
        }
    }

    // 3. Greedy smallest-first, extended while the change lies in the forbidden band. This is
    //    also what consolidates small outputs (H11: no consolidation RPC).
    {
        let mut pick = Vec::new();
        let mut sum = 0i64;
        for &i in &asc {
            if coins[i] <= 0 {
                continue;
            }
            if pick.len() == max_inputs {
                break;
            }
            pick.push(i);
            sum += coins[i];
            if sum < target {
                continue;
            }
            let change = sum - target;
            if change == 0 || change >= min_output {
                pick.sort_unstable();
                return make(SelectStage::Greedy, coins, pick, target, 0);
            }
            // change is in (0, min_output): keep extending (the next coin lifts it out).
        }
    }

    // 4. Bounded search for the smallest valid change, then the fewest inputs.
    {
        let mut w = Walk::new(
            coins,
            &desc,
            target,
            min_output,
            max_inputs,
            Goal::ValidChange,
            SELECT_SEARCH_BUDGET,
        );
        w.descend(0, 0);
        if w.found {
            return make(SelectStage::Search, coins, w.result(), target, 0);
        }
    }

    // H4: a REDEEM or a CLAIM may burn a sub-dollar remainder rather than strand the vault.
    if allow_sub_dollar_burn {
        let mut w = Walk::new(
            coins,
            &desc,
            target,
            min_output,
            max_inputs,
            Goal::Overshoot,
            SELECT_SEARCH_BUDGET,
        );
        w.descend(0, 0);
        if w.found {
            let extra = w.best_sum - target;
            if extra > 0 && extra < min_output {
                return make(SelectStage::Burn, coins, w.result(), target, extra);
            }
        }
    }
    none
}

/// `NearestWorkable` (`coinselect.cpp:265-293`): the largest workable amount strictly below
/// `target` and the smallest strictly above it (H2).
pub fn nearest_workable(
    coins: &[i64],
    target: i64,
    min_output: i64,
    max_inputs: usize,
) -> Alternatives {
    let mut alt = Alternatives::default();
    let desc = rank_descending(coins);
    let reach = reachable(coins, &desc, max_inputs);
    if reach <= 0 {
        return alt;
    }
    // Above: the smallest achievable sum strictly above the target (the total is always
    // achievable).
    {
        let mut w = Walk::new(
            coins,
            &desc,
            target,
            min_output,
            max_inputs,
            Goal::Above,
            SELECT_SEARCH_BUDGET,
        );
        w.descend(0, 0);
        let mut above = if w.found { w.best_sum } else { 0 };
        if reach > target && (!w.found || reach < above) {
            above = reach;
        }
        if above > target {
            alt.above = Some(above);
        }
    }
    // Below: anything at or under reach - min_output is workable (spend everything, the change
    // clears the floor), and an achievable sum below the target is workable exactly.
    {
        let mut below = reach - min_output;
        let mut w = Walk::new(
            coins,
            &desc,
            target,
            min_output,
            max_inputs,
            Goal::Below,
            SELECT_SEARCH_BUDGET,
        );
        w.descend(0, 0);
        if w.found && w.best_sum > below {
            below = w.best_sum;
        }
        if below >= min_output && below < target {
            alt.below = Some(below);
        }
    }
    alt
}

#[cfg(test)]
mod tests {
    //! `ycash-dd/src/test/yellowback_coinselect_tests.cpp`, ported table for table.
    use super::*;

    const FLOOR: i64 = crate::params::MIN_OUTPUT_CENTS as i64; // 100 cents = $1.00
    const CAP: usize = crate::params::MAX_INPUTS; // H11

    struct Case {
        name: &'static str,
        coins: Vec<i64>,
        target: i64,
        ok: bool,
        stage: SelectStage,
        change: i64,
    }

    fn case(
        name: &'static str,
        coins: &[i64],
        target: i64,
        ok: bool,
        stage: SelectStage,
        change: i64,
    ) -> Case {
        Case {
            name,
            coins: coins.to_vec(),
            target,
            ok,
            stage,
            change,
        }
    }

    /// `CheckInvariants`: every invariant a selection must satisfy whatever the stage.
    fn check_invariants(c: &Case, s: &Selection, allow_burn: bool) {
        let label = c.name;
        assert!(
            s.extra_burn >= 0 && s.extra_burn < FLOOR,
            "{label}: extraBurn out of [0, MIN_OUTPUT)"
        );
        if !s.ok {
            assert!(
                s.inputs.is_empty(),
                "{label}: a failed selection must name no inputs"
            );
            assert_eq!(
                s.stage,
                SelectStage::None,
                "{label}: a failed selection must be stage NONE"
            );
            return;
        }
        assert!(
            s.inputs.len() <= CAP,
            "{label}: more than the H11 cap of inputs"
        );
        for i in 0..s.inputs.len() {
            assert!(s.inputs[i] < c.coins.len(), "{label}: index out of range");
            if i > 0 {
                assert!(
                    s.inputs[i - 1] < s.inputs[i],
                    "{label}: indexes not strictly ascending"
                );
            }
        }
        let sum: i64 = s.inputs.iter().map(|&i| c.coins[i]).sum();
        assert_eq!(
            sum, s.selected,
            "{label}: selected does not match the coins named"
        );
        assert_eq!(
            s.selected,
            c.target + s.change + s.extra_burn,
            "{label}: the selection does not balance"
        );
        assert!(
            s.change == 0 || s.change >= FLOOR,
            "{label}: change inside the forbidden band"
        );
        if !allow_burn {
            assert_eq!(s.extra_burn, 0, "{label}: a TRANSFER selection burned");
        }
        if s.extra_burn > 0 {
            assert_eq!(
                s.stage,
                SelectStage::Burn,
                "{label}: a burn outside stage BURN"
            );
        }
    }

    /// `CheckDeterministic` (H1).
    fn check_deterministic(coins: &[i64], target: i64, allow_burn: bool) {
        let a = select_floor_aware(coins, target, FLOOR, CAP, allow_burn);
        for _ in 0..3 {
            let b = select_floor_aware(coins, target, FLOOR, CAP, allow_burn);
            assert_eq!(a, b);
        }
    }

    // Rule: H1
    #[test]
    fn h1_selector_table() {
        use SelectStage::*;
        let table = vec![
            // --- stage 1: exact
            case("exact_single_coin", &[1000, 5000], 5000, true, Exact, 0),
            case("exact_two_coins", &[2500, 2500, 9900], 5000, true, Exact, 0),
            case(
                "exact_beats_single_with_change",
                &[5000, 100000],
                5000,
                true,
                Exact,
                0,
            ),
            case("exact_whole_wallet", &[700, 300], 1000, true, Exact, 0),
            // --- stage 2: one input, valid change
            case(
                "single_input_valid_change",
                &[100000],
                4000,
                true,
                Single,
                96000,
            ),
            case(
                "single_smallest_that_works",
                &[9000, 100000],
                4000,
                true,
                Single,
                5000,
            ),
            case(
                "single_exactly_at_the_floor",
                &[4100],
                4000,
                true,
                Single,
                100,
            ),
            // --- stage 3: greedy, and greedy with extension
            case(
                "single_large_coin_when_no_exact",
                &[1000, 4000, 100000],
                4500,
                true,
                Single,
                95500,
            ),
            case(
                "greedy_two_small_coins",
                &[1000, 4000],
                4500,
                true,
                Greedy,
                500,
            ),
            // 99.50 of a 100.00 coin: the classic band (a 50-cent change); adding the dollar coin fixes it.
            case(
                "greedy_extension_over_band",
                &[100, 10000],
                9950,
                true,
                Greedy,
                150,
            ),
            case(
                "greedy_two_small_then_big",
                &[100, 100, 10000],
                9970,
                true,
                Greedy,
                230,
            ),
            // --- H2: nothing works, a TRANSFER must refuse
            case("band_single_coin_only", &[10000], 9950, false, None, 0),
            case(
                "band_all_coins_together",
                &[5000, 5000],
                9950,
                false,
                None,
                0,
            ),
            case("band_three_coins", &[200, 300, 9500], 9950, false, None, 0),
            // --- insufficient
            case("insufficient", &[100, 200], 1000, false, None, 0),
            case("insufficient_by_one_cent", &[999], 1000, false, None, 0),
            // --- exact at the very top of the wallet still works
            case(
                "exact_total_of_many",
                &[100, 100, 100, 100],
                400,
                true,
                Exact,
                0,
            ),
        ];
        for c in &table {
            let s = select_floor_aware(&c.coins, c.target, FLOOR, CAP, false);
            assert_eq!(s.ok, c.ok, "{}: ok = {}", c.name, s.ok);
            assert_eq!(s.stage, c.stage, "{}: stage = {}", c.name, s.stage.name());
            if c.ok {
                assert_eq!(s.change, c.change, "{}: change = {}", c.name, s.change);
            }
            check_invariants(c, &s, false);
            check_deterministic(&c.coins, c.target, false);
        }
    }

    // Rule: H1
    #[test]
    fn h1_insufficient_is_distinguished_from_the_floor() {
        let poor = select_floor_aware(&[100, 200], 1000, FLOOR, CAP, false);
        assert!(!poor.ok && poor.insufficient);
        let band = select_floor_aware(&[10000], 9950, FLOOR, CAP, false);
        assert!(!band.ok && !band.insufficient);
    }

    // Rule: H1
    #[test]
    fn h1_selection_order_is_stable_under_coin_order() {
        let a = [100, 4000, 10000];
        let b = [10000, 100, 4000];
        let sa = select_floor_aware(&a, 4050, FLOOR, CAP, false);
        let sb = select_floor_aware(&b, 4050, FLOOR, CAP, false);
        assert!(sa.ok && sb.ok);
        let mut va: Vec<i64> = sa.inputs.iter().map(|&i| a[i]).collect();
        let mut vb: Vec<i64> = sb.inputs.iter().map(|&i| b[i]).collect();
        va.sort_unstable();
        vb.sort_unstable();
        assert_eq!(va, vb);
        assert_eq!(sa.change, sb.change);
    }

    // Rule: H11
    #[test]
    fn h11_input_cap_is_respected() {
        let coins = vec![100i64; 400];
        let over = select_floor_aware(&coins, 30000, FLOOR, CAP, false);
        assert!(!over.ok && !over.insufficient && over.too_many_inputs);
        let at = select_floor_aware(&coins, 25000, FLOOR, CAP, false);
        assert!(at.ok);
        assert_eq!(at.inputs.len(), CAP);
        assert_eq!(at.change, 0);
    }

    // Rule: H1
    #[test]
    fn h1_bounded_search_when_greedy_is_capped_out() {
        // 300 one-dollar coins and one $255.50 coin; the target is $255.00: only the bounded
        // search finds $255.50 + $1.00 = change $1.50.
        let mut coins = vec![100i64; 300];
        coins.push(25550);
        let s = select_floor_aware(&coins, 25500, FLOOR, CAP, false);
        assert!(s.ok);
        assert_eq!(s.stage, SelectStage::Search);
        assert_eq!(s.change, 150);
        assert_eq!(s.inputs.len(), 2);
        let c = Case {
            name: "bounded_search",
            coins: coins.clone(),
            target: 25500,
            ok: true,
            stage: SelectStage::Search,
            change: 150,
        };
        check_invariants(&c, &s, false);
        check_deterministic(&coins, 25500, false);
    }

    // Rule: H4
    #[test]
    fn h4_redeem_burns_a_sub_dollar_remainder() {
        let s = select_floor_aware(&[10000], 9950, FLOOR, CAP, true);
        assert!(s.ok);
        assert_eq!(s.stage, SelectStage::Burn);
        assert_eq!(s.extra_burn, 50);
        assert_eq!(s.change, 0);
        assert_eq!(s.selected, 10000);
        assert!(s.extra_burn < FLOOR);
        let worst = select_floor_aware(&[10099], 10000, FLOOR, CAP, true);
        assert!(worst.ok && worst.stage == SelectStage::Burn);
        assert_eq!(worst.extra_burn, 99);
        let prefer = select_floor_aware(&[10000, 10100], 9950, FLOOR, CAP, true);
        assert!(prefer.ok && prefer.stage != SelectStage::Burn);
        assert_eq!(prefer.extra_burn, 0);
        assert_eq!(prefer.change, 150);
        let exact = select_floor_aware(&[9950, 10000], 9950, FLOOR, CAP, true);
        assert_eq!(exact.stage, SelectStage::Exact);
        assert_eq!(exact.extra_burn, 0);
        let poor = select_floor_aware(&[100], 9950, FLOOR, CAP, true);
        assert!(!poor.ok && poor.insufficient);
    }

    // Rule: H2
    #[test]
    fn h2_nearest_workable_amounts() {
        let alt = nearest_workable(&[10000], 9950, FLOOR, CAP);
        assert_eq!((alt.below, alt.above), (Some(9900), Some(10000)));
        let two = nearest_workable(&[5000, 5000], 9950, FLOOR, CAP);
        assert_eq!((two.below, two.above), (Some(9900), Some(10000)));
        let three = nearest_workable(&[200, 300, 9500], 9950, FLOOR, CAP);
        assert_eq!((three.below, three.above), (Some(9900), Some(10000)));
        let top = nearest_workable(&[10000], 10000, FLOOR, CAP);
        assert!(top.above.is_none());
        let tiny = nearest_workable(&[100], 150, FLOOR, CAP);
        assert_eq!(tiny.below, Some(100));
        assert!(tiny.above.is_none());
    }

    // Rule: H2
    #[test]
    fn h2_alternatives_are_workable_and_the_band_is_not() {
        let coins = [10000];
        let target = 9950;
        let alt = nearest_workable(&coins, target, FLOOR, CAP);
        let (below, above) = (alt.below.unwrap(), alt.above.unwrap());
        assert!(select_floor_aware(&coins, below, FLOOR, CAP, false).ok);
        assert!(select_floor_aware(&coins, above, FLOOR, CAP, false).ok);
        for t in below + 1..above {
            assert!(
                !select_floor_aware(&coins, t, FLOOR, CAP, false).ok,
                "amount {t} should be unworkable"
            );
        }
    }

    // Rule: H1
    #[test]
    fn h1_large_wallet_terminates_and_is_deterministic() {
        let coins: Vec<i64> = (0..300).map(|i| 100 + ((i * 37) % 53) * 7).collect();
        let total: i64 = coins.iter().sum();
        for target in [100, 12345, total / 2, total - 50, total] {
            let s = select_floor_aware(&coins, target, FLOOR, CAP, false);
            let c = Case {
                name: "large_wallet",
                coins: coins.clone(),
                target,
                ok: s.ok,
                stage: s.stage,
                change: s.change,
            };
            check_invariants(&c, &s, false);
            check_deterministic(&coins, target, false);
        }
    }

    // Rule: H1
    #[test]
    fn h1_degenerate_arguments() {
        assert!(!select_floor_aware(&[], 100, FLOOR, CAP, false).ok);
        assert!(select_floor_aware(&[], 100, FLOOR, CAP, false).insufficient);
        let zero = select_floor_aware(&[500], 0, FLOOR, CAP, false);
        assert!(zero.ok && zero.inputs.is_empty() && zero.change == 0);
        assert!(!select_floor_aware(&[500], -1, FLOOR, CAP, false).ok);
        assert!(!select_floor_aware(&[500], 100, FLOOR, 0, false).ok);
        assert!(select_floor_aware(&[500], 100, FLOOR, 0, false).too_many_inputs);
    }
}
