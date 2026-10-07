//! Tab Groups: named, colored sets of tabs in the strip.
//!
//! LIVE ONLY. Like the tabs themselves, groups last until PATANYX closes;
//! nothing here is written anywhere. The one way to keep a group is to save
//! it to a shelf (ipc.rs `shelf_create` with `group`), which stores its name
//! and color with the shelf in the encrypted Library. They are never kept in
//! prefs.json, which is plaintext.
//!
//! THE ORDER RULE. A group's tabs sit next to each other in the strip. Every
//! operation that changes membership or order ends in `normalize`, which
//! pulls each group's members together at the place its first member
//! occupies and leaves every other tab's relative order alone. The chrome
//! may propose any order (a drag); Rust's normalized order is what the strip
//! keeps.
//!
//! This module is pure: it knows tab ids and an order, never a webview, so
//! every rule is unit-tested here.

use std::collections::BTreeMap;

use serde_json::{json, Value};

/// Most groups at once. MAX_TABS is 32, so this is generous.
pub const MAX_GROUPS: usize = 16;
/// Longest group name, in characters. Names are shown on a tab chip.
pub const MAX_NAME_CHARS: usize = 40;

/// The fixed palette. Stored and sent as these lowercase words; the chrome
/// maps each to a class in chrome.css, so a color is never a page- or
/// user-supplied CSS value.
pub const COLORS: [&str; 8] = [
    "grey", "blue", "red", "yellow", "green", "pink", "purple", "cyan",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TabGroup {
    pub id: u64,
    pub name: String,
    pub color: &'static str,
    pub collapsed: bool,
}

#[derive(Debug, Default)]
pub struct TabGroups {
    next_id: u64,
    groups: Vec<TabGroup>,
    /// tab id -> group id.
    member: BTreeMap<u64, u64>,
}

/// A color word from the palette, or None. Used to validate IPC input.
pub fn color(word: &str) -> Option<&'static str> {
    COLORS.iter().copied().find(|c| *c == word)
}

/// A user-typed name, trimmed, whitespace-collapsed and capped. An empty
/// result is allowed: an unnamed group shows only its color.
pub fn clean_name(raw: &str) -> String {
    let collapsed: String = raw
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    collapsed.chars().take(MAX_NAME_CHARS).collect()
}

impl TabGroups {
    pub fn group_of(&self, tab: u64) -> Option<u64> {
        self.member.get(&tab).copied()
    }

    pub fn get(&self, id: u64) -> Option<&TabGroup> {
        self.groups.iter().find(|g| g.id == id)
    }

    fn get_mut(&mut self, id: u64) -> Option<&mut TabGroup> {
        self.groups.iter_mut().find(|g| g.id == id)
    }

    /// Members of a group, in the given strip order.
    pub fn members(&self, group: u64, order: &[u64]) -> Vec<u64> {
        order
            .iter()
            .copied()
            .filter(|t| self.member.get(t) == Some(&group))
            .collect()
    }

    /// The colors already in use, so a new group can take the next free one.
    fn next_color(&self) -> &'static str {
        COLORS
            .iter()
            .copied()
            .find(|c| !self.groups.iter().any(|g| g.color == *c))
            .unwrap_or(COLORS[self.groups.len() % COLORS.len()])
    }

    /// Make a group of `tabs` (which may already belong to other groups;
    /// they move). Returns the new group's id.
    pub fn create(
        &mut self,
        tabs: &[u64],
        name: &str,
        color: Option<&'static str>,
        order: &mut Vec<u64>,
    ) -> Result<u64, &'static str> {
        let live: Vec<u64> = tabs.iter().copied().filter(|t| order.contains(t)).collect();
        if live.is_empty() {
            return Err("not_found");
        }
        if self.groups.len() >= MAX_GROUPS {
            return Err("too_many_groups");
        }
        self.next_id += 1;
        let id = self.next_id;
        let color = color.unwrap_or_else(|| self.next_color());
        self.groups.push(TabGroup {
            id,
            name: clean_name(name),
            color,
            collapsed: false,
        });
        // Gather the chosen tabs at the place the first of them occupies,
        // BEFORE recording membership: normalize keeps a group together but
        // would otherwise also reorder the chosen tabs among themselves.
        let first = order.iter().position(|t| live.contains(t)).unwrap_or(0);
        let chosen: Vec<u64> = order.iter().copied().filter(|t| live.contains(t)).collect();
        order.retain(|t| !live.contains(t));
        let at = first.min(order.len());
        for (i, t) in chosen.into_iter().enumerate() {
            order.insert(at + i, t);
        }
        for t in &live {
            self.member.insert(*t, id);
        }
        self.drop_empty();
        self.normalize(order);
        Ok(id)
    }

    /// Put `tab` into `group`, at the end of the group's run.
    pub fn add(&mut self, group: u64, tab: u64, order: &mut Vec<u64>) -> Result<(), &'static str> {
        if self.get(group).is_none() || !order.contains(&tab) {
            return Err("not_found");
        }
        if self.member.get(&tab) == Some(&group) {
            return Ok(());
        }
        order.retain(|t| *t != tab);
        let at = order
            .iter()
            .rposition(|t| self.member.get(t) == Some(&group))
            .map_or(order.len(), |p| p + 1);
        order.insert(at, tab);
        self.member.insert(tab, group);
        self.drop_empty();
        self.normalize(order);
        Ok(())
    }

    /// Take `tab` out of its group; it lands just after the group's run.
    pub fn remove(&mut self, tab: u64, order: &mut Vec<u64>) -> Result<(), &'static str> {
        let group = self.member.remove(&tab).ok_or("not_found")?;
        let was = order.iter().position(|t| *t == tab).unwrap_or(order.len());
        order.retain(|t| *t != tab);
        let at = order
            .iter()
            .rposition(|t| self.member.get(t) == Some(&group))
            .map_or(was.min(order.len()), |p| p + 1);
        order.insert(at, tab);
        self.drop_empty();
        self.normalize(order);
        Ok(())
    }

    pub fn rename(&mut self, group: u64, name: &str) -> Result<(), &'static str> {
        let g = self.get_mut(group).ok_or("not_found")?;
        g.name = clean_name(name);
        Ok(())
    }

    pub fn set_color(&mut self, group: u64, color: &'static str) -> Result<(), &'static str> {
        self.get_mut(group).ok_or("not_found")?.color = color;
        Ok(())
    }

    pub fn set_collapsed(&mut self, group: u64, collapsed: bool) -> Result<(), &'static str> {
        self.get_mut(group).ok_or("not_found")?.collapsed = collapsed;
        Ok(())
    }

    /// Dissolve a group; its tabs stay open, ungrouped, where they are.
    pub fn ungroup(&mut self, group: u64) -> Result<(), &'static str> {
        if self.get(group).is_none() {
            return Err("not_found");
        }
        self.member.retain(|_, g| *g != group);
        self.groups.retain(|g| g.id != group);
        Ok(())
    }

    /// A tab closed.
    pub fn forget_tab(&mut self, tab: u64) {
        self.member.remove(&tab);
        self.drop_empty();
    }

    fn drop_empty(&mut self) {
        let member = &self.member;
        self.groups.retain(|g| member.values().any(|m| *m == g.id));
    }

    /// Pull each group's members together at the position of its first
    /// member; every other tab keeps its relative order.
    pub fn normalize(&self, order: &mut Vec<u64>) {
        let mut out = Vec::with_capacity(order.len());
        let mut placed: Vec<u64> = Vec::new();
        for &t in order.iter() {
            match self.member.get(&t) {
                None => out.push(t),
                Some(&g) => {
                    if placed.contains(&g) {
                        continue;
                    }
                    placed.push(g);
                    out.extend(order.iter().copied().filter(|x| self.member.get(x) == Some(&g)));
                }
            }
        }
        *order = out;
    }

    /// The groups as the chrome receives them, in strip order.
    pub fn to_json(&self, order: &[u64]) -> Value {
        let mut seen: Vec<u64> = Vec::new();
        for t in order {
            if let Some(&g) = self.member.get(t) {
                if !seen.contains(&g) {
                    seen.push(g);
                }
            }
        }
        Value::Array(
            seen.iter()
                .filter_map(|id| self.get(*id))
                .map(|g| {
                    json!({
                        "id": g.id,
                        "name": g.name,
                        "color": g.color,
                        "collapsed": g.collapsed,
                    })
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order(n: u64) -> Vec<u64> {
        (1..=n).collect()
    }

    #[test]
    fn create_gathers_the_chosen_tabs_at_the_first_one() {
        let mut g = TabGroups::default();
        let mut o = order(6);
        let id = g.create(&[2, 5], "Trip", None, &mut o).unwrap();
        assert_eq!(o, vec![1, 2, 5, 3, 4, 6]);
        assert_eq!(g.members(id, &o), vec![2, 5]);
        assert_eq!(g.get(id).unwrap().name, "Trip");
    }

    #[test]
    fn a_member_dragged_away_rejoins_its_run() {
        let mut g = TabGroups::default();
        let mut o = order(5);
        g.create(&[2, 3], "", None, &mut o).unwrap(); // 1 [2 3] 4 5
        // 3 dragged to the end: the run regathers at 2's place.
        let mut dragged = vec![1, 2, 4, 5, 3];
        g.normalize(&mut dragged);
        assert_eq!(dragged, vec![1, 2, 3, 4, 5]);
        // 2 dragged to the end alone: the run regathers at 3's place, in the
        // dragged order. Moving a WHOLE group is the chrome's job: dragging a
        // group's labeled chip sends every member together (chrome.js
        // groupAwareOrder), and this rule then changes nothing.
        let mut dragged = vec![1, 3, 4, 5, 2];
        g.normalize(&mut dragged);
        assert_eq!(dragged, vec![1, 3, 2, 4, 5]);
        let mut block_move = vec![1, 4, 5, 2, 3];
        g.normalize(&mut block_move);
        assert_eq!(block_move, vec![1, 4, 5, 2, 3]);
    }

    #[test]
    fn add_puts_the_tab_at_the_end_of_the_run() {
        let mut g = TabGroups::default();
        let mut o = order(5);
        let id = g.create(&[1, 2], "", None, &mut o).unwrap();
        g.add(id, 5, &mut o).unwrap();
        assert_eq!(o, vec![1, 2, 5, 3, 4]);
        assert_eq!(g.members(id, &o), vec![1, 2, 5]);
    }

    #[test]
    fn remove_leaves_the_tab_just_after_the_run() {
        let mut g = TabGroups::default();
        let mut o = order(5);
        let id = g.create(&[1, 2, 3], "", None, &mut o).unwrap();
        g.remove(1, &mut o).unwrap();
        assert_eq!(o, vec![2, 3, 1, 4, 5]);
        assert_eq!(g.members(id, &o), vec![2, 3]);
        assert_eq!(g.group_of(1), None);
    }

    #[test]
    fn an_emptied_group_disappears() {
        let mut g = TabGroups::default();
        let mut o = order(3);
        let id = g.create(&[2], "", None, &mut o).unwrap();
        g.forget_tab(2);
        assert!(g.get(id).is_none());
        let id = g.create(&[3], "", None, &mut o).unwrap();
        g.remove(3, &mut o).unwrap();
        assert!(g.get(id).is_none());
    }

    #[test]
    fn moving_a_tab_between_groups_keeps_both_runs_whole() {
        let mut g = TabGroups::default();
        let mut o = order(6);
        let a = g.create(&[1, 2], "", None, &mut o).unwrap();
        let b = g.create(&[4, 5], "", None, &mut o).unwrap();
        g.add(b, 1, &mut o).unwrap();
        assert_eq!(g.members(a, &o), vec![2]);
        assert_eq!(g.members(b, &o), vec![4, 5, 1]);
        let mut check = o.clone();
        g.normalize(&mut check);
        assert_eq!(check, o, "order after add must already be normal");
    }

    #[test]
    fn ungroup_keeps_tabs_in_place() {
        let mut g = TabGroups::default();
        let mut o = order(4);
        let id = g.create(&[2, 3], "", None, &mut o).unwrap();
        g.ungroup(id).unwrap();
        assert_eq!(o, vec![1, 2, 3, 4]);
        assert_eq!(g.group_of(2), None);
        assert!(g.get(id).is_none());
    }

    #[test]
    fn names_are_cleaned_and_capped() {
        assert_eq!(clean_name("  Trip \n  planning\t"), "Trip planning");
        assert_eq!(clean_name(&"x".repeat(100)).chars().count(), MAX_NAME_CHARS);
        assert_eq!(clean_name("a\u{0007}b"), "ab");
    }

    #[test]
    fn colors_come_only_from_the_palette() {
        assert_eq!(color("blue"), Some("blue"));
        assert_eq!(color("red; background: url(x)"), None);
        assert_eq!(color("BLUE"), None);
        let mut g = TabGroups::default();
        let mut o = order(3);
        let a = g.create(&[1], "", None, &mut o).unwrap();
        let b = g.create(&[2], "", None, &mut o).unwrap();
        assert_ne!(g.get(a).unwrap().color, g.get(b).unwrap().color, "new groups take a free color");
    }

    #[test]
    fn group_count_is_capped() {
        let mut g = TabGroups::default();
        let mut o = order(32);
        for t in 1..=MAX_GROUPS as u64 {
            g.create(&[t], "", None, &mut o).unwrap();
        }
        assert_eq!(g.create(&[20], "", None, &mut o), Err("too_many_groups"));
    }

    #[test]
    fn unknown_tabs_and_groups_are_refused() {
        let mut g = TabGroups::default();
        let mut o = order(3);
        assert_eq!(g.create(&[99], "", None, &mut o), Err("not_found"));
        assert_eq!(g.add(7, 1, &mut o), Err("not_found"));
        assert_eq!(g.remove(1, &mut o), Err("not_found"));
        assert_eq!(g.rename(7, "x"), Err("not_found"));
    }

    #[test]
    fn json_lists_groups_in_strip_order() {
        let mut g = TabGroups::default();
        let mut o = order(4);
        let a = g.create(&[3], "Later", Some("red"), &mut o).unwrap();
        let b = g.create(&[1], "First", Some("blue"), &mut o).unwrap();
        let v = g.to_json(&o);
        assert_eq!(v[0]["id"], b);
        assert_eq!(v[1]["id"], a);
        assert_eq!(v[1]["color"], "red");
    }

    #[test]
    fn a_deferred_close_keeps_membership_until_the_tab_really_closes() {
        // Pinned against the source (review round 2, R-005): the close that
        // waits for the session wipe used to forget the tab's group at once,
        // then the real close could be refused, leaving a live tab with no
        // group, and that refusal was discarded.
        // Commented-out code does not count, line or block: a fix that is
        // commented out must fail this test (review round 4, R-007; round 5,
        // R-006).
        let raw = include_str!("state.rs");
        let mut uncommented = String::with_capacity(raw.len());
        let mut rest = raw;
        while let Some(open) = rest.find("/*") {
            uncommented.push_str(&rest[..open]);
            rest = rest[open..].find("*/").map_or("", |close| &rest[open + close + 2..]);
        }
        uncommented.push_str(rest);
        let state: String = uncommented
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let at = state
            .find("self.tabs[index].close_after_session_wipe = true;")
            .expect("close_tab defers a close behind the session wipe");
        let deferred = &state[at..at + state[at..].find("return Ok(());").expect("the deferred branch returns")];
        assert!(!deferred.contains("forget_tab"), "the deferred branch must not forget membership");
        let fin = state.find("pub fn finish_session_wipe(").expect("finish_session_wipe exists");
        let body = &state[fin..fin + state[fin..].find("\n    }\n").expect("end of fn")];
        assert!(!body.contains("let _ = self.close_tab("), "a refused deferred close must not be discarded");
        assert!(body.contains("close_after_session_wipe = false"), "a refused deferred close leaves an ordinary tab");
        // ...that loads the page it was opened with (review round 3, R-005).
        let rearm = body.find("initial_navigation_pending = true;").expect("the skipped first page is re-armed");
        assert!(body[rearm..].contains("finish_initial_navigation();"), "and then loaded");
    }

}
