//! Day-number math: u32 days since 1970-01-01 UTC (design 2.2). Every
//! comparison in the licence system is "UTC day number vs UTC day number",
//! which removes all timezone ambiguity. The current day is NEVER read
//! here — this crate only converts, and callers inject `today_utc`.
//!
//! The algorithms are Howard Hinnant's `days_from_civil` / `civil_from_days`
//! (public domain), chosen because they are exact across the whole u32
//! range, need no lookup tables, and are short enough to audit at a glance.

/// Days in `month` of `year`, proleptic Gregorian; 0 for a bad month.
fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Civil date -> day number. Returns `None` for a date that does not exist
/// (month 13, February 29 in a non-leap year, day 0), for anything before
/// 1970-01-01, and for anything beyond the u32 range — a bad date must be
/// refused, never normalised into a different day.
pub fn day_number_from_civil(year: i32, month: u32, day: u32) -> Option<u32> {
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    let y = if month <= 2 {
        i64::from(year) - 1
    } else {
        i64::from(year)
    };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = i64::from(if month > 2 { month - 3 } else { month + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146097 + doe - 719468;
    u32::try_from(days).ok()
}

/// Day number -> (year, month, day), the inverse of
/// `day_number_from_civil`. Needed by tests now and by the expired-row date
/// ("Premium ended March 12.") in P2.
pub fn civil_from_day_number(day_number: u32) -> (i32, u32, u32) {
    let z = i64::from(day_number) + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };
    (year as i32, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_is_day_zero() {
        assert_eq!(day_number_from_civil(1970, 1, 1), Some(0));
        assert_eq!(civil_from_day_number(0), (1970, 1, 1));
    }

    #[test]
    fn the_designs_worked_example_is_exact() {
        // Design 2.2: "2026-03-12 UTC is day 20524."
        assert_eq!(day_number_from_civil(2026, 3, 12), Some(20524));
        assert_eq!(civil_from_day_number(20524), (2026, 3, 12));
    }

    #[test]
    fn civil_and_day_number_round_trip_across_two_centuries() {
        for n in 0..=73_000u32 {
            let (y, m, d) = civil_from_day_number(n);
            assert_eq!(day_number_from_civil(y, m, d), Some(n), "day {n}");
        }
    }

    #[test]
    fn leap_days_follow_the_gregorian_rules() {
        assert!(day_number_from_civil(2000, 2, 29).is_some()); // ÷400: leap
        assert!(day_number_from_civil(2024, 2, 29).is_some());
        assert_eq!(day_number_from_civil(2100, 2, 29), None); // ÷100 only: not leap
        assert_eq!(day_number_from_civil(2023, 2, 29), None);
    }

    #[test]
    fn dates_that_do_not_exist_are_none_not_normalised() {
        assert_eq!(day_number_from_civil(2026, 0, 10), None);
        assert_eq!(day_number_from_civil(2026, 13, 10), None);
        assert_eq!(day_number_from_civil(2026, 4, 31), None);
        assert_eq!(day_number_from_civil(2026, 1, 0), None);
        assert_eq!(day_number_from_civil(1969, 12, 31), None); // pre-epoch
    }

    #[test]
    fn the_largest_day_number_round_trips() {
        let (y, m, d) = civil_from_day_number(u32::MAX);
        assert_eq!(day_number_from_civil(y, m, d), Some(u32::MAX));
    }
}
