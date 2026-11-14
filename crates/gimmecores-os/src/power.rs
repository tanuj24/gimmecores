//! Laptop protections' readings that need the operating system's API (Windows). On macOS and
//! Linux gimmecores-node reads `pmset`/`ioreg` and `/sys` itself, so these return `None` there.
//! `None` means unknown, and an unknown reading never pauses lending.

/// Whether this computer runs on battery: `Some(false)` on mains power or with no battery.
pub fn on_battery() -> Option<bool> {
    #[cfg(windows)]
    {
        crate::windows::on_battery()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Seconds since the owner last used the keyboard or mouse in this session (the daemon runs in
/// the owner's session).
pub fn idle_secs() -> Option<u64> {
    #[cfg(windows)]
    {
        crate::windows::idle_secs()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// The battery reading from Windows' power status: AC line 0 = battery, 1 = mains, 255 =
/// unknown; battery flag bit 128 = no system battery.
pub fn battery_from_status(ac_line: u8, battery_flag: u8) -> Option<bool> {
    if battery_flag != 255 && battery_flag & 128 != 0 {
        return Some(false);
    }
    match ac_line {
        0 => Some(true),
        1 => Some(false),
        _ => None,
    }
}

/// Milliseconds since the last input, from two 32-bit tick counts that wrap every 49.7 days.
pub fn idle_ms(now_ticks: u32, last_input_ticks: u32) -> u64 {
    u64::from(now_ticks.wrapping_sub(last_input_ticks))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn battery_states_read_as_windows_reports_them() {
        assert_eq!(battery_from_status(0, 1), Some(true)); // on battery, charge high
        assert_eq!(battery_from_status(1, 8), Some(false)); // charging
        assert_eq!(battery_from_status(0, 128), Some(false)); // no battery at all
        assert_eq!(battery_from_status(255, 255), None); // unknown
        assert_eq!(battery_from_status(1, 255), Some(false));
    }

    #[test]
    fn idle_time_survives_the_tick_counter_wrapping() {
        assert_eq!(idle_ms(5_000, 2_000), 3_000);
        assert_eq!(idle_ms(1_000, u32::MAX - 999), 2_000);
    }
}
