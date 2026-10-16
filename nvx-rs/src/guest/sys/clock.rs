//! The monotonic clock.

use nix::time::{ClockId, clock_gettime};

use super::Errno;

/// Nanoseconds in a second, which scale the clock's whole seconds.
const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;

/// Nanoseconds in a millisecond, which `monotonic_ms` divides away.
const NANOSECONDS_PER_MILLISECOND: u64 = 1_000_000;

/// Returns the monotonic clock in nanoseconds, wrapping as the C programs' `u64` arithmetic did.
///
/// The C library reads this clock through the kernel's vDSO, without a system call. The C
/// `nvx-device-io` made the system call itself, so each read here costs less than there, and the
/// benchmark loops that read the clock can complete slightly more operations. The clock never
/// moves backwards, and its precision is that of the guest kernel's clocksource.
pub(crate) fn monotonic_ns() -> Result<u64, Errno> {
    let time = clock_gettime(ClockId::CLOCK_MONOTONIC)?;
    Ok((time.tv_sec() as u64)
        .wrapping_mul(NANOSECONDS_PER_SECOND)
        .wrapping_add(time.tv_nsec() as u64))
}

/// Returns the monotonic clock in whole milliseconds.
///
/// It equals the C programs' `tv_sec * 1000 + tv_nsec / 1000000` until the nanosecond count
/// wraps, 584 years after the clock's start.
pub(crate) fn monotonic_ms() -> Result<u64, Errno> {
    monotonic_ns().map(|nanoseconds| nanoseconds / NANOSECONDS_PER_MILLISECOND)
}

#[cfg(test)]
mod tests {
    //! Checks of the clock against the standard library's.

    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn advances_with_the_standard_monotonic_clock() {
        let started = monotonic_ns().unwrap();
        let instant = Instant::now();
        std::thread::sleep(Duration::from_millis(2));
        let elapsed = instant.elapsed();
        let ended = monotonic_ns().unwrap();
        assert!(started > 0);
        assert!(
            ended - started >= elapsed.as_nanos() as u64,
            "{started} {ended} {elapsed:?}"
        );
    }

    #[test]
    fn milliseconds_truncate_the_nanoseconds() {
        let before = monotonic_ns().unwrap() / NANOSECONDS_PER_MILLISECOND;
        let milliseconds = monotonic_ms().unwrap();
        let after = monotonic_ns().unwrap() / NANOSECONDS_PER_MILLISECOND;
        assert!(
            (before..=after).contains(&milliseconds),
            "{before} {milliseconds} {after}"
        );
    }
}
