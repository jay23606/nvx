//! Strict parsers of the numbers in the guest programs' command-line arguments and in the
//! kernel's text files.
//!
//! The C programs parsed command-line arguments with `strtoull(text, &end, 0)`, which also
//! accepts leading whitespace, a sign, and octal after a leading zero. No caller passes those
//! forms, so the programs reject them as usage errors rather than read them differently. The
//! managed agent's C program read its identities and descriptor in base 10 instead, so they are
//! plain decimal.
//!
//! The kernel's text files, such as its socket tables and sysctls, hold plain decimal and
//! hexadecimal numbers, which the C programs read with the C library's `strtoul` and `scanf`.
//! Those also accept the forms above, and saturate an overflowing value, but the kernel never
//! writes them, so the programs parse the kernel's numbers as strictly as their arguments.

use std::ffi::CStr;

/// Parses a whole, nonempty decimal number, or a hexadecimal one after a `0x` or `0X` prefix.
///
/// Returns `None` for an empty argument, any other character, a decimal number with a leading
/// zero, which C read as octal, or a value above `u64::MAX`.
pub(crate) fn parse_u64(text: &CStr) -> Option<u64> {
    let text = text.to_str().ok()?;
    let (digits, radix) = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(digits) => (digits, 16),
        None if text.len() > 1 && text.starts_with('0') => return None,
        None => (text, 10),
    };
    // `from_str_radix` alone would also accept a leading `+`.
    if digits.is_empty() || !digits.chars().all(|digit| digit.is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

/// Parses a whole, nonempty decimal number, whose leading zeros are decimal, as C's `strtoull`
/// and `strtol` read one in base 10.
///
/// Returns `None` for an empty argument, any other character, including the leading whitespace
/// and sign that C also skipped, or a value above `u64::MAX`.
pub(crate) fn parse_decimal(text: &[u8]) -> Option<u64> {
    // `from_str` alone would also accept a leading `+`.
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(text).ok()?.parse().ok()
}

/// Parses a whole, nonempty hexadecimal number without a prefix, in either case, as the kernel
/// prints one with `%X`.
///
/// Returns `None` for an empty text, any other character, including the leading whitespace, sign,
/// and `0x` prefix that C's `strtoul` and `scanf` also accepted, or a value above `u64::MAX`,
/// which they saturated.
pub(crate) fn parse_hexadecimal(text: &[u8]) -> Option<u64> {
    // `from_str_radix` alone would also accept a leading `+`.
    if text.is_empty() || !text.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(text).ok()?, 16).ok()
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    fn parse(text: &[u8]) -> Option<u64> {
        parse_u64(&CString::new(text).unwrap())
    }

    #[test]
    fn parses_decimal_and_hexadecimal_numbers() {
        let cases: &[(&[u8], u64)] = &[
            (b"0", 0),
            (b"7", 7),
            (b"4096", 4096),
            (b"18446744073709551615", u64::MAX),
            (b"0x0", 0),
            (b"0x10", 16),
            (b"0XfF", 255),
            (b"0x00ff", 255),
            (b"0xffffffffffffffff", u64::MAX),
        ];
        for &(text, expected) in cases {
            assert_eq!(parse(text), Some(expected), "{}", text.escape_ascii());
        }
    }

    #[test]
    fn rejects_every_other_form() {
        for text in [
            &b""[..],
            b"0x",
            b"0X",
            b"00",
            b"010",
            b"08",
            b"+1",
            b"-1",
            b" 1",
            b"1 ",
            b"1a",
            b"0x1g",
            b"0x+1",
            b"0x-1",
            b"1_000",
            b"0b1",
            b"18446744073709551616",
            b"0x10000000000000000",
            b"\xa01",
            "\u{661}".as_bytes(),
        ] {
            assert_eq!(parse(text), None, "{}", text.escape_ascii());
        }
    }

    #[test]
    fn parses_plain_decimal_numbers_with_leading_zeros() {
        let cases: &[(&[u8], u64)] = &[
            (b"0", 0),
            (b"7", 7),
            (b"007", 7),
            (b"2147483647", 2_147_483_647),
            (b"18446744073709551615", u64::MAX),
        ];
        for &(text, expected) in cases {
            assert_eq!(
                parse_decimal(text),
                Some(expected),
                "{}",
                text.escape_ascii()
            );
        }
        for text in [
            &b""[..],
            b"+7",
            b"-1",
            b" 42",
            b"42 ",
            b"1x",
            b"0x10",
            b"18446744073709551616",
            "\u{661}".as_bytes(),
        ] {
            assert_eq!(parse_decimal(text), None, "{}", text.escape_ascii());
        }
    }

    #[test]
    fn parses_plain_hexadecimal_numbers_in_either_case() {
        let cases: &[(&[u8], u64)] = &[
            (b"0", 0),
            (b"0A", 0x0a),
            (b"1f90", 0x1f90),
            (b"0100007F", 0x0100_007f),
            (b"FFFFFFFFFFFFFFFF", u64::MAX),
            (b"0000000000000000000001", 1),
        ];
        for &(text, expected) in cases {
            assert_eq!(
                parse_hexadecimal(text),
                Some(expected),
                "{}",
                text.escape_ascii()
            );
        }
        for text in [
            &b""[..],
            b"+A",
            b"-1",
            b"-0000001",
            b"0x10",
            b"0X10",
            b" A",
            b"A ",
            b"\x0bA",
            b"A\0",
            b"1F90:",
            b"g",
            b"10000000000000000",
            "\u{ff21}".as_bytes(),
        ] {
            assert_eq!(parse_hexadecimal(text), None, "{}", text.escape_ascii());
        }
    }
}
