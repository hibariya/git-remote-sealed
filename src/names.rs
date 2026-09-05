//! Bundle file names: §4.1 grammar, canonical form, and the §3 carve-out
//! classification.
//!
//! ```abnf
//! name     = seq ["-full"] ".bundle.age" [chunk]
//! seq      = nzdigit *DIGIT
//! chunk    = "." chunknum
//! chunknum = "0" / (nzdigit *DIGIT)
//! ```

use std::fmt;

/// §4.1: seq value >= 1 and <= 2^63-1 (fixes the integer type for ports).
pub const MAX_SEQ: u64 = (1 << 63) - 1;
/// §4.1: chunknum at most 7 digits (< 10^7), shared with the manifest's
/// chunk-count bound (§7.2).
pub const MAX_CHUNK_DIGITS: usize = 7;

/// A canonical bundle name. Constructing one enforces the §4.1 value bounds,
/// so a `BundleName` that exists is always formattable to a canonical name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BundleName {
    // Field order is load-bearing for the derived `Ord`:
    // §4.1: apply order is ascending numeric value of `seq`; chunk parts
    // (`.0` upward, §6.5) order within one logical name.
    seq: u64,
    full: bool,
    chunk: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    /// §4.1: seq must be >= 1 and <= 2^63-1.
    SeqOutOfBounds(u64),
    /// §4.1: chunknum must be < 10^7.
    ChunkOutOfBounds(u64),
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameError::SeqOutOfBounds(v) => {
                write!(f, "sequence number {v} out of bounds (must be 1..=2^63-1)")
            }
            NameError::ChunkOutOfBounds(v) => {
                write!(f, "chunk number {v} out of bounds (must be < 10^7)")
            }
        }
    }
}

impl std::error::Error for NameError {}

impl BundleName {
    pub fn new(seq: u64, full: bool, chunk: Option<u64>) -> Result<Self, NameError> {
        if !(1..=MAX_SEQ).contains(&seq) {
            return Err(NameError::SeqOutOfBounds(seq));
        }
        if let Some(c) = chunk {
            if c >= 10_000_000 {
                return Err(NameError::ChunkOutOfBounds(c));
            }
        }
        Ok(BundleName { seq, full, chunk })
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn is_full(&self) -> bool {
        self.full
    }

    pub fn chunk(&self) -> Option<u64> {
        self.chunk
    }

    /// §4.1: the logical name is the name without any chunk suffix.
    pub fn logical(&self) -> BundleName {
        BundleName {
            chunk: None,
            ..*self
        }
    }

    /// The name of chunk part `i` of this logical name (§4.2).
    pub fn part(&self, i: u64) -> Result<BundleName, NameError> {
        BundleName::new(self.seq, self.full, Some(i))
    }
}

impl fmt::Display for BundleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.seq)?;
        if self.full {
            write!(f, "-full")?;
        }
        write!(f, ".bundle.age")?;
        if let Some(c) = self.chunk {
            write!(f, ".{c}")?;
        }
        Ok(())
    }
}

/// §3: how a tree entry name relates to the bundle grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameClass {
    /// Matches the grammar in canonical form: a real bundle file name.
    Canonical(BundleName),
    /// §3 carve-out: matches the bundle-name *shape* but violates canonical
    /// form (leading zeros, or an out-of-bound number). Readers MUST ignore
    /// it; writers MUST NOT preserve it.
    BundleShapedNonCanonical,
    /// Outside the grammar entirely: readers MUST ignore, writers SHOULD
    /// preserve (forward compatibility).
    NonGrammar,
}

/// Classify a tree entry name per §3/§4.1.
///
/// §3: the carve-out covers names matching the bundle shape **compared
/// case-insensitively** — a case near-miss like `1-FULL.bundle.age` can
/// only be a decoy or corruption (the namespace is spec-owned), so it is
/// ignored on read and stripped on rewrite, never preserved.
pub fn classify(name: &str) -> NameClass {
    // Shape first, canonical-form judgment second: §3 distinguishes
    // "matches the pattern but is not canonical" from "not grammar".
    let Some((seq_digits, full, chunk_digits)) = shape(name) else {
        // Exact shape failed; a case-insensitive shape match is the §3
        // carve-out (wrong letter case is a non-canonical spelling).
        let lowered = name.to_ascii_lowercase();
        return if lowered != name && shape(&lowered).is_some() {
            NameClass::BundleShapedNonCanonical
        } else {
            NameClass::NonGrammar
        };
    };

    // Bundle-shaped; canonical-form and value-bound checks (§4.1) decide
    // between Canonical and the §3 carve-out.
    let seq = match parse_canonical(seq_digits) {
        Some(v) if (1..=MAX_SEQ).contains(&v) => v,
        _ => return NameClass::BundleShapedNonCanonical,
    };
    let chunk = match chunk_digits {
        None => None,
        Some(d) => {
            if d.len() > MAX_CHUNK_DIGITS {
                return NameClass::BundleShapedNonCanonical;
            }
            match parse_canonical(d) {
                Some(v) => Some(v),
                None => return NameClass::BundleShapedNonCanonical,
            }
        }
    };

    match BundleName::new(seq, full, chunk) {
        Ok(n) => NameClass::Canonical(n),
        // Unreachable given the checks above, but never panic in library code.
        Err(_) => NameClass::BundleShapedNonCanonical,
    }
}

/// Exact (case-sensitive) shape match: digits ["-full"] ".bundle.age"
/// ["." digits]. Returns the digit substrings for canonicality judgment.
fn shape(name: &str) -> Option<(&str, bool, Option<&str>)> {
    let seq_end = name
        .as_bytes()
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    if seq_end == 0 {
        return None;
    }
    let seq_digits = &name[..seq_end];
    let mut rest = &name[seq_end..];

    let full = if let Some(r) = rest.strip_prefix("-full") {
        rest = r;
        true
    } else {
        false
    };

    rest = rest.strip_prefix(".bundle.age")?;

    let chunk_digits = if rest.is_empty() {
        None
    } else {
        let r = rest.strip_prefix('.')?;
        if r.is_empty() || !r.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(r)
    };
    Some((seq_digits, full, chunk_digits))
}

/// Parse an all-digit string as canonical decimal: no leading zeros
/// (§4.1: "0" itself is canonical), no u64 overflow. Returns None on a
/// non-canonical spelling or overflow.
pub(crate) fn parse_canonical(digits: &str) -> Option<u64> {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return None;
    }
    digits.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(name: &str) -> BundleName {
        match classify(name) {
            NameClass::Canonical(n) => n,
            other => panic!("{name}: expected Canonical, got {other:?}"),
        }
    }

    #[test]
    fn parses_plain_and_full_and_chunked() {
        let n = canonical("2.bundle.age");
        assert_eq!((n.seq(), n.is_full(), n.chunk()), (2, false, None));

        let n = canonical("7-full.bundle.age");
        assert_eq!((n.seq(), n.is_full(), n.chunk()), (7, true, None));

        let n = canonical("7-full.bundle.age.87");
        assert_eq!((n.seq(), n.is_full(), n.chunk()), (7, true, Some(87)));

        let n = canonical("10.bundle.age.0");
        assert_eq!((n.seq(), n.is_full(), n.chunk()), (10, false, Some(0)));
    }

    #[test]
    fn formats_round_trip() {
        for s in [
            "1-full.bundle.age",
            "2.bundle.age",
            "10.bundle.age.0",
            "9223372036854775807.bundle.age.9999999",
        ] {
            assert_eq!(canonical(s).to_string(), s);
        }
    }

    #[test]
    fn cross_decade_ordering_is_numeric_not_lexical() {
        // §4.1: apply order is ascending numeric value of seq.
        let two = canonical("2.bundle.age");
        let ten = canonical("10.bundle.age");
        assert!(two < ten);
        // The string order says otherwise — that is exactly the trap.
        assert!("10.bundle.age" < "2.bundle.age");
    }

    #[test]
    fn chunk_parts_order_numerically_within_a_logical_name() {
        let p2 = canonical("3.bundle.age.2");
        let p10 = canonical("3.bundle.age.10");
        assert!(p2 < p10);
    }

    #[test]
    fn leading_zeros_are_bundle_shaped_non_canonical() {
        // §4.1 canonical form; §3 carve-out.
        for s in [
            "01.bundle.age",
            "007-full.bundle.age",
            "1.bundle.age.00",
            "1.bundle.age.01",
        ] {
            assert_eq!(classify(s), NameClass::BundleShapedNonCanonical, "{s}");
        }
    }

    #[test]
    fn out_of_bound_values_are_bundle_shaped_non_canonical() {
        // §4.1: seq >= 1 and <= 2^63-1; chunknum < 10^7.
        for s in [
            "0.bundle.age",                    // seq >= 1
            "9223372036854775808.bundle.age",  // 2^63
            "99999999999999999999.bundle.age", // > u64
            "1.bundle.age.12345678",           // 8 digits
        ] {
            assert_eq!(classify(s), NameClass::BundleShapedNonCanonical, "{s}");
        }
    }

    #[test]
    fn bounds_are_inclusive_where_the_spec_says_so() {
        assert!(matches!(
            classify("9223372036854775807.bundle.age"), // 2^63-1
            NameClass::Canonical(_)
        ));
        assert!(matches!(
            classify("1.bundle.age.9999999"), // 7 digits
            NameClass::Canonical(_)
        ));
        assert!(matches!(
            classify("1.bundle.age.0"),
            NameClass::Canonical(_)
        ));
    }

    #[test]
    fn case_mismatch_is_bundle_shaped_non_canonical() {
        // §3: the carve-out compares the shape case-insensitively — a case
        // near-miss can only be a decoy (e.g. `999-FULL.bundle.age` aimed at
        // Appendix A's human), so writers strip it rather than preserve it.
        for s in ["1-FULL.bundle.age", "1.BUNDLE.AGE", "1.Bundle.Age.0"] {
            assert_eq!(classify(s), NameClass::BundleShapedNonCanonical, "{s}");
        }
        // But a case-insensitive NON-match is still non-grammar.
        assert_eq!(classify("x-FULL.bundle.age"), NameClass::NonGrammar);
    }

    #[test]
    fn non_grammar_names() {
        for s in [
            "sealed-manifest.age",
            "refs.age",
            "sealed-format",
            "",
            "full.bundle.age",
            "1-ful.bundle.age",
            "1-fullx.bundle.age",
            "1.bundle.age.",
            "1.bundle.age.0.0",
            "1.bundle.age.x",
            "1.bundle.agex",
            "x1.bundle.age",
            "1 .bundle.age",
        ] {
            assert_eq!(classify(s), NameClass::NonGrammar, "{s:?}");
        }
    }

    #[test]
    fn constructor_enforces_bounds() {
        assert_eq!(
            BundleName::new(0, false, None),
            Err(NameError::SeqOutOfBounds(0))
        );
        assert_eq!(
            BundleName::new(MAX_SEQ + 1, false, None),
            Err(NameError::SeqOutOfBounds(MAX_SEQ + 1))
        );
        assert_eq!(
            BundleName::new(1, false, Some(10_000_000)),
            Err(NameError::ChunkOutOfBounds(10_000_000))
        );
        assert!(BundleName::new(1, true, Some(9_999_999)).is_ok());
    }

    #[test]
    fn logical_strips_chunk() {
        let n = canonical("5-full.bundle.age.3");
        assert_eq!(n.logical().to_string(), "5-full.bundle.age");
    }
}
