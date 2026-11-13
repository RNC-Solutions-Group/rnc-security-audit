//! Strict canonical source-locator and unit-identity contract.
//!
//! This is a trust-boundary validator, not a path cleaner. Adapters normalize
//! native acquisition paths; the contract rejects ambiguous spellings so two
//! filesystem objects cannot collapse into one identity.

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::error::CoreError;

pub const SOURCE_ID: &str = "local-working-tree";
pub const MAX_LOCATOR_SCALARS: usize = 4096;

const WINDOWS_DEVICE_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

fn is_format_control(character: char) -> bool {
    matches!(
        character,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

fn is_windows_reserved(segment: &str) -> bool {
    let stem = segment.split('.').next().unwrap_or("").to_ascii_uppercase();
    WINDOWS_DEVICE_NAMES.contains(&stem.as_str())
}

/// Validate and return the one accepted canonical locator.
pub fn canonical_locator(locator: &str) -> Result<&str, CoreError> {
    if locator.is_empty() {
        return Err(CoreError::Locator("locator must be a non-empty string"));
    }
    if locator.chars().count() > MAX_LOCATOR_SCALARS {
        return Err(CoreError::Locator(
            "locator exceeds the supported path length",
        ));
    }
    if locator
        .chars()
        .any(|character| character.is_control() || character == '\0')
    {
        return Err(CoreError::Locator(
            "locator contains a NUL or control character",
        ));
    }
    if locator.chars().any(is_format_control) {
        return Err(CoreError::Locator(
            "locator contains a formatting or separator control character",
        ));
    }
    let normalized: String = locator.nfc().collect();
    if normalized != locator {
        return Err(CoreError::Locator("locator must be NFC-normalized"));
    }
    if locator.contains('\\') {
        return Err(CoreError::Locator("locator must use forward slashes only"));
    }
    if locator.starts_with('/') || locator.starts_with('~') {
        return Err(CoreError::Locator(
            "locator must be relative to the source root",
        ));
    }
    let bytes = locator.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(CoreError::Locator(
            "locator must not contain a drive prefix",
        ));
    }
    if locator.starts_with("./") {
        return Err(CoreError::Locator("locator must not start with ./"));
    }
    if locator.ends_with('/') {
        return Err(CoreError::Locator("locator must not end with a separator"));
    }
    for segment in locator.split('/') {
        if segment.is_empty() {
            return Err(CoreError::Locator("locator contains an empty segment"));
        }
        if segment == "." || segment == ".." {
            return Err(CoreError::Locator(
                "locator contains a dot or traversal segment",
            ));
        }
        if segment.trim() != segment || segment.ends_with('.') {
            return Err(CoreError::Locator(
                "locator has a trailing space or dot segment",
            ));
        }
        if segment
            .chars()
            .any(|character| matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        {
            return Err(CoreError::Locator(
                "locator contains a platform-ambiguous character",
            ));
        }
        if is_windows_reserved(segment) {
            return Err(CoreError::Locator("locator contains a Windows device name"));
        }
    }
    Ok(locator)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

pub fn unit_id(source_id: &str, locator: &str) -> Result<String, CoreError> {
    if source_id.is_empty() || source_id.contains('\0') {
        return Err(CoreError::Locator(
            "source_id must be non-empty without NUL",
        ));
    }
    canonical_locator(locator)?;
    let mut hasher = Sha256::new();
    hasher.update(source_id.as_bytes());
    hasher.update([0]);
    hasher.update(locator.as_bytes());
    Ok(format!("u-{}", hex::encode(hasher.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_paths() {
        for value in [
            "file.txt",
            "nested/deep/file.txt",
            "café/résumé.txt",
            "Case.TXT",
        ] {
            assert_eq!(canonical_locator(value).unwrap(), value);
        }
    }

    #[test]
    fn rejects_ambiguous_or_unsafe_paths() {
        let rejected = [
            "",
            "./file.txt",
            "a//b",
            "a/./b",
            "a/../b",
            "a/",
            "/a",
            "\\a",
            "a\\b",
            "C:/a",
            "C:a",
            "//server/share",
            "~/a",
            "a:b",
            "a*b",
            "a?b",
            "a<b",
            "a>b",
            "a|b",
            "a\"b",
            "CON",
            "con.txt",
            "LPT1.log",
            "foo.",
            "foo ",
            "a/\0b",
            "cafe\u{301}.txt",
            "a/\u{202e}b.txt",
        ];
        for value in rejected {
            assert!(canonical_locator(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn case_is_preserved_and_identity_is_stable() {
        assert_ne!(
            unit_id(SOURCE_ID, "A.txt").unwrap(),
            unit_id(SOURCE_ID, "a.txt").unwrap()
        );
        assert_eq!(
            unit_id(SOURCE_ID, "nested/file.txt").unwrap(),
            unit_id(SOURCE_ID, "nested/file.txt").unwrap()
        );
    }

    #[test]
    fn unit_id_matches_cross_language_formula() {
        // Generated by tools/cp0/contracts.py for source local-working-tree.
        assert_eq!(
            unit_id(SOURCE_ID, "clean.txt").unwrap(),
            "u-82e4bec5c86d7542fa7ee3347c4feb2a053889b80d91d5aa0ac0f5df7f16571e"
        );
    }
}
