//! Deterministic candidate validators. They never perform network checks.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Validator {
    MarkerFormat,
    MarkerSuffix,
    AsciiOnly,
}

impl Validator {
    pub fn name(self) -> &'static str {
        match self {
            Self::MarkerFormat => "MARKER_FORMAT",
            Self::MarkerSuffix => "MARKER_SUFFIX",
            Self::AsciiOnly => "ASCII_ONLY",
        }
    }

    pub fn apply(self, candidate: &[u8]) -> Result<(), ValidationError> {
        match self {
            Self::MarkerFormat => validate_marker_format(candidate),
            Self::MarkerSuffix => validate_marker_suffix(candidate),
            Self::AsciiOnly => {
                if candidate.is_ascii() {
                    Ok(())
                } else {
                    Err(ValidationError(self))
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationError(pub Validator);

const MARKER_PREFIX: &[u8] = b"RNC_SYNTH_KEY_";

fn validate_marker_format(candidate: &[u8]) -> Result<(), ValidationError> {
    if !(16..=128).contains(&candidate.len()) || !candidate.starts_with(MARKER_PREFIX) {
        return Err(ValidationError(Validator::MarkerFormat));
    }
    if !candidate
        .iter()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(ValidationError(Validator::MarkerFormat));
    }
    Ok(())
}

fn validate_marker_suffix(candidate: &[u8]) -> Result<(), ValidationError> {
    let suffix = candidate
        .strip_prefix(MARKER_PREFIX)
        .ok_or(ValidationError(Validator::MarkerSuffix))?;
    let final_segment = suffix
        .rsplit(|byte| *byte == b'_')
        .next()
        .unwrap_or_default();
    if suffix.len() < 4 || suffix.ends_with(b"_") || final_segment.len() < 4 {
        return Err(ValidationError(Validator::MarkerSuffix));
    }
    if suffix.windows(5).any(|window| window == b"DECOY")
        || suffix.windows(4).any(|window| window == b"FAKE")
    {
        return Err(ValidationError(Validator::MarkerSuffix));
    }
    Ok(())
}

pub fn validate_candidate(
    candidate: &[u8],
    validators: &[Validator],
) -> Result<Vec<String>, ValidationError> {
    for validator in validators {
        validator.apply(candidate)?;
    }
    Ok(validators
        .iter()
        .map(|validator| validator.name().to_string())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_harmless_marker() {
        let validators = [Validator::MarkerFormat, Validator::MarkerSuffix];
        assert_eq!(
            validate_candidate(b"RNC_SYNTH_KEY_GENERIC_ALPHA", &validators).unwrap(),
            vec!["MARKER_FORMAT", "MARKER_SUFFIX"]
        );
    }

    #[test]
    fn rejects_decoys_and_malformed_values() {
        for value in [
            b"NOT_A_MARKER".as_slice(),
            b"RNC_SYNTH_KEY_".as_slice(),
            b"RNC_SYNTH_KEY_lower".as_slice(),
            b"RNC_SYNTH_KEY_DECOY_ALPHA".as_slice(),
            b"RNC_SYNTH_KEY_TRAILING_".as_slice(),
            b"RNC_SYNTH_KEY_AWS_12".as_slice(),
        ] {
            assert!(
                validate_candidate(value, &[Validator::MarkerFormat, Validator::MarkerSuffix])
                    .is_err()
            );
        }
    }
}
