//! Bounded candidate context derived from the exact regex match.
//!
//! Matching owns candidate spans; validation owns value structure. This module
//! carries the small amount of syntax information between them without changing
//! the finding span, evidence digest or rule identity.

use crate::backend::MatchCandidate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContextError {
    InvalidSpan,
    MissingIdentifier,
}

/// Exact value span plus the syntax surrounding it in the full regex match.
///
/// `value` is always the same byte range used for finding construction. The
/// remaining fields are validation context and are never serialized.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CandidateContext<'a> {
    pub value: &'a [u8],
    pub identifier: Option<&'a [u8]>,
    pub delimiter: Option<u8>,
    pub value_quote: Option<u8>,
    pub define_call: bool,
}

impl<'a> CandidateContext<'a> {
    pub(crate) fn from_candidate(
        data: &'a [u8],
        candidate: &MatchCandidate,
        require_identifier: bool,
    ) -> Result<Self, ContextError> {
        if candidate.match_start >= candidate.match_end
            || candidate.match_start > candidate.start
            || candidate.start >= candidate.end
            || candidate.end > candidate.match_end
            || candidate.match_end > data.len()
        {
            return Err(ContextError::InvalidSpan);
        }

        let identifier = match candidate.identifier {
            Some(span) => {
                if span.start < candidate.match_start
                    || span.start >= span.end
                    || span.end > candidate.match_end
                {
                    return Err(ContextError::InvalidSpan);
                }
                Some(&data[span.start..span.end])
            }
            None => None,
        };
        if require_identifier && identifier.is_none() {
            return Err(ContextError::MissingIdentifier);
        }

        let full_match = &data[candidate.match_start..candidate.match_end];
        let value = &data[candidate.start..candidate.end];
        let value_relative = candidate.start - candidate.match_start;
        let (delimiter, value_quote) = syntax_before(full_match, value_relative);
        let define_call = candidate.identifier.is_some_and(|span| {
            let identifier_relative = span.start - candidate.match_start;
            is_define_prefix(&full_match[..identifier_relative])
        });

        Ok(Self {
            value,
            identifier,
            delimiter,
            value_quote,
            define_call,
        })
    }
}

/// Inspect the source immediately before the captured value.
///
/// The regex may place whitespace, an opening quote and a multi-byte operator
/// between the assignment name and the value. Only the last meaningful delimiter
/// is returned; `=>` is normalized to `=`.
fn syntax_before(full_match: &[u8], value_relative: usize) -> (Option<u8>, Option<u8>) {
    let mut end = value_relative.min(full_match.len());
    while end > 0 && matches!(full_match[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    let value_quote = if end > 0 && matches!(full_match[end - 1], b'"' | b'\'' | b'`') {
        let quote = full_match[end - 1];
        end -= 1;
        Some(quote)
    } else {
        None
    };
    while end > 0 && matches!(full_match[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    let mut delimiter = end.checked_sub(1).map(|index| full_match[index]);
    if delimiter == Some(b'>') && end >= 2 && full_match[end - 2] == b'=' {
        delimiter = Some(b'=');
    }
    (delimiter, value_quote)
}

/// Return true only for the immediate `define(...)` call form supported by the
/// generic assignment rule. A similarly named variable is not accepted.
fn is_define_prefix(prefix: &[u8]) -> bool {
    let mut end = prefix.len();
    while end > 0 && matches!(prefix[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    if end > 0 && matches!(prefix[end - 1], b'"' | b'\'' | b'`') {
        end -= 1;
    }
    while end > 0 && matches!(prefix[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    if end == 0 || prefix[end - 1] != b'(' {
        return false;
    }
    end -= 1;
    while end > 0 && matches!(prefix[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    let start = prefix[..end]
        .iter()
        .rposition(|byte| !(byte.is_ascii_alphanumeric() || *byte == b'_'))
        .map_or(0, |index| index + 1);
    prefix[start..end].eq_ignore_ascii_case(b"define")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::CaptureSpan;

    fn candidate(start: usize, end: usize, match_start: usize, match_end: usize) -> MatchCandidate {
        MatchCandidate {
            rule_index: 0,
            start,
            end,
            match_start,
            match_end,
            identifier: None,
        }
    }

    fn context<'a>(data: &'a [u8], value: &str) -> CandidateContext<'a> {
        let start = data
            .windows(value.len())
            .position(|window| window == value.as_bytes())
            .unwrap();
        let end = start + value.len();
        CandidateContext::from_candidate(data, &candidate(start, end, 0, data.len()), false)
            .unwrap()
    }

    #[test]
    fn quoted_and_unquoted_delimiters_are_detected() {
        let data = b"api_key = \"value9x\"\n";
        let value = context(data, "value9x");
        assert_eq!(value.delimiter, Some(b'='));
        assert_eq!(value.value_quote, Some(b'"'));

        let data = b"api_key: value9x\n";
        let value = context(data, "value9x");
        assert_eq!(value.delimiter, Some(b':'));
        assert_eq!(value.value_quote, None);
    }

    #[test]
    fn arrow_and_define_delimiters_are_normalized() {
        let data = b"api_key => `value9x`\n";
        let value = context(data, "value9x");
        assert_eq!(value.delimiter, Some(b'='));
        assert_eq!(value.value_quote, Some(b'`'));

        let data = b"define('DB_PASSWORD', 'value9x');\n";
        let start = data
            .windows(b"value9x".len())
            .position(|window| window == b"value9x")
            .unwrap();
        let identifier_start = data
            .windows(b"DB_PASSWORD".len())
            .position(|window| window == b"DB_PASSWORD")
            .unwrap();
        let candidate = MatchCandidate {
            rule_index: 0,
            start,
            end: start + b"value9x".len(),
            match_start: 0,
            match_end: data.len() - 2,
            identifier: Some(CaptureSpan {
                start: identifier_start,
                end: identifier_start + b"DB_PASSWORD".len(),
            }),
        };
        let value =
            CandidateContext::from_candidate(data, &candidate, true).expect("define context");
        assert_eq!(value.delimiter, Some(b','));
        assert_eq!(value.value_quote, Some(b'\''));
        assert!(value.define_call);
    }

    #[test]
    fn comma_outside_define_is_still_context_not_an_assignment() {
        let data = b"conn.login('user', 'password1', function(err, res) {\n";
        let start = data
            .windows(b"function(err".len())
            .position(|window| window == b"function(err")
            .unwrap();
        let candidate = candidate(start, start + b"function(err".len(), 0, data.len() - 1);
        let value = CandidateContext::from_candidate(data, &candidate, false).unwrap();
        assert_eq!(value.delimiter, Some(b','));
        assert!(!value.define_call);
    }

    #[test]
    fn invalid_spans_are_integrity_errors() {
        let data = b"value9x\n";
        for candidate in [
            candidate(0, 0, 0, data.len()),
            candidate(1, 0, 0, data.len()),
            candidate(0, data.len() + 1, 0, data.len()),
            candidate(0, 2, 1, data.len()),
        ] {
            assert!(CandidateContext::from_candidate(data, &candidate, false).is_err());
        }
        let candidate = candidate(0, 2, 0, data.len());
        assert!(matches!(
            CandidateContext::from_candidate(data, &candidate, true),
            Err(ContextError::MissingIdentifier)
        ));
    }
}
