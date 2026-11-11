//! Deterministic, read-only local working-tree discovery and scope gate.
//!
//! Blocking is a pre-scan adapter operation: a blocked unit is never opened by
//! the detector. CP2 adds declared glob selectors and policy provenance while
//! preserving the strict canonical locator contract.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::error::CoreError;
use crate::path::{canonical_locator, unit_id};
use crate::policy::{BlockRule, PolicyOrigin, PolicySpec, ScopeGlob};

pub const DEFAULT_MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_TIMEOUT_MS: u64 = 300_000;
pub const DEFAULT_MAX_FINDINGS: usize = 10_000;
pub const DEFAULT_STREAM_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct ScanLimits {
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub timeout: Duration,
    pub max_findings: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            max_findings: DEFAULT_MAX_FINDINGS,
        }
    }
}

impl ScanLimits {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.max_file_bytes == 0
            || self.max_total_bytes == 0
            || self.max_total_bytes < self.max_file_bytes
        {
            return Err(CoreError::Input(
                "limits require max_total_bytes >= max_file_bytes > 0".to_string(),
            ));
        }
        if self.timeout.is_zero() || self.max_findings == 0 {
            return Err(CoreError::Input(
                "timeout and max_findings must be positive".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreScanScope {
    Inspect,
    Blocked,
    Skipped(&'static str),
}

#[derive(Debug, Clone)]
pub struct DiscoveredUnit {
    pub unit_id: String,
    pub locator: String,
    pub path: PathBuf,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub required_scope: bool,
    pub scope: PreScanScope,
    pub block_matches: Vec<String>,
    pub block_request_id: Option<String>,
}

#[derive(Debug, Default)]
pub struct Discovery {
    pub units: Vec<DiscoveredUnit>,
    pub fatal_errors: Vec<String>,
    pub warnings: Vec<String>,
    pub unmatched_selectors: usize,
}

#[derive(Debug, Clone)]
pub struct LocalSource {
    root: PathBuf,
    blocks: Vec<BlockRule>,
    skips: Vec<ScopeGlob>,
    optional: Vec<ScopeGlob>,
}

impl LocalSource {
    /// Compatibility constructor using exact CLI-style selectors. The caller
    /// remains responsible for supplying matching policy provenance.
    pub fn new(
        root: PathBuf,
        excludes: &[String],
        skips: &[String],
        optional: &[String],
    ) -> Result<Self, CoreError> {
        let mut spec = PolicySpec::empty();
        for (index, selector) in excludes.iter().enumerate() {
            spec.add_block(
                &format!("CLI-EXCLUDE-{index}"),
                PolicyOrigin::Cli,
                selector,
                "CLI pre-scan block",
                "1",
                false,
            )?;
        }
        for selector in skips {
            spec.add_skip(selector)?;
        }
        for selector in optional {
            spec.add_optional(selector)?;
        }
        Self::new_with_policy(root, &spec)
    }

    pub fn new_with_policy(root: PathBuf, policy: &PolicySpec) -> Result<Self, CoreError> {
        if policy.errors.is_empty() {
            policy.validate()?;
        }
        let root = fs::canonicalize(root).map_err(CoreError::Io)?;
        if !root.is_dir() {
            return Err(CoreError::Input("scan root is not a directory".to_string()));
        }
        Ok(Self {
            root,
            blocks: policy.blocks.clone(),
            skips: policy.skips.clone(),
            optional: policy.optional.clone(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn discover(&self) -> Discovery {
        let mut discovery = Discovery::default();
        self.walk(Path::new(""), &[], false, false, &mut discovery);
        discovery
            .units
            .sort_by(|left, right| left.locator.cmp(&right.locator));

        let matched_blocks: BTreeSet<&str> = discovery
            .units
            .iter()
            .flat_map(|unit| unit.block_matches.iter().map(String::as_str))
            .collect();
        for request in &self.blocks {
            if !matched_blocks.contains(request.request_id.as_str()) {
                discovery.unmatched_selectors += 1;
            }
        }
        let discovered: BTreeSet<&str> = discovery
            .units
            .iter()
            .map(|unit| unit.locator.as_str())
            .collect();
        for selector in self.skips.iter().chain(self.optional.iter()) {
            if !discovered.iter().any(|locator| selector.matches(locator)) {
                discovery.unmatched_selectors += 1;
            }
        }
        if discovery.unmatched_selectors > 0 {
            discovery
                .warnings
                .push("UNMATCHED_SCOPE_SELECTOR".to_string());
        }
        discovery
    }

    fn walk(
        &self,
        prefix: &Path,
        inherited_blocks: &[String],
        inherited_skip: bool,
        inherited_optional: bool,
        discovery: &mut Discovery,
    ) {
        let directory = if prefix.as_os_str().is_empty() {
            self.root.clone()
        } else {
            self.root.join(prefix)
        };
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(_) => {
                discovery
                    .fatal_errors
                    .push("DIRECTORY_UNREADABLE".to_string());
                return;
            }
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    discovery
                        .fatal_errors
                        .push("DIRECTORY_ENTRY_UNREADABLE".to_string());
                    continue;
                }
            };
            let name = match entry.file_name().into_string() {
                Ok(name) => name,
                Err(_) => {
                    discovery.fatal_errors.push("NON_UTF8_PATH".to_string());
                    continue;
                }
            };
            names.push(name);
        }
        names.sort();
        for name in names {
            let relative = if prefix.as_os_str().is_empty() {
                name.clone()
            } else {
                format!("{}/{}", prefix.to_string_lossy().replace('\\', "/"), name)
            };
            let locator = match canonical_locator(&relative) {
                Ok(locator) => locator.to_string(),
                Err(_) => {
                    discovery
                        .fatal_errors
                        .push("NON_CANONICAL_PATH".to_string());
                    continue;
                }
            };
            let path = self.root.join(&relative);
            let mut block_matches = inherited_blocks.to_vec();
            for request in &self.blocks {
                if request.matcher.matches(&locator)
                    && !block_matches.iter().any(|id| id == &request.request_id)
                {
                    block_matches.push(request.request_id.clone());
                }
            }
            let skip =
                inherited_skip || self.skips.iter().any(|selector| selector.matches(&locator));
            let optional = inherited_optional
                || self
                    .optional
                    .iter()
                    .any(|selector| selector.matches(&locator));
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => {
                    let scope = if block_matches.is_empty() {
                        PreScanScope::Skipped("METADATA_UNAVAILABLE")
                    } else {
                        PreScanScope::Blocked
                    };
                    discovery.units.push(self.unit(
                        locator,
                        path,
                        0,
                        None,
                        scope,
                        optional,
                        block_matches,
                    ));
                    continue;
                }
            };
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                let scope = if block_matches.is_empty() {
                    PreScanScope::Skipped("SYMLINK_NOT_FOLLOWED")
                } else {
                    PreScanScope::Blocked
                };
                discovery.units.push(self.unit(
                    locator,
                    path,
                    0,
                    None,
                    scope,
                    optional,
                    block_matches,
                ));
            } else if file_type.is_dir() {
                self.walk(
                    Path::new(&relative),
                    &block_matches,
                    skip,
                    optional,
                    discovery,
                );
            } else if file_type.is_file() {
                let scope = if !block_matches.is_empty() {
                    PreScanScope::Blocked
                } else if skip {
                    PreScanScope::Skipped("OPERATOR_SKIPPED")
                } else {
                    PreScanScope::Inspect
                };
                discovery.units.push(self.unit(
                    locator,
                    path,
                    metadata.len(),
                    metadata.modified().ok(),
                    scope,
                    optional,
                    block_matches,
                ));
            } else {
                let scope = if block_matches.is_empty() {
                    PreScanScope::Skipped("UNSUPPORTED_FILE_TYPE")
                } else {
                    PreScanScope::Blocked
                };
                discovery.units.push(self.unit(
                    locator,
                    path,
                    0,
                    None,
                    scope,
                    optional,
                    block_matches,
                ));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn unit(
        &self,
        locator: String,
        path: PathBuf,
        size: u64,
        modified: Option<SystemTime>,
        scope: PreScanScope,
        optional: bool,
        block_matches: Vec<String>,
    ) -> DiscoveredUnit {
        let block_request_id = if scope == PreScanScope::Blocked {
            block_matches
                .iter()
                .filter_map(|id| self.blocks.iter().find(|request| &request.request_id == id))
                .max_by(|left, right| {
                    left.matcher
                        .specificity()
                        .cmp(&right.matcher.specificity())
                        .then_with(|| left.request_id.cmp(&right.request_id))
                })
                .map(|request| request.request_id.clone())
        } else {
            None
        };
        DiscoveredUnit {
            unit_id: unit_id(crate::path::SOURCE_ID, &locator).unwrap_or_default(),
            required_scope: !optional,
            locator,
            path,
            size,
            modified,
            scope,
            block_matches,
            block_request_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn discovers_deterministically_and_marks_scope_before_read() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("nested")).unwrap();
        File::create(temp.path().join("b.txt"))
            .unwrap()
            .write_all(b"b")
            .unwrap();
        File::create(temp.path().join("nested/a.txt"))
            .unwrap()
            .write_all(b"a")
            .unwrap();
        let source = LocalSource::new(
            temp.path().to_path_buf(),
            &["b.txt".to_string()],
            &["nested/a.txt".to_string()],
            &["nested/a.txt".to_string()],
        )
        .unwrap();
        let discovery = source.discover();
        assert!(discovery.fatal_errors.is_empty());
        let locators: Vec<&str> = discovery
            .units
            .iter()
            .map(|unit| unit.locator.as_str())
            .collect();
        assert_eq!(locators, vec!["b.txt", "nested/a.txt"]);
        assert_eq!(discovery.units[0].scope, PreScanScope::Blocked);
        assert_eq!(
            discovery.units[1].scope,
            PreScanScope::Skipped("OPERATOR_SKIPPED")
        );
        assert!(!discovery.units[1].required_scope);
    }

    #[test]
    fn glob_block_inherits_over_directory_without_opening_files() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("secrets/nested")).unwrap();
        File::create(temp.path().join("secrets/nested/a.txt"))
            .unwrap()
            .write_all(b"secret")
            .unwrap();
        let mut spec = PolicySpec::empty();
        spec.add_block(
            "REPO-BLOCK",
            PolicyOrigin::Repository,
            "secrets/**",
            "required block",
            "1",
            false,
        )
        .unwrap();
        let source = LocalSource::new_with_policy(temp.path().to_path_buf(), &spec).unwrap();
        let discovery = source.discover();
        assert_eq!(discovery.units.len(), 1);
        assert_eq!(discovery.units[0].scope, PreScanScope::Blocked);
        assert_eq!(discovery.units[0].block_matches.len(), 1);
        assert_eq!(discovery.units[0].size, 6);
    }

    #[cfg(unix)]
    #[test]
    fn does_not_follow_symlinks() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        File::create(outside.path().join("outside.txt"))
            .unwrap()
            .write_all(b"RNC_SYNTH_KEY_AWS_OUTSIDE")
            .unwrap();
        symlink(
            outside.path().join("outside.txt"),
            temp.path().join("link.txt"),
        )
        .unwrap();
        let source = LocalSource::new(temp.path().to_path_buf(), &[], &[], &[]).unwrap();
        let discovery = source.discover();
        assert_eq!(discovery.units.len(), 1);
        assert_eq!(
            discovery.units[0].scope,
            PreScanScope::Skipped("SYMLINK_NOT_FOLLOWED")
        );
    }
}
