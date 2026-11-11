//! Deterministic, read-only local working-tree discovery and scope gate.
//!
//! CP1 implements only the minimum pre-scan scope gate needed for safe source
//! acquisition. The full policy and exemption engine belongs to CP2.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::error::CoreError;
use crate::path::canonical_locator;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreScanScope {
    Inspect,
    Blocked,
    Skipped(&'static str),
}

#[derive(Debug, Clone)]
pub struct DiscoveredUnit {
    pub locator: String,
    pub path: PathBuf,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub required_scope: bool,
    pub scope: PreScanScope,
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
    excludes: BTreeSet<String>,
    skips: BTreeSet<String>,
    optional: BTreeSet<String>,
}

fn canonical_selector(selector: &str) -> Result<String, CoreError> {
    Ok(canonical_locator(selector)?.to_string())
}

impl LocalSource {
    pub fn new(
        root: PathBuf,
        excludes: &[String],
        skips: &[String],
        optional: &[String],
    ) -> Result<Self, CoreError> {
        let root = fs::canonicalize(root).map_err(CoreError::Io)?;
        if !root.is_dir() {
            return Err(CoreError::Input("scan root is not a directory".to_string()));
        }
        let excludes: BTreeSet<String> = excludes
            .iter()
            .map(|value| canonical_selector(value))
            .collect::<Result<_, _>>()?;
        let skips: BTreeSet<String> = skips
            .iter()
            .map(|value| canonical_selector(value))
            .collect::<Result<_, _>>()?;
        let optional: BTreeSet<String> = optional
            .iter()
            .map(|value| canonical_selector(value))
            .collect::<Result<_, _>>()?;
        if let Some(conflict) = excludes.intersection(&skips).next() {
            return Err(CoreError::Input(format!(
                "locator is both excluded and skipped: {conflict}"
            )));
        }
        Ok(Self {
            root,
            excludes,
            skips,
            optional,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn discover(&self) -> Discovery {
        let mut discovery = Discovery::default();
        self.walk(Path::new(""), &mut discovery);
        discovery
            .units
            .sort_by(|left, right| left.locator.cmp(&right.locator));
        let discovered: BTreeSet<&str> = discovery
            .units
            .iter()
            .map(|unit| unit.locator.as_str())
            .collect();
        for selector in self
            .excludes
            .iter()
            .chain(self.skips.iter())
            .chain(self.optional.iter())
        {
            if !discovered.contains(selector.as_str()) {
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

    fn walk(&self, prefix: &Path, discovery: &mut Discovery) {
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
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => {
                    discovery.units.push(self.unit(
                        locator,
                        path,
                        0,
                        None,
                        PreScanScope::Skipped("METADATA_UNAVAILABLE"),
                    ));
                    continue;
                }
            };
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                discovery.units.push(self.unit(
                    locator,
                    path,
                    0,
                    None,
                    PreScanScope::Skipped("SYMLINK_NOT_FOLLOWED"),
                ));
            } else if file_type.is_dir() {
                if self.excludes.contains(&locator) {
                    // A directory-wide verified block needs a directory-aware
                    // unit type that CP0 v0.2 does not define. Fail rather than
                    // silently enumerate or silently skip it.
                    discovery
                        .fatal_errors
                        .push("DIRECTORY_EXCLUDE_UNSUPPORTED".to_string());
                    continue;
                }
                self.walk(Path::new(&relative), discovery);
            } else if file_type.is_file() {
                let scope = if self.excludes.contains(&locator) {
                    PreScanScope::Blocked
                } else if self.skips.contains(&locator) {
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
                ));
            } else {
                discovery.units.push(self.unit(
                    locator,
                    path,
                    0,
                    None,
                    PreScanScope::Skipped("UNSUPPORTED_FILE_TYPE"),
                ));
            }
        }
    }

    fn unit(
        &self,
        locator: String,
        path: PathBuf,
        size: u64,
        modified: Option<SystemTime>,
        scope: PreScanScope,
    ) -> DiscoveredUnit {
        DiscoveredUnit {
            required_scope: !self.optional.contains(&locator),
            locator,
            path,
            size,
            modified,
            scope,
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
