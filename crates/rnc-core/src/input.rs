//! Deterministic, read-only local working-tree discovery and scope gate.
//!
//! Blocking is a pre-scan adapter operation: a blocked unit is never opened by
//! the detector. CP2 adds declared glob selectors and policy provenance while
//! preserving the strict canonical locator contract.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crate::error::CoreError;
use crate::path::{canonical_locator, unit_id};
use crate::policy::{BlockRule, PolicyOrigin, PolicySpec, ScopeGlob};

pub const DEFAULT_MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_TIMEOUT_MS: u64 = 300_000;
pub const DEFAULT_MAX_FINDINGS: usize = 10_000;
pub const DEFAULT_STREAM_CHUNK_BYTES: usize = 64 * 1024;
pub const DEFAULT_DISCOVERY_ENTRIES: usize = 1_000_000;
pub const DEFAULT_DISCOVERY_DEPTH: usize = 128;
pub const DEFAULT_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(300);
pub const DEFAULT_POLICY_WORK: u64 = 50_000_000;

#[derive(Debug, Clone, Copy)]
pub struct DiscoveryBudget {
    pub deadline: Instant,
    pub max_entries: usize,
    pub max_depth: usize,
    pub max_policy_work: u64,
}

impl Default for DiscoveryBudget {
    fn default() -> Self {
        Self {
            deadline: Instant::now() + DEFAULT_DISCOVERY_TIMEOUT,
            max_entries: DEFAULT_DISCOVERY_ENTRIES,
            max_depth: DEFAULT_DISCOVERY_DEPTH,
            max_policy_work: DEFAULT_POLICY_WORK,
        }
    }
}

fn consume_policy_budget(budget: &mut u64, cost: u64) -> bool {
    if *budget < cost {
        return false;
    }
    *budget -= cost;
    true
}

fn abort_policy_budget(discovery: &mut Discovery) {
    discovery.aborted = true;
    discovery
        .fatal_errors
        .push("POLICY_BUDGET_EXCEEDED".to_string());
}

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
pub struct GitBlobRef {
    pub commit: String,
    pub blob_oid: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct GitHistoryInfo {
    pub repository_path: PathBuf,
    pub repository_id: String,
    pub refs: Vec<String>,
    pub commits: usize,
    pub changed_paths: usize,
    pub deleted_paths: usize,
    pub units_seen: usize,
    pub scope: String,
}

#[derive(Debug, Clone)]
pub struct DiscoveredUnit {
    pub unit_id: String,
    pub source_id: String,
    pub source_kind: String,
    pub locator: String,
    pub path: PathBuf,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub required_scope: bool,
    pub scope: PreScanScope,
    pub block_matches: Vec<String>,
    pub block_request_id: Option<String>,
    pub git: Option<GitBlobRef>,
}

#[derive(Debug, Default)]
pub struct Discovery {
    pub root: PathBuf,
    pub units: Vec<DiscoveredUnit>,
    pub fatal_errors: Vec<String>,
    pub warnings: Vec<String>,
    pub unmatched_selectors: usize,
    pub aborted: bool,
    pub entries_seen: usize,
    pub matched_scope_selectors: BTreeSet<String>,
    pub source_adapter_id: String,
    pub source_adapter_version: String,
    pub git_history: Option<GitHistoryInfo>,
    pub git_source: Option<crate::git::GitHistorySource>,
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
        self.discover_with_budget(DiscoveryBudget::default())
    }

    pub fn discover_until(&self, deadline: Instant) -> Discovery {
        self.discover_with_budget(DiscoveryBudget {
            deadline,
            ..DiscoveryBudget::default()
        })
    }

    pub fn discover_with_budget(&self, budget: DiscoveryBudget) -> Discovery {
        let mut discovery = Discovery {
            root: self.root.clone(),
            source_adapter_id: "local-working-tree".to_string(),
            source_adapter_version: env!("CARGO_PKG_VERSION").to_string(),
            ..Discovery::default()
        };
        let mut policy_budget = budget.max_policy_work;
        self.walk(
            Path::new(""),
            &[],
            false,
            false,
            0,
            &mut discovery,
            budget,
            &mut policy_budget,
        );
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
        for selector in self.skips.iter().chain(self.optional.iter()) {
            if !discovery
                .matched_scope_selectors
                .contains(selector.as_str())
            {
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

    /// Apply declared pre-scan scope to already-enumerated virtual units.
    /// This is used by the Git adapter: selectors are evaluated against the
    /// commit/path locator before any blob content is requested.
    pub fn apply_policy_to_discovery(discovery: &mut Discovery, policy: &PolicySpec) {
        let mut matched_selectors = BTreeSet::new();
        let mut matched_blocks = BTreeSet::new();
        for unit in &mut discovery.units {
            let mut block_matches = Vec::new();
            for request in &policy.blocks {
                if request.matcher.matches(&unit.locator) {
                    block_matches.push(request.request_id.clone());
                    matched_blocks.insert(request.request_id.clone());
                }
            }
            let mut skip = false;
            for selector in &policy.skips {
                if selector.matches(&unit.locator) {
                    skip = true;
                    matched_selectors.insert(selector.as_str().to_string());
                }
            }
            let mut optional = !unit.required_scope;
            for selector in &policy.optional {
                if selector.matches(&unit.locator) {
                    optional = true;
                    matched_selectors.insert(selector.as_str().to_string());
                }
            }
            if !block_matches.is_empty() {
                unit.block_request_id = policy
                    .blocks
                    .iter()
                    .filter(|request| block_matches.contains(&request.request_id))
                    .max_by(|left, right| {
                        left.matcher
                            .specificity()
                            .cmp(&right.matcher.specificity())
                            .then_with(|| left.request_id.cmp(&right.request_id))
                    })
                    .map(|request| request.request_id.clone());
                unit.scope = PreScanScope::Blocked;
            } else if skip {
                unit.scope = PreScanScope::Skipped("OPERATOR_SKIPPED");
            }
            unit.required_scope = !optional;
            unit.block_matches = block_matches;
        }
        discovery.unmatched_selectors = policy
            .blocks
            .iter()
            .filter(|request| !matched_blocks.contains(&request.request_id))
            .count()
            + policy
                .skips
                .iter()
                .chain(policy.optional.iter())
                .filter(|selector| !matched_selectors.contains(selector.as_str()))
                .count();
        if discovery.unmatched_selectors > 0 {
            discovery
                .warnings
                .push("UNMATCHED_SCOPE_SELECTOR".to_string());
        }
    }

    fn directory_within_root(&self, directory: &Path) -> bool {
        match fs::canonicalize(directory) {
            Ok(canonical) => {
                #[cfg(windows)]
                {
                    let root = self
                        .root
                        .to_string_lossy()
                        .replace("\\\\?\\", "")
                        .replace('/', "\\")
                        .to_ascii_lowercase();
                    let canonical = canonical
                        .to_string_lossy()
                        .replace("\\\\?\\", "")
                        .replace('/', "\\")
                        .to_ascii_lowercase();
                    let base = root.clone();
                    let prefix = if root.ends_with('\\') {
                        root
                    } else {
                        format!("{root}\\")
                    };
                    canonical == base || canonical.starts_with(&prefix)
                }
                #[cfg(not(windows))]
                {
                    canonical.starts_with(&self.root)
                }
            }
            Err(_) => false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn walk(
        &self,
        prefix: &Path,
        inherited_blocks: &[String],
        inherited_skip: bool,
        inherited_optional: bool,
        depth: usize,
        discovery: &mut Discovery,
        budget: DiscoveryBudget,
        policy_budget: &mut u64,
    ) {
        if discovery.aborted {
            return;
        }
        if Instant::now() >= budget.deadline {
            discovery.aborted = true;
            discovery.fatal_errors.push("DISCOVERY_TIMEOUT".to_string());
            return;
        }
        if depth > budget.max_depth {
            discovery.aborted = true;
            discovery
                .fatal_errors
                .push("DISCOVERY_DEPTH_LIMIT".to_string());
            return;
        }
        let directory = if prefix.as_os_str().is_empty() {
            self.root.clone()
        } else {
            self.root.join(prefix)
        };
        if !self.directory_within_root(&directory) {
            discovery.aborted = true;
            discovery.fatal_errors.push("DIRECTORY_ESCAPE".to_string());
            return;
        }
        if fs::symlink_metadata(&directory)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            discovery.aborted = true;
            discovery
                .fatal_errors
                .push("DIRECTORY_SYMLINK_ESCAPE".to_string());
            return;
        }
        #[cfg(windows)]
        if fs::symlink_metadata(&directory).is_ok_and(|metadata| {
            use std::os::windows::fs::MetadataExt;
            metadata.file_attributes() & 0x0400 != 0
        }) {
            discovery.aborted = true;
            discovery
                .fatal_errors
                .push("DIRECTORY_REPARSE_ESCAPE".to_string());
            return;
        }
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
            discovery.entries_seen += 1;
            if discovery.entries_seen > budget.max_entries {
                discovery.aborted = true;
                discovery
                    .fatal_errors
                    .push("DISCOVERY_ENTRY_LIMIT".to_string());
                return;
            }
            names.push(name);
        }
        names.sort();
        for name in names {
            if discovery.aborted {
                return;
            }
            if Instant::now() >= budget.deadline {
                discovery.aborted = true;
                discovery.fatal_errors.push("DISCOVERY_TIMEOUT".to_string());
                return;
            }
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
            let path_segments = relative.split('/').count();
            let mut block_matches = inherited_blocks.to_vec();
            for request in &self.blocks {
                if !consume_policy_budget(policy_budget, request.matcher.cost(path_segments)) {
                    abort_policy_budget(discovery);
                    return;
                }
                if request.matcher.matches(&locator)
                    && !block_matches.iter().any(|id| id == &request.request_id)
                {
                    block_matches.push(request.request_id.clone());
                }
            }
            let mut skip = inherited_skip;
            for selector in &self.skips {
                if !consume_policy_budget(policy_budget, selector.cost(path_segments)) {
                    abort_policy_budget(discovery);
                    return;
                }
                if selector.matches(&locator) {
                    skip = true;
                    discovery
                        .matched_scope_selectors
                        .insert(selector.as_str().to_string());
                }
            }
            let mut optional = inherited_optional;
            for selector in &self.optional {
                if !consume_policy_budget(policy_budget, selector.cost(path_segments)) {
                    abort_policy_budget(discovery);
                    return;
                }
                if selector.matches(&locator) {
                    optional = true;
                    discovery
                        .matched_scope_selectors
                        .insert(selector.as_str().to_string());
                }
            }
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
                    depth + 1,
                    discovery,
                    budget,
                    policy_budget,
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
            source_id: crate::path::SOURCE_ID.to_string(),
            source_kind: "working_tree_file".to_string(),
            required_scope: !optional,
            locator,
            path,
            size,
            modified,
            scope,
            block_matches,
            block_request_id,
            git: None,
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

    #[test]
    fn discovery_budget_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        File::create(temp.path().join("a.txt"))
            .unwrap()
            .write_all(b"a")
            .unwrap();
        File::create(temp.path().join("b.txt"))
            .unwrap()
            .write_all(b"b")
            .unwrap();
        let source = LocalSource::new(temp.path().to_path_buf(), &[], &[], &[]).unwrap();
        let discovery = source.discover_with_budget(DiscoveryBudget {
            max_entries: 1,
            ..DiscoveryBudget::default()
        });
        assert!(discovery.aborted);
        assert!(discovery
            .fatal_errors
            .contains(&"DISCOVERY_ENTRY_LIMIT".to_string()));
        let discovery = source.discover_with_budget(DiscoveryBudget {
            deadline: Instant::now() - std::time::Duration::from_secs(1),
            ..DiscoveryBudget::default()
        });
        assert!(discovery.aborted);
        assert!(discovery
            .fatal_errors
            .contains(&"DISCOVERY_TIMEOUT".to_string()));
    }

    #[test]
    fn discovery_depth_limit_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("one/two/three")).unwrap();
        File::create(temp.path().join("one/two/three/file.txt"))
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let source = LocalSource::new(temp.path().to_path_buf(), &[], &[], &[]).unwrap();
        let discovery = source.discover_with_budget(DiscoveryBudget {
            max_depth: 1,
            ..DiscoveryBudget::default()
        });
        assert!(discovery.aborted);
        assert!(discovery
            .fatal_errors
            .contains(&"DISCOVERY_DEPTH_LIMIT".to_string()));
    }

    #[test]
    fn policy_evaluation_budget_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        File::create(temp.path().join("a.txt"))
            .unwrap()
            .write_all(b"a")
            .unwrap();
        let mut spec = PolicySpec::empty();
        spec.add_block(
            "B",
            PolicyOrigin::Repository,
            "**/*.txt",
            "budget test",
            "1",
            false,
        )
        .unwrap();
        let source = LocalSource::new_with_policy(temp.path().to_path_buf(), &spec).unwrap();
        let discovery = source.discover_with_budget(DiscoveryBudget {
            max_policy_work: 1,
            ..DiscoveryBudget::default()
        });
        assert!(discovery.aborted);
        assert!(discovery
            .fatal_errors
            .contains(&"POLICY_BUDGET_EXCEEDED".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn directory_symlink_escape_is_not_enumerated() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        File::create(outside.path().join("outside.txt"))
            .unwrap()
            .write_all(b"RNC_SYNTH_KEY_AWS_OUTSIDE")
            .unwrap();
        symlink(outside.path(), temp.path().join("escape")).unwrap();
        let source = LocalSource::new(temp.path().to_path_buf(), &[], &[], &[]).unwrap();
        let discovery = source.discover();
        assert!(!discovery.aborted);
        assert!(discovery
            .units
            .iter()
            .all(|unit| unit.locator != "escape/outside.txt"));
        let link = discovery
            .units
            .iter()
            .find(|unit| unit.locator == "escape")
            .expect("symlink entry recorded");
        assert_eq!(link.scope, PreScanScope::Skipped("SYMLINK_NOT_FOLLOWED"));
    }
}
