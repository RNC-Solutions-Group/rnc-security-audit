//! Secure report destination resolution and atomic publication.
//!
//! Unix uses a directory-fd-relative `openat`/`renameat` chain with
//! `O_NOFOLLOW`, so an ancestor substitution cannot redirect creation or
//! replacement outside the validated parent. Windows validates canonical
//! containment and reparse points and uses `MoveFileExW` for a same-volume
//! replace; this is a narrower documented guarantee because Win32 does not
//! expose a stable public directory-relative rename chain.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub struct ReportError(pub String);

impl std::fmt::Display for ReportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ReportError {}

fn path_within_root(root: &Path, candidate: &Path) -> bool {
    #[cfg(windows)]
    {
        let normalize = |path: &Path| {
            path.to_string_lossy()
                .replace("\\\\?\\", "")
                .replace('/', "\\")
                .to_ascii_lowercase()
        };
        let root = normalize(root);
        let candidate = normalize(candidate);
        if candidate == root {
            return true;
        }
        let prefix = if root.ends_with('\\') {
            root
        } else {
            format!("{root}\\")
        };
        candidate.starts_with(&prefix)
    }
    #[cfg(not(windows))]
    {
        candidate.starts_with(root)
    }
}

#[derive(Debug, Clone)]
pub struct ReportDestination {
    #[allow(dead_code)]
    path: PathBuf,
    parent: PathBuf,
    #[allow(dead_code)]
    name: OsString,
    #[allow(dead_code)]
    private: bool,
}

impl ReportDestination {
    /// Resolve a report path against the process working directory and prove
    /// that its parent and final path are outside the authorized scan root.
    /// Resolution failure is fatal; the caller must not fall back to the
    /// original relative path.
    pub fn new(output: &Path, root: &Path, private: bool) -> Result<Self, ReportError> {
        let root = fs::canonicalize(root)
            .map_err(|error| ReportError(format!("cannot resolve scan root: {error}")))?;
        let working = std::env::current_dir()
            .map_err(|error| ReportError(format!("cannot resolve working directory: {error}")))?;
        let absolute = if output.is_absolute() {
            output.to_path_buf()
        } else {
            working.join(output)
        };
        let name = absolute
            .file_name()
            .ok_or_else(|| ReportError("report path has no file name".to_string()))?
            .to_os_string();
        if name.is_empty() || name == "." || name == ".." {
            return Err(ReportError(
                "report path has an invalid file name".to_string(),
            ));
        }
        let parent = absolute
            .parent()
            .ok_or_else(|| ReportError("report path has no parent directory".to_string()))?;
        let parent = fs::canonicalize(parent)
            .map_err(|error| ReportError(format!("cannot resolve report parent: {error}")))?;
        if !parent.is_dir() {
            return Err(ReportError("report parent is not a directory".to_string()));
        }
        if path_within_root(&root, &parent) {
            return Err(ReportError(
                "report output must be outside the scan root".to_string(),
            ));
        }
        let resolved = parent.join(&name);
        if path_within_root(&root, &resolved) {
            return Err(ReportError(
                "report output must be outside the scan root".to_string(),
            ));
        }
        if let Ok(metadata) = fs::symlink_metadata(&resolved) {
            if is_link_or_reparse(&metadata) {
                return Err(ReportError(
                    "report output must not be a symbolic link or reparse point".to_string(),
                ));
            }
            if metadata.is_dir() {
                return Err(ReportError(
                    "report output must not be a directory".to_string(),
                ));
            }
        }
        Ok(Self {
            path: resolved,
            parent,
            name,
            private,
        })
    }

    /// Publish complete bytes atomically. The destination is either the old
    /// complete file or the new complete file; a failed or interrupted write
    /// leaves the destination untouched and removes the temporary file.
    pub fn write(&self, payload: &[u8]) -> Result<(), ReportError> {
        #[cfg(unix)]
        {
            let mut hook = || {};
            self.write_unix_with_hook(payload, &mut hook)
        }
        #[cfg(windows)]
        {
            self.write_windows(payload)
        }
        #[cfg(not(any(unix, windows)))]
        {
            self.write_fallback(payload)
        }
    }

    #[cfg(all(unix, test))]
    pub fn write_with_hook(
        &self,
        payload: &[u8],
        hook: &mut dyn FnMut(),
    ) -> Result<(), ReportError> {
        self.write_unix_with_hook(payload, hook)
    }

    #[cfg(unix)]
    fn write_unix_with_hook(
        &self,
        payload: &[u8],
        hook: &mut dyn FnMut(),
    ) -> Result<(), ReportError> {
        use std::ffi::CString;
        use std::io::Write;
        use std::os::fd::{FromRawFd, RawFd};
        use std::os::unix::ffi::OsStrExt;

        fn cstring(value: &std::ffi::OsStr) -> Result<CString, ReportError> {
            CString::new(value.as_bytes())
                .map_err(|_| ReportError("report path contains NUL".to_string()))
        }
        fn open_dir(fd: RawFd, component: &std::ffi::OsStr) -> Result<RawFd, ReportError> {
            let name = cstring(component)?;
            let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            let opened = unsafe { libc::openat(fd, name.as_ptr(), flags) };
            if opened < 0 {
                return Err(ReportError(format!(
                    "cannot open report parent component: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(opened)
        }
        fn open_parent(path: &Path) -> Result<RawFd, ReportError> {
            let root = cstring(std::ffi::OsStr::new("/"))?;
            let mut current = unsafe {
                libc::open(
                    root.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if current < 0 {
                return Err(ReportError(format!(
                    "cannot open filesystem root: {}",
                    std::io::Error::last_os_error()
                )));
            }
            for component in path.components() {
                let std::path::Component::Normal(value) = component else {
                    continue;
                };
                match open_dir(current, value) {
                    Ok(next) => {
                        unsafe { libc::close(current) };
                        current = next;
                    }
                    Err(error) => {
                        unsafe { libc::close(current) };
                        return Err(error);
                    }
                }
            }
            Ok(current)
        }
        fn stat_at(dir: RawFd, name: &std::ffi::OsStr) -> Result<Option<libc::stat>, ReportError> {
            let name = cstring(name)?;
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            let result = unsafe {
                libc::fstatat(
                    dir,
                    name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if result == 0 {
                Ok(Some(unsafe { stat.assume_init() }))
            } else {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ENOENT) {
                    Ok(None)
                } else {
                    Err(ReportError(format!(
                        "cannot inspect report destination: {error}"
                    )))
                }
            }
        }

        let dir = open_parent(&self.parent)?;
        hook();
        if let Some(stat) = stat_at(dir, &self.name)? {
            let kind = stat.st_mode & libc::S_IFMT;
            if kind != libc::S_IFREG {
                unsafe { libc::close(dir) };
                return Err(ReportError(
                    "report output must be an existing regular file or absent".to_string(),
                ));
            }
        }
        let mode = if self.private { 0o600 } else { 0o644 };
        let mut temp_name = OsString::new();
        let mut temp_fd = -1;
        for _ in 0..32 {
            let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            temp_name = OsString::from(format!(".rnc-report-{}-{counter}.tmp", std::process::id()));
            let temp = cstring(&temp_name)?;
            temp_fd = unsafe {
                libc::openat(
                    dir,
                    temp.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    mode,
                )
            };
            if temp_fd >= 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                unsafe { libc::close(dir) };
                return Err(ReportError(format!(
                    "cannot create temporary report: {error}"
                )));
            }
        }
        if temp_fd < 0 {
            unsafe { libc::close(dir) };
            return Err(ReportError(
                "cannot allocate a unique temporary report".to_string(),
            ));
        }
        let mut file = unsafe { std::fs::File::from_raw_fd(temp_fd) };
        let result = (|| -> Result<(), ReportError> {
            file.write_all(payload)
                .and_then(|_| file.write_all(b"\n"))
                .map_err(|error| ReportError(format!("cannot write report: {error}")))?;
            file.flush()
                .map_err(|error| ReportError(format!("cannot flush report: {error}")))?;
            file.sync_all()
                .map_err(|error| ReportError(format!("cannot sync report: {error}")))?;
            let rc = unsafe { libc::fchmod(temp_fd, mode) };
            if rc != 0 {
                return Err(ReportError(format!(
                    "cannot restrict report permissions: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // Reject a symlink introduced after the initial check; renameat
            // would replace the link safely, but reporting policy is to fail.
            if let Some(stat) = stat_at(dir, &self.name)? {
                let kind = stat.st_mode & libc::S_IFMT;
                if kind != libc::S_IFREG {
                    return Err(ReportError(
                        "report destination changed to an unsafe object".to_string(),
                    ));
                }
            }
            let temp = cstring(&temp_name)?;
            let destination = cstring(&self.name)?;
            let rc = unsafe { libc::renameat(dir, temp.as_ptr(), dir, destination.as_ptr()) };
            if rc != 0 {
                return Err(ReportError(format!(
                    "cannot publish report atomically: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let _ = unsafe { libc::fsync(dir) };
            Ok(())
        })();
        drop(file);
        if result.is_err() {
            if let Ok(temp) = cstring(&temp_name) {
                unsafe { libc::unlinkat(dir, temp.as_ptr(), 0) };
            }
        }
        unsafe { libc::close(dir) };
        result
    }

    #[cfg(windows)]
    fn write_windows(&self, payload: &[u8]) -> Result<(), ReportError> {
        use std::io::Write;
        use std::os::windows::ffi::OsStrExt;
        let temp = self.parent.join(format!(
            ".rnc-report-{}-{}.tmp",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = options
            .open(&temp)
            .map_err(|error| ReportError(format!("cannot create temporary report: {error}")))?;
        let result = (|| -> Result<(), ReportError> {
            file.write_all(payload)
                .and_then(|_| file.write_all(b"\n"))
                .map_err(|error| ReportError(format!("cannot write report: {error}")))?;
            file.flush()
                .map_err(|error| ReportError(format!("cannot flush report: {error}")))?;
            file.sync_all()
                .map_err(|error| ReportError(format!("cannot sync report: {error}")))?;
            drop(file);
            if let Ok(metadata) = fs::symlink_metadata(&self.path) {
                if is_link_or_reparse(&metadata) || metadata.is_dir() {
                    return Err(ReportError(
                        "report destination is not a safe regular file".to_string(),
                    ));
                }
            }
            let from: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
            let to: Vec<u16> = self.path.as_os_str().encode_wide().chain(Some(0)).collect();
            let replaced = unsafe {
                MoveFileExW(
                    from.as_ptr(),
                    to.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            };
            if replaced == 0 {
                return Err(ReportError(format!(
                    "cannot publish report atomically: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    #[cfg(not(any(unix, windows)))]
    fn write_fallback(&self, payload: &[u8]) -> Result<(), ReportError> {
        let temp = self.parent.join(format!(
            ".rnc-report-{}-{}.tmp",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&temp, payload)
            .map_err(|error| ReportError(format!("cannot write temporary report: {error}")))?;
        fs::rename(&temp, &self.path)
            .map_err(|error| ReportError(format!("cannot publish report: {error}")))
    }
}

#[cfg(windows)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
#[cfg(windows)]
const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn absolute_path_outside_root_is_accepted_and_atomic() {
        let temp = temp();
        let root = temp.path().join("root");
        let reports = temp.path().join("reports");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&reports).unwrap();
        let destination =
            ReportDestination::new(&reports.join("report.json"), &root, true).unwrap();
        destination.write(b"{\"ok\":true}").unwrap();
        assert_eq!(
            fs::read_to_string(reports.join("report.json")).unwrap(),
            "{\"ok\":true}\n"
        );
    }

    #[test]
    fn existing_regular_file_is_replaced() {
        let temp = temp();
        let root = temp.path().join("root");
        let reports = temp.path().join("reports");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&reports).unwrap();
        let path = reports.join("report.json");
        fs::write(&path, b"old").unwrap();
        ReportDestination::new(&path, &root, false)
            .unwrap()
            .write(b"new")
            .unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new\n");
    }

    #[cfg(unix)]
    #[test]
    fn final_and_parent_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;
        let temp = temp();
        let root = temp.path().join("root");
        let reports = temp.path().join("reports");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&reports).unwrap();
        fs::write(root.join("target.json"), b"target").unwrap();
        let link = reports.join("link.json");
        symlink(root.join("target.json"), &link).unwrap();
        assert!(ReportDestination::new(&link, &root, true).is_err());
        let parent_link = temp.path().join("parent-link");
        symlink(&reports, &parent_link).unwrap();
        assert!(ReportDestination::new(&parent_link.join("x.json"), &root, true).is_ok());
        let into_root = temp.path().join("into-root");
        symlink(&root, &into_root).unwrap();
        assert!(ReportDestination::new(&into_root.join("x.json"), &root, true).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_report_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let temp = temp();
        let root = temp.path().join("root");
        let reports = temp.path().join("reports");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&reports).unwrap();
        let path = reports.join("private.json");
        ReportDestination::new(&path, &root, true)
            .unwrap()
            .write(b"{}")
            .unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn parent_substitution_cannot_redirect_publish() {
        use std::os::unix::fs::symlink;
        let temp = temp();
        let root = temp.path().join("root");
        let reports = temp.path().join("reports");
        let elsewhere = temp.path().join("elsewhere");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&reports).unwrap();
        fs::create_dir_all(&elsewhere).unwrap();
        let path = reports.join("report.json");
        let destination = ReportDestination::new(&path, &root, true).unwrap();
        let mut hook = || {
            fs::rename(&reports, temp.path().join("moved-reports")).unwrap();
            symlink(&elsewhere, &reports).unwrap();
        };
        destination.write_with_hook(b"safe", &mut hook).unwrap();
        assert!(!elsewhere.join("report.json").exists());
        assert_eq!(
            fs::read_to_string(temp.path().join("moved-reports/report.json")).unwrap(),
            "safe\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn final_component_substitution_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;
        let temp = temp();
        let root = temp.path().join("root");
        let reports = temp.path().join("reports");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&reports).unwrap();
        let target = temp.path().join("target.txt");
        fs::write(&target, b"unchanged").unwrap();
        let path = reports.join("report.json");
        let destination = ReportDestination::new(&path, &root, true).unwrap();
        let mut hook = || {
            symlink(&target, &path).unwrap();
        };
        assert!(destination.write_with_hook(b"new", &mut hook).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");
    }
}
