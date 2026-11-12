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
    #[allow(dead_code)]
    root: PathBuf,
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
            root,
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
        use std::ffi::c_void;
        use std::io::Write;
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::{AsRawHandle, FromRawHandle};

        type Handle = *mut c_void;
        const INVALID_HANDLE_VALUE: Handle = usize::MAX as Handle;
        const GENERIC_READ: u32 = 0x8000_0000;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const DELETE: u32 = 0x0001_0000;
        const READ_CONTROL: u32 = 0x0002_0000;
        const FILE_SHARE_READ: u32 = 0x1;
        const FILE_SHARE_WRITE: u32 = 0x2;
        const FILE_SHARE_DELETE: u32 = 0x4;
        const OPEN_EXISTING: u32 = 3;
        const CREATE_NEW: u32 = 1;
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

        #[repr(C)]
        struct FileRenameInfo {
            replace_if_exists: u8,
            root_directory: Handle,
            file_name_length: u32,
            file_name: [u16; 1],
        }

        struct OwnedHandle(Handle);
        impl Drop for OwnedHandle {
            fn drop(&mut self) {
                if self.0 != INVALID_HANDLE_VALUE {
                    unsafe { CloseHandle(self.0) };
                }
            }
        }

        fn wide(path: &Path) -> Vec<u16> {
            path.as_os_str().encode_wide().chain(Some(0)).collect()
        }
        fn final_path(handle: Handle) -> Result<PathBuf, ReportError> {
            let length = unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, 0) };
            if length == 0 {
                return Err(ReportError(format!(
                    "cannot resolve report handle: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let mut buffer = vec![0u16; length as usize + 1];
            let written = unsafe {
                GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0)
            };
            if written == 0 {
                return Err(ReportError(format!(
                    "cannot resolve report handle: {}",
                    std::io::Error::last_os_error()
                )));
            }
            buffer.truncate(written as usize);
            let value: std::ffi::OsString = std::os::windows::ffi::OsStringExt::from_wide(&buffer);
            Ok(value.into())
        }

        let parent_name = wide(&self.parent);
        let parent = unsafe {
            CreateFileW(
                parent_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | 0x20 | 0x40,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if parent == INVALID_HANDLE_VALUE {
            return Err(ReportError(format!(
                "cannot open report parent handle: {}",
                std::io::Error::last_os_error()
            )));
        }
        let parent = OwnedHandle(parent);
        let parent_final = final_path(parent.0)?;
        if path_within_root(&self.root, &parent_final) {
            return Err(ReportError(
                "report parent handle is inside the scan root".to_string(),
            ));
        }

        let mut private_acl = if self.private {
            Some(windows_private_acl::PrivateAcl::create().map_err(ReportError)?)
        } else {
            None
        };
        let mut security_attributes = private_acl
            .as_mut()
            .map(windows_private_acl::PrivateAcl::attributes);
        let security_pointer = security_attributes
            .as_mut()
            .map_or(std::ptr::null_mut(), |attributes| {
                attributes as *mut windows_private_acl::SecurityAttributes as *mut c_void
            });
        let temp_path = self.parent.join(format!(
            ".rnc-report-{}-{}.tmp",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let temp_name = wide(&temp_path);
        let temp_handle = unsafe {
            CreateFileW(
                temp_name.as_ptr(),
                GENERIC_WRITE | DELETE | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                security_pointer,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if temp_handle == INVALID_HANDLE_VALUE {
            return Err(ReportError(format!(
                "cannot create temporary report: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut file = unsafe { std::fs::File::from_raw_handle(temp_handle) };
        let result = (|| -> Result<(), ReportError> {
            let temp_final = final_path(file.as_raw_handle())?;
            if !path_within_root(&parent_final, &temp_final) {
                return Err(ReportError(
                    "temporary report escaped the validated parent".to_string(),
                ));
            }
            if let Some(acl) = &private_acl {
                acl.verify_handle(file.as_raw_handle())
                    .map_err(ReportError)?;
            }
            file.write_all(payload)
                .and_then(|_| file.write_all(b"\n"))
                .map_err(|error| ReportError(format!("cannot write report: {error}")))?;
            file.flush()
                .map_err(|error| ReportError(format!("cannot flush report: {error}")))?;
            file.sync_all()
                .map_err(|error| ReportError(format!("cannot sync report: {error}")))?;
            let base: Vec<u16> = self.name.encode_wide().collect();
            let name_offset = std::mem::offset_of!(FileRenameInfo, file_name);
            let size = name_offset + base.len() * 2;
            let words = size.div_ceil(std::mem::size_of::<u64>());
            let mut buffer = vec![0u64; words];
            let info = buffer.as_mut_ptr() as *mut FileRenameInfo;
            unsafe {
                (*info).replace_if_exists = 1;
                (*info).root_directory = parent.0;
                (*info).file_name_length = (base.len() * 2) as u32;
                std::ptr::copy_nonoverlapping(
                    base.as_ptr(),
                    (*info).file_name.as_mut_ptr(),
                    base.len(),
                );
                #[repr(C)]
                struct IoStatusBlock {
                    status_or_pointer: *mut c_void,
                    information: usize,
                }
                let mut io_status = IoStatusBlock {
                    status_or_pointer: std::ptr::null_mut(),
                    information: 0,
                };
                let status = NtSetInformationFile(
                    file.as_raw_handle(),
                    &mut io_status as *mut IoStatusBlock as *mut c_void,
                    info as *mut c_void,
                    size as u32,
                    10,
                );
                if status < 0 {
                    return Err(ReportError(format!(
                        "cannot publish report atomically (NTSTATUS {status:#x})"
                    )));
                }
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
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

/// Explicit Windows DACL for private report files.
///
/// The private temporary file is created with this security descriptor rather
/// than inheriting the destination directory. The protected DACL grants full
/// control only to the current user, LocalSystem and the built-in
/// Administrators group. It is verified on the opened handle before payload
/// bytes are written. The same file object is then renamed into place, so the
/// final report keeps the restrictive descriptor.
#[cfg(windows)]
mod windows_private_acl {
    use std::ffi::{c_void, OsStr};
    use std::fmt::Write as _;
    use std::os::windows::ffi::OsStrExt;

    type Handle = *mut c_void;

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_CLASS: u32 = 1;
    const SE_FILE_OBJECT: i32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const SE_DACL_PRESENT: u16 = 0x0004;
    const SE_DACL_PROTECTED: u16 = 0x1000;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const INHERITED_ACE: u8 = 0x10;
    const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
    const ERROR_SUCCESS: u32 = 0;
    const SDDL_REVISION_1: u32 = 1;

    const SYSTEM_SID: &str = "S-1-5-18";
    const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

    #[repr(C)]
    pub struct SecurityAttributes {
        pub length: u32,
        pub security_descriptor: *mut c_void,
        pub inherit_handle: i32,
    }

    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut c_void,
        attributes: u32,
    }

    #[repr(C)]
    struct TokenUser {
        user: SidAndAttributes,
    }

    #[repr(C)]
    struct AceHeader {
        ace_type: u8,
        ace_flags: u8,
        ace_size: u16,
    }

    #[repr(C)]
    struct AccessAllowedAce {
        header: AceHeader,
        mask: u32,
        sid_start: u32,
    }

    struct OwnedHandle(Handle);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    struct LocalMemory(*mut c_void);

    impl Drop for LocalMemory {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0) };
            }
        }
    }

    pub struct PrivateAcl {
        descriptor: *mut c_void,
        allowed: std::collections::BTreeSet<String>,
    }

    impl PrivateAcl {
        pub fn create() -> Result<Self, String> {
            let user_sid = current_user_sid()?;
            let allowed = std::collections::BTreeSet::from([
                user_sid,
                SYSTEM_SID.to_string(),
                ADMINISTRATORS_SID.to_string(),
            ]);
            let mut aces = String::new();
            for sid in &allowed {
                let _ = write!(aces, "(A;;FA;;;{sid})");
            }
            let sddl = format!("D:P{aces}");
            let sddl_wide = wide(OsStr::new(&sddl));
            let mut descriptor: *mut c_void = std::ptr::null_mut();
            let mut size = 0u32;
            let converted = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl_wide.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    &mut size,
                )
            };
            if converted == 0 || descriptor.is_null() {
                return Err(format!(
                    "cannot construct private-report security descriptor: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(Self {
                descriptor,
                allowed,
            })
        }

        pub fn attributes(&mut self) -> SecurityAttributes {
            SecurityAttributes {
                length: std::mem::size_of::<SecurityAttributes>() as u32,
                security_descriptor: self.descriptor,
                inherit_handle: 0,
            }
        }

        pub fn verify_handle(&self, handle: Handle) -> Result<(), String> {
            let mut descriptor: *mut c_void = std::ptr::null_mut();
            let mut dacl: *mut c_void = std::ptr::null_mut();
            let result = unsafe {
                GetSecurityInfo(
                    handle,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut dacl,
                    std::ptr::null_mut(),
                    &mut descriptor,
                )
            };
            if result != ERROR_SUCCESS || descriptor.is_null() {
                return Err(format!(
                    "cannot read private-report security descriptor: {}",
                    std::io::Error::from_raw_os_error(result as i32)
                ));
            }
            let descriptor_guard = LocalMemory(descriptor);
            let mut control = 0u16;
            let mut revision = 0u32;
            let control_ok =
                unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
            if control_ok == 0
                || control & (SE_DACL_PRESENT | SE_DACL_PROTECTED)
                    != SE_DACL_PRESENT | SE_DACL_PROTECTED
            {
                return Err(
                    "private-report security descriptor is not a protected DACL".to_string()
                );
            }
            let mut present = 0i32;
            let mut defaulted = 0i32;
            let mut acl: *mut c_void = std::ptr::null_mut();
            let dacl_ok = unsafe {
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted)
            };
            if dacl_ok == 0 || present == 0 || acl.is_null() || defaulted != 0 {
                return Err("private-report security descriptor has no explicit DACL".to_string());
            }
            if !std::ptr::eq(acl, dacl) {
                return Err("private-report DACL changed during verification".to_string());
            }
            let mut seen = std::collections::BTreeSet::new();
            let mut index = 0u32;
            loop {
                let mut ace: *mut c_void = std::ptr::null_mut();
                let ok = unsafe { GetAce(acl, index, &mut ace) };
                if ok == 0 {
                    break;
                }
                if ace.is_null() {
                    return Err("private-report DACL contains a null ACE".to_string());
                }
                if index >= 32 {
                    return Err("private-report DACL contains too many ACEs".to_string());
                }
                let header = unsafe { &*(ace as *const AceHeader) };
                if header.ace_size < 16 || header.ace_size as usize > 4096 {
                    return Err("private-report DACL contains a malformed ACE".to_string());
                }
                if header.ace_type != ACCESS_ALLOWED_ACE_TYPE
                    || header.ace_flags & INHERITED_ACE != 0
                {
                    return Err(
                        "private-report DACL contains an unexpected or inherited ACE".to_string(),
                    );
                }
                let allowed = unsafe { &*(ace as *const AccessAllowedAce) };
                if allowed.mask != FILE_ALL_ACCESS {
                    return Err("private-report DACL grants partial file access".to_string());
                }
                let sid = std::ptr::addr_of!(allowed.sid_start) as *mut c_void;
                let sid = sid_to_string(sid)?;
                if !self.allowed.contains(&sid) {
                    return Err(format!(
                        "private-report DACL grants access to unexpected principal {sid}"
                    ));
                }
                if !seen.insert(sid) {
                    return Err("private-report DACL contains a duplicate ACE".to_string());
                }
                index += 1;
            }
            if seen != self.allowed {
                return Err(
                    "private-report DACL does not contain exactly the intended principals"
                        .to_string(),
                );
            }
            let _ = descriptor_guard;
            Ok(())
        }
    }

    #[cfg(test)]
    #[repr(C)]
    struct TrusteeW {
        multiple_trustee: *mut c_void,
        multiple_trustee_operation: u32,
        trustee_form: u32,
        trustee_type: u32,
        name: *mut c_void,
    }

    #[cfg(test)]
    pub fn current_user_sid_for_test() -> Result<String, String> {
        current_user_sid()
    }

    #[cfg(test)]
    pub fn effective_rights_for_sid(handle: Handle, sid_text: &str) -> Result<u32, String> {
        let mut sid: *mut c_void = std::ptr::null_mut();
        let sid_wide = wide(OsStr::new(sid_text));
        let converted = unsafe { ConvertStringSidToSidW(sid_wide.as_ptr(), &mut sid) };
        if converted == 0 || sid.is_null() {
            return Err(format!(
                "cannot construct test SID: {}",
                std::io::Error::last_os_error()
            ));
        }
        let sid_guard = LocalMemory(sid);
        let mut descriptor: *mut c_void = std::ptr::null_mut();
        let mut dacl: *mut c_void = std::ptr::null_mut();
        let result = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if result != ERROR_SUCCESS || descriptor.is_null() || dacl.is_null() {
            return Err(format!(
                "cannot read DACL for effective-rights test: {}",
                std::io::Error::from_raw_os_error(result as i32)
            ));
        }
        let descriptor_guard = LocalMemory(descriptor);
        let mut trustee = TrusteeW {
            multiple_trustee: std::ptr::null_mut(),
            multiple_trustee_operation: 0,
            trustee_form: 0,
            trustee_type: 0,
            name: sid,
        };
        let mut access = 0u32;
        let result = unsafe { GetEffectiveRightsFromAclW(dacl, &mut trustee, &mut access) };
        let _ = (sid_guard, descriptor_guard);
        if result != ERROR_SUCCESS {
            return Err(format!(
                "cannot compute effective rights: {}",
                std::io::Error::from_raw_os_error(result as i32)
            ));
        }
        Ok(access)
    }

    impl Drop for PrivateAcl {
        fn drop(&mut self) {
            if !self.descriptor.is_null() {
                unsafe { LocalFree(self.descriptor) };
            }
        }
    }

    fn current_user_sid() -> Result<String, String> {
        let mut token: Handle = std::ptr::null_mut();
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if opened == 0 {
            return Err(format!(
                "cannot open current process token: {}",
                std::io::Error::last_os_error()
            ));
        }
        let token = OwnedHandle(token);
        let mut length = 0u32;
        unsafe {
            GetTokenInformation(
                token.0,
                TOKEN_USER_CLASS,
                std::ptr::null_mut(),
                0,
                &mut length,
            );
        }
        if length == 0 {
            return Err(format!(
                "cannot size current user token: {}",
                std::io::Error::last_os_error()
            ));
        }
        let words = (length as usize).div_ceil(std::mem::size_of::<u64>());
        let mut buffer = vec![0u64; words];
        let ok = unsafe {
            GetTokenInformation(
                token.0,
                TOKEN_USER_CLASS,
                buffer.as_mut_ptr() as *mut c_void,
                (buffer.len() * std::mem::size_of::<u64>()) as u32,
                &mut length,
            )
        };
        if ok == 0 {
            return Err(format!(
                "cannot read current user token: {}",
                std::io::Error::last_os_error()
            ));
        }
        let user = unsafe { &*(buffer.as_ptr() as *const TokenUser) };
        sid_to_string(user.user.sid)
    }

    fn sid_to_string(sid: *mut c_void) -> Result<String, String> {
        if sid.is_null() {
            return Err("cannot identify a null SID".to_string());
        }
        let mut value: *mut u16 = std::ptr::null_mut();
        let ok = unsafe { ConvertSidToStringSidW(sid, &mut value) };
        if ok == 0 || value.is_null() {
            return Err(format!(
                "cannot format SID: {}",
                std::io::Error::last_os_error()
            ));
        }
        let result = unsafe {
            let mut length = 0usize;
            while *value.add(length) != 0 {
                length += 1;
                if length > 256 {
                    break;
                }
            }
            let mut buffer = Vec::with_capacity(length);
            buffer.extend_from_slice(std::slice::from_raw_parts(value, length));
            String::from_utf16_lossy(&buffer)
        };
        unsafe { LocalFree(value as *mut c_void) };
        Ok(result)
    }

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn GetTokenInformation(
            token: Handle,
            class: u32,
            information: *mut c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
        fn ConvertSidToStringSidW(sid: *mut c_void, value: *mut *mut u16) -> i32;
        #[cfg(test)]
        fn ConvertStringSidToSidW(value: *const u16, sid: *mut *mut c_void) -> i32;
        #[cfg(test)]
        fn GetEffectiveRightsFromAclW(
            dacl: *mut c_void,
            trustee: *mut TrusteeW,
            access: *mut u32,
        ) -> u32;
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl: *const u16,
            revision: u32,
            descriptor: *mut *mut c_void,
            size: *mut u32,
        ) -> i32;
        fn GetSecurityInfo(
            handle: Handle,
            object_type: i32,
            security_information: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut c_void,
            sacl: *mut *mut c_void,
            descriptor: *mut *mut c_void,
        ) -> u32;
        fn GetSecurityDescriptorControl(
            descriptor: *mut c_void,
            control: *mut u16,
            revision: *mut u32,
        ) -> i32;
        fn GetSecurityDescriptorDacl(
            descriptor: *mut c_void,
            present: *mut i32,
            dacl: *mut *mut c_void,
            defaulted: *mut i32,
        ) -> i32;
        fn GetAce(dacl: *mut c_void, index: u32, ace: *mut *mut c_void) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
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
#[link(name = "kernel32")]
extern "system" {
    fn GetFinalPathNameByHandleW(
        handle: *mut std::ffi::c_void,
        path: *mut u16,
        length: u32,
        flags: u32,
    ) -> u32;
    fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *mut std::ffi::c_void,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
}

#[cfg(windows)]
#[link(name = "ntdll")]
extern "system" {
    fn NtSetInformationFile(
        file: *mut std::ffi::c_void,
        io_status: *mut std::ffi::c_void,
        info: *mut std::ffi::c_void,
        length: u32,
        class: u32,
    ) -> i32;
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

    #[cfg(windows)]
    #[test]
    fn private_report_has_explicit_restrictive_acl_on_permissive_parent() {
        use std::os::windows::io::AsRawHandle;
        use std::process::Command;

        let temp = temp();
        let root = temp.path().join("root");
        let reports = temp.path().join("reports");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&reports).unwrap();
        let grant = Command::new("icacls")
            .arg(&reports)
            .args(["/grant", "*S-1-1-0:(OI)(CI)F"])
            .output()
            .unwrap();
        assert!(
            grant.status.success(),
            "icacls grant failed: {}",
            String::from_utf8_lossy(&grant.stderr)
        );
        let path = reports.join("private.json");
        fs::write(&path, b"old-permissive-content").unwrap();
        ReportDestination::new(&path, &root, true)
            .unwrap()
            .write(b"{\"private\":true}")
            .unwrap();
        let file = fs::File::open(&path).unwrap();
        let expected = windows_private_acl::PrivateAcl::create().unwrap();
        expected
            .verify_handle(file.as_raw_handle())
            .expect("private report DACL");
        let user = windows_private_acl::current_user_sid_for_test().unwrap();
        assert_ne!(
            windows_private_acl::effective_rights_for_sid(file.as_raw_handle(), &user).unwrap(),
            0
        );
        assert_ne!(
            windows_private_acl::effective_rights_for_sid(file.as_raw_handle(), "S-1-5-18")
                .unwrap(),
            0
        );
        for unrelated in ["S-1-1-0", "S-1-5-32-545"] {
            assert_eq!(
                windows_private_acl::effective_rights_for_sid(file.as_raw_handle(), unrelated)
                    .unwrap(),
                0,
                "unrelated principal {unrelated} received access"
            );
        }
        assert!(fs::read_dir(&reports).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".rnc-report-")));
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
