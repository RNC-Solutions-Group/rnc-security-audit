//! Read-only local Git-history acquisition.
//!
//! The adapter never checks out, resets, fetches, writes the index, runs hooks,
//! invokes external diff drivers or follows submodules. It asks the installed
//! Git executable for commit metadata, raw first-parent tree deltas and blob
//! bytes using bounded pipes. Historical source units are commit/path
//! revisions, so equal credential bytes in different commits remain distinct
//! occurrences.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::CoreError;
use crate::input::{Discovery, GitBlobRef, GitDiffSpec, GitHistoryInfo, PreScanScope};
use crate::path::sha256_hex;

pub const GIT_SOURCE_KIND: &str = "git_commit_blob";
pub const GIT_ADAPTER_ID: &str = "local-git-history";
pub const DEFAULT_MAX_COMMITS: usize = 2_000;
pub const DEFAULT_MAX_UNITS: usize = 20_000;
const MAX_REF_BYTES: usize = 1024;
const MAX_STDERR_BYTES: usize = 64 * 1024;
const MAX_BATCH_HEADER_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitIoMode {
    Process,
    Batch,
}

impl GitIoMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Batch => "batch",
        }
    }

    pub fn parse(value: &str) -> Result<Self, CoreError> {
        match value {
            "process" => Ok(Self::Process),
            "batch" => Ok(Self::Batch),
            _ => Err(CoreError::Input(
                "--git-io must be process or batch".to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitHistoryMode {
    Whole,
    Diff,
}

impl GitHistoryMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Whole => "whole",
            Self::Diff => "diff",
        }
    }

    pub fn parse(value: &str) -> Result<Self, CoreError> {
        match value {
            "whole" => Ok(Self::Whole),
            "diff" => Ok(Self::Diff),
            _ => Err(CoreError::Input(
                "--history-mode must be whole or diff".to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GitHistoryOptions {
    pub refs: Vec<String>,
    pub max_commits: usize,
    pub max_units: usize,
    pub io: GitIoMode,
    pub history_mode: GitHistoryMode,
    pub context_lines: usize,
    pub profiler: Option<Arc<crate::profile::Profiler>>,
}

impl Default for GitHistoryOptions {
    fn default() -> Self {
        Self {
            refs: Vec::new(),
            max_commits: DEFAULT_MAX_COMMITS,
            max_units: DEFAULT_MAX_UNITS,
            io: GitIoMode::Process,
            history_mode: GitHistoryMode::Whole,
            context_lines: 0,
            profiler: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum GitReadError {
    Timeout,
    TooLarge,
    ObjectUnavailable,
}

impl GitReadError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Timeout => "TIMEOUT",
            Self::TooLarge => "FILE_SIZE_LIMIT",
            Self::ObjectUnavailable => "GIT_OBJECT_UNAVAILABLE",
        }
    }
}

#[derive(Debug)]
enum GitFailure {
    Timeout,
    OutputLimit,
    CommitLimit,
    UnitLimit,
    Status,
    Spawn,
    InvalidData,
}

impl GitFailure {
    fn code(&self) -> &'static str {
        match self {
            Self::Timeout => "GIT_TIMEOUT",
            Self::OutputLimit => "GIT_OUTPUT_LIMIT",
            Self::CommitLimit => "GIT_COMMIT_LIMIT",
            Self::UnitLimit => "GIT_UNIT_LIMIT",
            Self::Status => "GIT_COMMAND_FAILED",
            Self::Spawn => "GIT_UNAVAILABLE",
            Self::InvalidData => "GIT_INVALID_DATA",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileKind {
    None,
    Wall,
    Worker,
}

#[derive(Debug)]
struct GitRunner {
    repo: PathBuf,
    deadline: Instant,
    profiler: Option<Arc<crate::profile::Profiler>>,
    profile_kind: ProfileKind,
}

impl GitRunner {
    fn new(repo: &Path, deadline: Instant) -> Self {
        Self {
            repo: repo.to_path_buf(),
            deadline,
            profiler: None,
            profile_kind: ProfileKind::None,
        }
    }

    fn with_profile(
        repo: &Path,
        deadline: Instant,
        profiler: Option<Arc<crate::profile::Profiler>>,
        profile_kind: ProfileKind,
    ) -> Self {
        Self {
            repo: repo.to_path_buf(),
            deadline,
            profiler,
            profile_kind,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new("git");
        command
            .arg("--no-replace-objects")
            .arg("-C")
            .arg(&self.repo)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_PAGER", "cat")
            .env("GIT_ALLOW_PROTOCOL", "file")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for name in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_COMMON_DIR",
            "GIT_NAMESPACE",
            "GIT_CONFIG",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_COUNT",
            "GIT_EXTERNAL_DIFF",
            "GIT_DIFF_OPTS",
            "GIT_SSH",
            "GIT_SSH_COMMAND",
            "GIT_ASKPASS",
            "SSH_ASKPASS",
        ] {
            command.env_remove(name);
        }
        command
    }

    fn run<I, S>(&self, args: I, max_output: usize) -> Result<Vec<u8>, GitFailure>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.run_named("command", args, max_output)
    }

    fn run_named<I, S>(&self, name: &str, args: I, max_output: usize) -> Result<Vec<u8>, GitFailure>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let started = Instant::now();
        let result = self.run_inner(args, max_output);
        if let Some(profiler) = &self.profiler {
            let phase = format!("git.{name}");
            let bytes = result.as_ref().map(|value| value.len() as u64).unwrap_or(0);
            match self.profile_kind {
                ProfileKind::Wall => {
                    profiler.record_wall_duration(&phase, started.elapsed(), bytes, 1)
                }
                ProfileKind::Worker => profiler.record_worker(&phase, started.elapsed(), bytes, 1),
                ProfileKind::None => {}
            }
        }
        result
    }

    fn run_inner<I, S>(&self, args: I, max_output: usize) -> Result<Vec<u8>, GitFailure>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut child = self
            .command()
            .args(args)
            .spawn()
            .map_err(|_| GitFailure::Spawn)?;
        let stdout = child.stdout.take().ok_or(GitFailure::Spawn)?;
        let stderr = child.stderr.take().ok_or(GitFailure::Spawn)?;
        let exceeded = Arc::new(AtomicBool::new(false));
        let stdout_flag = Arc::clone(&exceeded);
        let stdout_reader =
            std::thread::spawn(move || read_bounded(stdout, max_output, stdout_flag));
        let stderr_flag = Arc::clone(&exceeded);
        let stderr_reader =
            std::thread::spawn(move || read_bounded(stderr, MAX_STDERR_BYTES, stderr_flag));
        let status = loop {
            if exceeded.load(Ordering::Relaxed) {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(GitFailure::OutputLimit);
            }
            if Instant::now() >= self.deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(GitFailure::Timeout);
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_reader.join();
                    let _ = stderr_reader.join();
                    return Err(GitFailure::Spawn);
                }
            }
        };
        let output = stdout_reader
            .join()
            .map_err(|_| GitFailure::Spawn)?
            .map_err(|_| GitFailure::OutputLimit)?;
        let _ = stderr_reader.join();
        if !status.success() {
            return Err(GitFailure::Status);
        }
        Ok(output)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BatchError {
    Timeout,
    TooLarge,
    ObjectUnavailable,
    Protocol,
}

struct BatchRequest {
    oid: String,
    max_bytes: u64,
    reply: SyncSender<Result<Vec<u8>, BatchError>>,
}

struct BatchReader {
    request_tx: Option<SyncSender<BatchRequest>>,
    worker: Option<std::thread::JoinHandle<()>>,
    child: Arc<Mutex<Child>>,
    stderr: Option<std::thread::JoinHandle<()>>,
    stderr_exceeded: Arc<AtomicBool>,
}

impl std::fmt::Debug for BatchReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BatchReader")
    }
}

impl BatchReader {
    fn start(
        repo: &Path,
        deadline: Instant,
        profiler: Option<Arc<crate::profile::Profiler>>,
    ) -> Result<Self, BatchError> {
        let runner = GitRunner::new(repo, deadline);
        let mut command = runner.command();
        command
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let start = Instant::now();
        let mut child = command.spawn().map_err(|_| BatchError::ObjectUnavailable)?;
        if let Some(profiler) = &profiler {
            profiler.record_worker("git.batch.start", start.elapsed(), 0, 1);
        }
        let stdin = child.stdin.take().ok_or(BatchError::ObjectUnavailable)?;
        let stdout = child.stdout.take().ok_or(BatchError::ObjectUnavailable)?;
        let stderr = child.stderr.take().ok_or(BatchError::ObjectUnavailable)?;
        let exceeded = Arc::new(AtomicBool::new(false));
        let stderr_flag = Arc::clone(&exceeded);
        let stderr_handle = std::thread::spawn(move || {
            let _ = read_bounded(stderr, MAX_STDERR_BYTES, stderr_flag);
        });
        let (request_tx, request_rx) = sync_channel(4);
        let child = Arc::new(Mutex::new(child));
        let worker = std::thread::spawn(move || {
            batch_worker(stdin, stdout, request_rx, profiler.as_deref());
        });
        Ok(Self {
            request_tx: Some(request_tx),
            worker: Some(worker),
            child,
            stderr: Some(stderr_handle),
            stderr_exceeded: exceeded,
        })
    }

    fn read_blob(
        &self,
        oid: &str,
        max_bytes: u64,
        deadline: Instant,
    ) -> Result<Vec<u8>, BatchError> {
        if self.stderr_exceeded.load(Ordering::Relaxed) {
            return Err(BatchError::Protocol);
        }
        let (reply_tx, reply_rx) = sync_channel(1);
        self.request_tx
            .as_ref()
            .ok_or(BatchError::ObjectUnavailable)?
            .send(BatchRequest {
                oid: oid.to_string(),
                max_bytes,
                reply: reply_tx,
            })
            .map_err(|_| BatchError::ObjectUnavailable)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        match reply_rx.recv_timeout(remaining) {
            Ok(Ok(bytes)) => Ok(bytes),
            Ok(Err(error)) => Err(error),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                self.kill();
                Err(BatchError::Timeout)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(BatchError::Protocol),
        }
    }

    fn kill(&self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
        }
    }
}

impl Drop for BatchReader {
    fn drop(&mut self) {
        drop(self.request_tx.take());
        self.kill();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        if let Ok(mut child) = self.child.lock() {
            let _ = child.wait();
        }
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.join();
        }
    }
}

fn batch_worker(
    mut stdin: ChildStdin,
    stdout: ChildStdout,
    requests: Receiver<BatchRequest>,
    profiler: Option<&crate::profile::Profiler>,
) {
    let mut reader = BufReader::new(stdout);
    while let Ok(request) = requests.recv() {
        let started = Instant::now();
        let result = batch_read(&mut stdin, &mut reader, &request);
        if let Some(profiler) = profiler {
            let bytes = result.as_ref().map(|value| value.len() as u64).unwrap_or(0);
            profiler.record_worker("git.acquire.batch", started.elapsed(), bytes, 1);
        }
        let fatal = result.is_err();
        let _ = request.reply.send(result);
        if fatal {
            break;
        }
    }
}

fn batch_read(
    stdin: &mut ChildStdin,
    reader: &mut BufReader<ChildStdout>,
    request: &BatchRequest,
) -> Result<Vec<u8>, BatchError> {
    stdin
        .write_all(format!("{}\n", request.oid).as_bytes())
        .map_err(|_| BatchError::ObjectUnavailable)?;
    stdin.flush().map_err(|_| BatchError::ObjectUnavailable)?;

    let mut header = String::new();
    reader
        .read_line(&mut header)
        .map_err(|_| BatchError::ObjectUnavailable)?;
    if header.is_empty() || header.len() > MAX_BATCH_HEADER_BYTES {
        return Err(BatchError::Protocol);
    }
    let header = header.trim_end_matches(['\r', '\n']);
    let mut fields = header.split_whitespace();
    let oid = fields.next().ok_or(BatchError::Protocol)?;
    let kind = fields.next().ok_or(BatchError::Protocol)?;
    let size = fields.next().ok_or(BatchError::Protocol)?;
    if fields.next().is_some() || oid != request.oid || kind != "blob" {
        return Err(BatchError::Protocol);
    }
    let size = size.parse::<u64>().map_err(|_| BatchError::Protocol)?;
    if size > request.max_bytes {
        return Err(BatchError::TooLarge);
    }
    let size = usize::try_from(size).map_err(|_| BatchError::TooLarge)?;
    let mut bytes = vec![0u8; size.saturating_add(1)];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| BatchError::ObjectUnavailable)?;
    if bytes.last() != Some(&b'\n') {
        return Err(BatchError::Protocol);
    }
    bytes.pop();
    Ok(bytes)
}

fn read_bounded(
    mut reader: impl Read,
    limit: usize,
    exceeded: Arc<AtomicBool>,
) -> Result<Vec<u8>, ()> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = reader.read(&mut buffer).map_err(|_| ())?;
        if read == 0 {
            break;
        }
        if output.len().saturating_add(read) > limit {
            exceeded.store(true, Ordering::Relaxed);
            return Err(());
        }
        output.extend_from_slice(&buffer[..read]);
    }
    Ok(output)
}

fn optional_output(
    runner: &GitRunner,
    args: &[&str],
    limit: usize,
) -> Result<Option<Vec<u8>>, GitFailure> {
    match runner.run(args, limit) {
        Ok(output) => Ok(Some(output)),
        Err(GitFailure::Status) => Ok(None),
        Err(error) => Err(error),
    }
}

fn text(output: &[u8]) -> Result<String, GitFailure> {
    std::str::from_utf8(output)
        .map(str::trim)
        .map(str::to_string)
        .map_err(|_| GitFailure::InvalidData)
}

fn valid_oid(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REF_BYTES
        && !value.starts_with('-')
        && !value.chars().any(char::is_control)
        && !value.contains(char::is_whitespace)
        && !value.contains("..")
        && !value.contains("@{")
        && !value.contains(':')
        && !value.contains('?')
        && !value.contains('*')
        && !value.contains('[')
        && !value.contains('\\')
        && !value.contains('^')
        && !value.contains('~')
}

#[derive(Debug)]
enum DiffAvailability {
    Text(GitDiffSpec),
    Binary,
    NoIntroduced,
}

fn diff_for_unit(
    runner: &GitRunner,
    commit: &str,
    parent: Option<&str>,
    path: &str,
    context_lines: usize,
) -> Result<DiffAvailability, GitFailure> {
    let mut args: Vec<OsString> = Vec::new();
    if parent.is_some() {
        args.push(OsString::from("diff"));
        args.push(OsString::from("--no-color"));
        args.push(OsString::from("--no-ext-diff"));
        args.push(OsString::from("--no-textconv"));
        args.push(OsString::from("--no-renames"));
        args.push(OsString::from(format!("-U{context_lines}")));
        args.push(OsString::from(parent.expect("checked parent")));
        args.push(OsString::from(commit));
        args.push(OsString::from("--"));
        args.push(OsString::from(path));
    } else {
        args.push(OsString::from("diff-tree"));
        args.push(OsString::from("--root"));
        args.push(OsString::from("-p"));
        args.push(OsString::from("--no-commit-id"));
        args.push(OsString::from("--no-renames"));
        args.push(OsString::from("--no-ext-diff"));
        args.push(OsString::from("--no-textconv"));
        args.push(OsString::from("-r"));
        args.push(OsString::from(format!("-U{context_lines}")));
        args.push(OsString::from(commit));
        args.push(OsString::from("--"));
        args.push(OsString::from(path));
    }
    let output = runner.run_named("diff", args, 32 * 1024 * 1024)?;
    parse_diff(&output)
}

fn parse_diff(output: &[u8]) -> Result<DiffAvailability, GitFailure> {
    if output
        .split(|byte| *byte == b'\n')
        .any(|line| line.starts_with(b"Binary files ") || line.starts_with(b"GIT binary patch"))
    {
        return Ok(DiffAvailability::Binary);
    }
    let text = std::str::from_utf8(output).map_err(|_| GitFailure::InvalidData)?;
    let mut introduced_lines = Vec::new();
    let mut scan_line_ranges = Vec::new();
    let mut current: Option<(usize, usize, usize)> = None;
    for line in text.lines() {
        if line.starts_with("@@ ") {
            if let Some((start, count, _)) = current.take() {
                if count > 0 {
                    scan_line_ranges.push((start, start + count - 1));
                }
            }
            let (start, count) = parse_hunk_header(line).ok_or(GitFailure::InvalidData)?;
            current = Some((start, count, start));
            continue;
        }
        let Some((_, _, new_line)) = current.as_mut() else {
            continue;
        };
        if line.starts_with('+') {
            introduced_lines.push(*new_line);
            *new_line += 1;
        } else if line.starts_with(' ') {
            *new_line += 1;
        } else if line.starts_with('-') || line.starts_with('\\') {
            // Deleted lines and "\ No newline" do not advance the new file.
        } else {
            // A new file header ends the current hunk.
            if let Some((start, count, _)) = current.take() {
                if count > 0 {
                    scan_line_ranges.push((start, start + count - 1));
                }
            }
        }
    }
    if let Some((start, count, _)) = current {
        if count > 0 {
            scan_line_ranges.push((start, start + count - 1));
        }
    }
    if introduced_lines.is_empty() {
        return Ok(DiffAvailability::NoIntroduced);
    }
    introduced_lines.sort_unstable();
    introduced_lines.dedup();
    scan_line_ranges.sort_unstable();
    scan_line_ranges.dedup();
    Ok(DiffAvailability::Text(GitDiffSpec {
        introduced_lines,
        scan_line_ranges,
    }))
}

fn parse_hunk_header(line: &str) -> Option<(usize, usize)> {
    let plus = line.find(" +")?;
    let rest = &line[plus + 2..];
    let end = rest.find(' ').unwrap_or(rest.len());
    let range = &rest[..end];
    let (start, count) = match range.split_once(',') {
        Some((start, count)) => (start, count),
        None => (range, "1"),
    };
    let start = start.parse::<usize>().ok()?;
    let count = count.parse::<usize>().ok()?;
    Some((start, count))
}

#[derive(Debug)]
pub struct GitHistorySource {
    repo: PathBuf,
    source_id: String,
    repository_id: String,
    refs: Vec<String>,
    resolved_refs: Vec<String>,
    max_commits: usize,
    max_units: usize,
    io: GitIoMode,
    history_mode: GitHistoryMode,
    context_lines: usize,
    profiler: Option<Arc<crate::profile::Profiler>>,
    batch: Arc<Mutex<Option<BatchReader>>>,
    empty: bool,
}

impl Clone for GitHistorySource {
    fn clone(&self) -> Self {
        Self {
            repo: self.repo.clone(),
            source_id: self.source_id.clone(),
            repository_id: self.repository_id.clone(),
            refs: self.refs.clone(),
            resolved_refs: self.resolved_refs.clone(),
            max_commits: self.max_commits,
            max_units: self.max_units,
            io: self.io,
            history_mode: self.history_mode,
            context_lines: self.context_lines,
            profiler: self.profiler.clone(),
            batch: Arc::clone(&self.batch),
            empty: self.empty,
        }
    }
}

impl GitHistorySource {
    pub fn open(repo: PathBuf, options: &GitHistoryOptions) -> Result<Self, CoreError> {
        if options.max_commits == 0 || options.max_units == 0 {
            return Err(CoreError::Input(
                "Git history limits must be positive".to_string(),
            ));
        }
        if options.history_mode == GitHistoryMode::Whole && options.context_lines != 0 {
            return Err(CoreError::Input(
                "--context-lines requires --history-mode diff".to_string(),
            ));
        }
        if options.context_lines > 5 {
            return Err(CoreError::Input(
                "--context-lines must be 0, 1, 3 or 5".to_string(),
            ));
        }
        let repo = std::fs::canonicalize(repo).map_err(CoreError::Io)?;
        if !repo.is_dir() {
            return Err(CoreError::Input(
                "Git repository path is not a directory".to_string(),
            ));
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        let runner =
            GitRunner::with_profile(&repo, deadline, options.profiler.clone(), ProfileKind::Wall);
        let git_dir = text(
            &runner
                .run_named("open", ["rev-parse", "--absolute-git-dir"], 16 * 1024)
                .map_err(|failure| {
                    CoreError::Input(format!("not a Git repository: {}", failure.code()))
                })?,
        )
        .map_err(|_| CoreError::Input("Git directory path is not UTF-8".to_string()))?;
        let git_dir = PathBuf::from(git_dir);
        let git_dir = std::fs::canonicalize(&git_dir).unwrap_or(git_dir);
        let repository_id = repository_id(&git_dir);

        if optional_output(&runner, &["rev-parse", "--is-shallow-repository"], 64)
            .map_err(|failure| {
                CoreError::Input(format!("cannot read Git shallow state: {}", failure.code()))
            })?
            .and_then(|value| text(&value).ok())
            .is_some_and(|value| value == "true")
        {
            return Err(CoreError::Input(
                "shallow Git history is unsupported because parent evidence is incomplete"
                    .to_string(),
            ));
        }
        let partial_extension = optional_output(
            &runner,
            &["config", "--local", "--get", "extensions.partialClone"],
            4096,
        )
        .map_err(|failure| {
            CoreError::Input(format!(
                "cannot read Git partial-clone state: {}",
                failure.code()
            ))
        })?;
        let promisor_remote = optional_output(
            &runner,
            &[
                "config",
                "--local",
                "--get-regexp",
                r"^remote\..*\.promisor$",
            ],
            4096,
        )
        .map_err(|failure| {
            CoreError::Input(format!(
                "cannot read Git promisor state: {}",
                failure.code()
            ))
        })?;
        if partial_extension.is_some_and(|value| !value.is_empty())
            || promisor_remote.is_some_and(|value| {
                String::from_utf8_lossy(&value)
                    .lines()
                    .any(|line| line.split_whitespace().last() == Some("true"))
            })
        {
            return Err(CoreError::Input(
                "partial/promisor Git clones are unsupported because objects may be absent"
                    .to_string(),
            ));
        }
        if let Some(output) = optional_output(
            &runner,
            &["rev-parse", "--git-path", "objects/info/alternates"],
            8192,
        )
        .map_err(|failure| {
            CoreError::Input(format!(
                "cannot inspect Git object paths: {}",
                failure.code()
            ))
        })? {
            if let Ok(path) = text(&output) {
                let path = PathBuf::from(path);
                let path = if path.is_absolute() {
                    path
                } else {
                    repo.join(path)
                };
                if std::fs::metadata(&path)
                    .map(|metadata| metadata.len() > 0)
                    .unwrap_or(false)
                {
                    return Err(CoreError::Input(
                        "Git object alternates are unsupported because they can escape the approved repository boundary"
                            .to_string(),
                    ));
                }
            }
        }

        for reference in &options.refs {
            if !valid_ref(reference) {
                return Err(CoreError::Input(
                    "invalid Git reference selector; ranges and revision operators are not accepted"
                        .to_string(),
                ));
            }
        }
        let mut resolved_refs = Vec::new();
        for reference in &options.refs {
            let expression = format!("{reference}^{{commit}}");
            let output = runner
                .run(["rev-parse", "--verify", expression.as_str()], 16 * 1024)
                .map_err(|failure| {
                    CoreError::Input(format!(
                        "Git reference cannot be resolved: {}",
                        failure.code()
                    ))
                })?;
            let oid = text(&output)
                .map_err(|_| CoreError::Input("Git reference resolved to non-UTF-8".to_string()))?;
            if !valid_oid(&oid) {
                return Err(CoreError::Input(
                    "Git reference did not resolve to a commit object".to_string(),
                ));
            }
            resolved_refs.push(oid);
        }
        let empty = optional_output(&runner, &["rev-parse", "--verify", "HEAD"], 16 * 1024)
            .map_err(|failure| {
                CoreError::Input(format!("cannot inspect Git HEAD: {}", failure.code()))
            })?
            .is_none();
        let source_id = source_id_for(&repository_id);
        Ok(Self {
            repo,
            source_id,
            repository_id,
            refs: options.refs.clone(),
            resolved_refs,
            max_commits: options.max_commits,
            max_units: options.max_units,
            io: options.io,
            history_mode: options.history_mode,
            context_lines: options.context_lines,
            profiler: options.profiler.clone(),
            batch: Arc::new(Mutex::new(None)),
            empty: empty && options.refs.is_empty(),
        })
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn repository_id(&self) -> &str {
        &self.repository_id
    }

    pub fn discover_until(&self, deadline: Instant) -> Discovery {
        let mut discovery = Discovery {
            root: self.repo.clone(),
            source_adapter_id: GIT_ADAPTER_ID.to_string(),
            source_adapter_version: env!("CARGO_PKG_VERSION").to_string(),
            git_history: Some(GitHistoryInfo {
                repository_path: self.repo.clone(),
                repository_id: self.repository_id.clone(),
                refs: if self.refs.is_empty() {
                    vec!["--all".to_string()]
                } else {
                    self.refs.clone()
                },
                scope: if self.refs.is_empty() {
                    "all-reachable-refs-and-head".to_string()
                } else {
                    "selected-refs".to_string()
                },
                history_mode: self.history_mode.as_str().to_string(),
                git_io: self.io.as_str().to_string(),
                context_lines: self.context_lines,
                ..GitHistoryInfo::default()
            }),
            git_source: Some(self.clone()),
            ..Discovery::default()
        };
        if self.empty {
            discovery.warnings.push("EMPTY_GIT_HISTORY".to_string());
            return discovery;
        }
        if let Err(failure) = self.discover_inner(deadline, &mut discovery) {
            discovery.aborted = true;
            discovery.fatal_errors.push(failure.code().to_string());
        }
        discovery
    }

    fn discover_inner(
        &self,
        deadline: Instant,
        discovery: &mut Discovery,
    ) -> Result<(), GitFailure> {
        let runner = GitRunner::with_profile(
            &self.repo,
            deadline,
            self.profiler.clone(),
            ProfileKind::Wall,
        );
        let mut rev_args: Vec<OsString> = vec![
            OsString::from("rev-list"),
            OsString::from("--parents"),
            OsString::from("--topo-order"),
            OsString::from("--reverse"),
        ];
        if self.refs.is_empty() {
            rev_args.push(OsString::from("--all"));
            rev_args.push(OsString::from("HEAD"));
        } else {
            for oid in &self.resolved_refs {
                rev_args.push(OsString::from(oid));
            }
        }
        let output = runner.run_named(
            "enumerate",
            rev_args,
            self.max_commits.saturating_mul(128) + 4096,
        )?;
        let output_text = std::str::from_utf8(&output).map_err(|_| GitFailure::InvalidData)?;
        let commits: Vec<Vec<&str>> = output_text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| line.split_whitespace().collect())
            .collect();
        if commits.len() > self.max_commits {
            return Err(GitFailure::CommitLimit);
        }
        let commit_count = commits.len();
        if let Some(history) = &mut discovery.git_history {
            history.commits = commit_count;
        }
        if commit_count == 0 {
            discovery.warnings.push("EMPTY_GIT_HISTORY".to_string());
            return Ok(());
        }

        let mut seen_units = BTreeSet::new();
        for fields in commits {
            let Some(commit) = fields.first().filter(|value| valid_oid(value)) else {
                return Err(GitFailure::InvalidData);
            };
            if fields.iter().skip(1).any(|value| !valid_oid(value)) {
                return Err(GitFailure::InvalidData);
            }
            let parent = fields.get(1).copied();
            let mut diff_args: Vec<OsString> = vec![
                OsString::from("diff-tree"),
                OsString::from("--no-commit-id"),
                OsString::from("--no-renames"),
                OsString::from("--no-ext-diff"),
                OsString::from("--no-textconv"),
                OsString::from("-r"),
                OsString::from("--raw"),
                OsString::from("-z"),
            ];
            if parent.is_none() {
                diff_args.push(OsString::from("--root"));
            }
            if let Some(parent) = parent {
                diff_args.push(OsString::from(parent));
            }
            diff_args.push(OsString::from(commit));
            let diff = runner.run_named("deltas", diff_args, 32 * 1024 * 1024)?;
            let mut records = diff.split(|byte| *byte == 0);
            loop {
                let Some(metadata) = records.next() else {
                    break;
                };
                if metadata.is_empty() {
                    continue;
                }
                let path = records.next().ok_or(GitFailure::InvalidData)?;
                if !metadata.starts_with(b":") {
                    return Err(GitFailure::InvalidData);
                }
                let fields = std::str::from_utf8(metadata)
                    .map_err(|_| GitFailure::InvalidData)?
                    .trim_start_matches(':')
                    .split(' ')
                    .collect::<Vec<_>>();
                if fields.len() < 5 {
                    return Err(GitFailure::InvalidData);
                }
                let status = fields[4];
                let old_mode = fields[0];
                let new_mode = fields[1];
                let new_oid = fields[3];
                if let Some(history) = &mut discovery.git_history {
                    history.changed_paths += 1;
                }
                if status.starts_with('D') {
                    if let Some(history) = &mut discovery.git_history {
                        history.deleted_paths += 1;
                    }
                    // A deletion is not a new content revision. The parent
                    // commit is also traversed, so credentials that only existed
                    // before removal are still inspected there.
                    continue;
                }
                if status.starts_with('U') {
                    return Err(GitFailure::InvalidData);
                }
                let path = std::str::from_utf8(path).map_err(|_| GitFailure::InvalidData)?;
                if path.is_empty()
                    || path.starts_with('/')
                    || path
                        .split('/')
                        .any(|part| part.is_empty() || part == "." || part == "..")
                {
                    return Err(GitFailure::InvalidData);
                }
                let locator_text = format!("commit/{commit}/{path}");
                let Ok(locator) = crate::path::canonical_locator(&locator_text) else {
                    return Err(GitFailure::InvalidData);
                };
                let mode = new_mode;
                let blob_oid = new_oid;
                if mode == "160000" || mode == "040000" {
                    push_skipped_git_unit(
                        discovery,
                        commit,
                        locator,
                        "GIT_SUBMODULE_NOT_TRAVERSED",
                        &mut seen_units,
                        self.max_units,
                    )?;
                    continue;
                }
                if mode == "120000" {
                    push_skipped_git_unit(
                        discovery,
                        commit,
                        locator,
                        "GIT_SYMLINK_NOT_FOLLOWED",
                        &mut seen_units,
                        self.max_units,
                    )?;
                    continue;
                }
                if !valid_oid(blob_oid) || old_mode.is_empty() {
                    return Err(GitFailure::InvalidData);
                }
                let git_diff = if self.history_mode == GitHistoryMode::Diff {
                    match diff_for_unit(&runner, commit, parent, path, self.context_lines)? {
                        DiffAvailability::Text(spec) => Some(spec),
                        DiffAvailability::Binary => {
                            push_skipped_git_unit(
                                discovery,
                                commit,
                                locator,
                                "GIT_DIFF_BINARY_UNSUPPORTED",
                                &mut seen_units,
                                self.max_units,
                            )?;
                            continue;
                        }
                        DiffAvailability::NoIntroduced => {
                            // Deletion-only and mode-only changes introduce no
                            // content revision to scan; they are not a coverage
                            // gap in diff mode.
                            continue;
                        }
                    }
                } else {
                    None
                };
                let key = (commit.to_string(), locator.to_string());
                if !seen_units.insert(key) {
                    continue;
                }
                if discovery.units.len() >= self.max_units {
                    return Err(GitFailure::UnitLimit);
                }
                let unit_id = crate::path::unit_id(&self.source_id, locator)
                    .map_err(|_| GitFailure::InvalidData)?;
                discovery.units.push(crate::input::DiscoveredUnit {
                    unit_id,
                    source_id: self.source_id.clone(),
                    source_kind: GIT_SOURCE_KIND.to_string(),
                    locator: locator.to_string(),
                    path: PathBuf::new(),
                    size: 0,
                    modified: None,
                    required_scope: true,
                    scope: PreScanScope::Inspect,
                    block_matches: Vec::new(),
                    block_request_id: None,
                    git: Some(GitBlobRef {
                        commit: commit.to_string(),
                        blob_oid: blob_oid.to_string(),
                    }),
                    git_diff,
                });
                if let Some(history) = &mut discovery.git_history {
                    history.units_seen = discovery.units.len();
                }
            }
            if Instant::now() >= deadline {
                return Err(GitFailure::Timeout);
            }
        }
        discovery
            .units
            .sort_by(|left, right| left.unit_id.cmp(&right.unit_id));
        if let Some(history) = &mut discovery.git_history {
            history.units_seen = discovery.units.len();
        }
        Ok(())
    }

    pub fn read_blob(
        &self,
        oid: &str,
        max_bytes: u64,
        deadline: Instant,
    ) -> Result<Vec<u8>, GitReadError> {
        if !valid_oid(oid) {
            return Err(GitReadError::ObjectUnavailable);
        }
        let limit = usize::try_from(max_bytes)
            .unwrap_or(usize::MAX)
            .saturating_add(1);
        if self.io == GitIoMode::Batch {
            return self.read_blob_batch(oid, max_bytes, deadline);
        }
        let runner = GitRunner::with_profile(
            &self.repo,
            deadline,
            self.profiler.clone(),
            ProfileKind::Worker,
        );
        match runner.run_named("acquire.process", ["cat-file", "blob", oid], limit) {
            Ok(bytes) if bytes.len() as u64 > max_bytes => Err(GitReadError::TooLarge),
            Ok(bytes) => Ok(bytes),
            Err(GitFailure::Timeout) => Err(GitReadError::Timeout),
            Err(GitFailure::OutputLimit) => Err(GitReadError::TooLarge),
            Err(_) => Err(GitReadError::ObjectUnavailable),
        }
    }

    fn read_blob_batch(
        &self,
        oid: &str,
        max_bytes: u64,
        deadline: Instant,
    ) -> Result<Vec<u8>, GitReadError> {
        if !valid_oid(oid) {
            return Err(GitReadError::ObjectUnavailable);
        }
        let mut guard = self
            .batch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.is_none() {
            *guard = Some(
                BatchReader::start(&self.repo, deadline, self.profiler.clone())
                    .map_err(map_batch_error)?,
            );
        }
        let result = guard
            .as_ref()
            .expect("batch reader initialized")
            .read_blob(oid, max_bytes, deadline)
            .map_err(map_batch_error);
        if result.is_err() {
            *guard = None;
        }
        result
    }
}

fn map_batch_error(error: BatchError) -> GitReadError {
    match error {
        BatchError::Timeout => GitReadError::Timeout,
        BatchError::TooLarge => GitReadError::TooLarge,
        BatchError::ObjectUnavailable | BatchError::Protocol => GitReadError::ObjectUnavailable,
    }
}

fn push_skipped_git_unit(
    discovery: &mut Discovery,
    commit: &str,
    locator: &str,
    reason: &'static str,
    seen: &mut BTreeSet<(String, String)>,
    max_units: usize,
) -> Result<(), GitFailure> {
    if !seen.insert((commit.to_string(), locator.to_string())) {
        return Ok(());
    }
    if discovery.units.len() >= max_units {
        return Err(GitFailure::UnitLimit);
    }
    let source_id = discovery
        .git_history
        .as_ref()
        .map(|history| source_id_for(&history.repository_id))
        .ok_or(GitFailure::InvalidData)?;
    let unit_id = crate::path::unit_id(&source_id, locator).map_err(|_| GitFailure::InvalidData)?;
    discovery.units.push(crate::input::DiscoveredUnit {
        unit_id,
        source_id,
        source_kind: GIT_SOURCE_KIND.to_string(),
        locator: locator.to_string(),
        path: PathBuf::new(),
        size: 0,
        modified: None,
        required_scope: true,
        scope: PreScanScope::Skipped(reason),
        block_matches: Vec::new(),
        block_request_id: None,
        git: None,
        git_diff: None,
    });
    Ok(())
}

fn repository_id(git_dir: &Path) -> String {
    sha256_hex(git_dir.to_string_lossy().as_bytes())
}

fn source_id_for(repository_id: &str) -> String {
    let digest = repository_id
        .strip_prefix("sha256:")
        .unwrap_or(repository_id);
    format!("local-git-history:{}", &digest[..digest.len().min(16)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_parser_tracks_introduced_and_context_lines() {
        let diff = b"\
diff --git a/app.env b/app.env\n\
--- a/app.env\n\
+++ b/app.env\n\
@@ -1,2 +1,3 @@\n\
-API_KEY=old\n\
+API_KEY=new\n\
 \x20DB_PASSWORD=unchanged\n\
+TOKEN=added\n";
        let parsed = parse_diff(diff).unwrap();
        let DiffAvailability::Text(spec) = parsed else {
            panic!("expected text diff");
        };
        assert_eq!(spec.introduced_lines, vec![1, 3]);
        assert_eq!(spec.scan_line_ranges, vec![(1, 3)]);
    }

    #[test]
    fn diff_parser_handles_added_lines_starting_with_plus() {
        let diff = b"\
@@ -0,0 +1,1 @@\n\
+++this is a literal added line\n";
        let parsed = parse_diff(diff).unwrap();
        let DiffAvailability::Text(spec) = parsed else {
            panic!("expected text diff");
        };
        assert_eq!(spec.introduced_lines, vec![1]);
    }

    #[test]
    fn diff_parser_identifies_binary_and_deletion_only_changes() {
        let binary = b"diff --git a/x b/x\nBinary files a/x and b/x differ\n";
        assert!(matches!(parse_diff(binary), Ok(DiffAvailability::Binary)));
        let deletion = b"@@ -1,1 +0,0 @@\n-secret\n";
        assert!(matches!(
            parse_diff(deletion),
            Ok(DiffAvailability::NoIntroduced)
        ));
    }

    #[test]
    fn hunk_header_parser_supports_implicit_counts() {
        assert_eq!(parse_hunk_header("@@ -1 +1 @@"), Some((1, 1)));
        assert_eq!(parse_hunk_header("@@ -0,0 +1,3 @@"), Some((1, 3)));
        assert_eq!(parse_hunk_header("@@ -4,2 +8,0 @@"), Some((8, 0)));
    }
}
