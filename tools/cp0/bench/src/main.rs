// CP0 representative benchmark scanner. Disposable, not the production engine.
// Mirrors the Go implementation: same rule file, matching semantics, candidate
// validation, stream overlap, deterministic checksum and failure behavior.
use regex::bytes::Regex;
use std::collections::{HashSet, VecDeque};
use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process;
use std::sync::{Arc, Mutex};

struct Rule {
    id: String,
    capture: usize,
    family: String,
    re: Regex,
}

struct FileResult {
    keys: Vec<String>,
}

fn load_rules(path: &str, limit: usize) -> Result<Vec<Rule>, String> {
    let text = fs::read_to_string(path).map_err(|err| format!("cannot read rules: {err}"))?;
    let mut rules = Vec::new();
    for line in text.lines() {
        let line = line.trim_start_matches('\u{feff}');
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(4, '\t').collect();
        if parts.len() != 4 {
            return Err(format!("invalid rule line: {line:?}"));
        }
        let capture: usize = parts[1]
            .parse()
            .map_err(|_| format!("invalid capture group in {line:?}"))?;
        if capture > 1 {
            return Err(format!("invalid capture group in {line:?}"));
        }
        let re = Regex::new(parts[3]).map_err(|err| format!("invalid regex for {}: {err}", parts[0]))?;
        rules.push(Rule {
            id: parts[0].to_string(),
            capture,
            family: parts[2].to_string(),
            re,
        });
        if limit > 0 && rules.len() >= limit {
            break;
        }
    }
    if rules.is_empty() {
        return Err("no rules loaded".to_string());
    }
    Ok(rules)
}

fn valid_marker(value: &[u8], family: &str) -> bool {
    if value.len() < 16 || value.len() > 96 {
        return false;
    }
    let prefix = format!("RNC_SYNTH_KEY_{family}_");
    let text = match std::str::from_utf8(value) {
        Ok(text) => text,
        Err(_) => return false,
    };
    if !text.starts_with(&prefix) {
        return false;
    }
    if !value.iter().all(|byte| {
        byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_'
    }) {
        return false;
    }
    let suffix = &text[prefix.len()..];
    if suffix.len() < 4 || suffix.ends_with('_') || suffix.contains("DECOY") || suffix.contains("FAKE") {
        return false;
    }
    true
}

fn scan_window(
    data: &[u8],
    absolute_offset: usize,
    rules: &[Rule],
    path: &str,
    seen: &mut HashSet<String>,
) {
    for rule in rules {
        for captures in rule.re.captures_iter(data) {
            let matched = if rule.capture == 0 {
                captures.get(0)
            } else {
                captures.get(1)
            };
            let matched = match matched {
                Some(value) => value,
                None => continue,
            };
            let start = matched.start();
            let end = matched.end();
            if end <= start || !valid_marker(&data[start..end], &rule.family) {
                continue;
            }
            let key = format!(
                "{}\t{}\t{}\t{}\n",
                rule.id,
                path,
                start + absolute_offset,
                end + absolute_offset
            );
            seen.insert(key);
        }
    }
}

fn scan_whole(data: &[u8], rules: &[Rule], path: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    scan_window(data, 0, rules, path, &mut seen);
    seen.into_iter().collect()
}

fn scan_stream(path: &Path, rules: &[Rule], rel: &str) -> Result<Vec<String>, String> {
    let mut handle = File::open(path).map_err(|err| format!("cannot open {}: {err}", path.display()))?;
    const CHUNK: usize = 256 * 1024;
    const OVERLAP: usize = 8192;
    let mut buffer = vec![0_u8; CHUNK];
    let mut carry: Vec<u8> = Vec::with_capacity(OVERLAP);
    let mut base = 0_usize;
    let mut seen = HashSet::new();
    loop {
        let read = handle
            .read(&mut buffer)
            .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
        if read == 0 {
            break;
        }
        let mut window = Vec::with_capacity(carry.len() + read);
        window.extend_from_slice(&carry);
        window.extend_from_slice(&buffer[..read]);
        let offset = base.saturating_sub(carry.len());
        scan_window(&window, offset, rules, rel, &mut seen);
        base += read;
        if window.len() > OVERLAP {
            carry = window[window.len() - OVERLAP..].to_vec();
        } else {
            carry = window;
        }
    }
    Ok(seen.into_iter().collect())
}

fn read_manifest(path: &str) -> Result<Vec<String>, String> {
    let text = fs::read_to_string(path).map_err(|err| format!("cannot read manifest: {err}"))?;
    let files: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.replace('\\', "/"))
        .collect();
    if files.is_empty() {
        return Err("manifest contains no files".to_string());
    }
    Ok(files)
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let candidate = Path::new(relative);
    if candidate.is_absolute()
        || candidate.components().any(|component| {
            matches!(component, Component::ParentDir | Component::RootDir | Component::Prefix(_))
        })
    {
        return Err(format!("manifest path escapes corpus root: {relative}"));
    }
    let joined = root.join(candidate);
    let root_abs = fs::canonicalize(root).map_err(|err| format!("cannot resolve corpus root: {err}"))?;
    let joined_abs = fs::canonicalize(&joined).map_err(|err| format!("cannot resolve {relative}: {err}"))?;
    if !joined_abs.starts_with(&root_abs) {
        return Err(format!("manifest path escapes corpus root: {relative}"));
    }
    Ok(joined_abs)
}

fn process(
    files: &[String],
    root: &Path,
    rules: &[Rule],
    mode: &str,
    threads: usize,
) -> Result<Vec<String>, String> {
    let jobs = Arc::new(Mutex::new(VecDeque::from_iter(0..files.len())));
    let results: Arc<Mutex<Vec<Option<FileResult>>>> = Arc::new(Mutex::new(
        (0..files.len()).map(|_| None).collect(),
    ));
    let error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let workers = threads.min(files.len()).max(1);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let jobs = Arc::clone(&jobs);
            let results = Arc::clone(&results);
            let error = Arc::clone(&error);
            scope.spawn(move || loop {
                let index = {
                    let mut queue = jobs.lock().unwrap();
                    queue.pop_front()
                };
                let index = match index {
                    Some(value) => value,
                    None => break,
                };
                let relative = &files[index];
                let outcome = (|| -> Result<Vec<String>, String> {
                    let full = safe_join(root, relative)?;
                    if mode == "stream" {
                        scan_stream(&full, rules, relative)
                    } else {
                        let data = fs::read(&full)
                            .map_err(|err| format!("cannot read {}: {err}", full.display()))?;
                        Ok(scan_whole(&data, rules, relative))
                    }
                })();
                match outcome {
                    Ok(keys) => {
                        results.lock().unwrap()[index] = Some(FileResult { keys });
                    }
                    Err(message) => {
                        let mut slot = error.lock().unwrap();
                        if slot.is_none() {
                            *slot = Some(message);
                        }
                        break;
                    }
                }
            });
        }
    });
    if let Some(message) = error.lock().unwrap().clone() {
        return Err(message);
    }
    let mut keys = Vec::new();
    for result in results.lock().unwrap().iter() {
        if let Some(value) = result {
            keys.extend(value.keys.iter().cloned());
        }
    }
    Ok(keys)
}

fn fnv(keys: &[String]) -> u64 {
    let mut hash = 14695981039346656037_u64;
    for key in keys {
        for value in key.as_bytes() {
            hash ^= u64::from(*value);
            hash = hash.wrapping_mul(1099511628211);
        }
    }
    hash
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 11 {
        eprintln!("usage: scanner --corpus DIR --manifest FILE --rules FILE --mode whole|stream --threads N");
        process::exit(64);
    }
    let mut corpus = String::new();
    let mut manifest = String::new();
    let mut rules_path = String::new();
    let mut mode = String::new();
    let mut threads = 1_usize;
    let mut index = 1;
    while index + 1 < args.len() {
        match args[index].as_str() {
            "--corpus" => corpus = args[index + 1].clone(),
            "--manifest" => manifest = args[index + 1].clone(),
            "--rules" => rules_path = args[index + 1].clone(),
            "--mode" => mode = args[index + 1].clone(),
            "--threads" => {
                threads = match args[index + 1].parse() {
                    Ok(value) if value > 0 => value,
                    _ => {
                        eprintln!("threads must be a positive integer");
                        process::exit(64);
                    }
                }
            }
            other => {
                eprintln!("unknown argument {other}");
                process::exit(64);
            }
        }
        index += 2;
    }
    if corpus.is_empty() || manifest.is_empty() || rules_path.is_empty() || (mode != "whole" && mode != "stream") {
        eprintln!("missing required argument or invalid mode");
        process::exit(64);
    }
    let limit = if Path::new(&rules_path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.contains("basic"))
        .unwrap_or(false)
    {
        8
    } else {
        0
    };
    let rules = match load_rules(&rules_path, limit) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            process::exit(1);
        }
    };
    let files = match read_manifest(&manifest) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            process::exit(1);
        }
    };
    let mut keys = match process(&files, Path::new(&corpus), &rules, &mode, threads) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            process::exit(1);
        }
    };
    keys.sort();
    println!(
        "count={} checksum={:016x} rules={} mode={} threads={}",
        keys.len(),
        fnv(&keys),
        rules.len(),
        mode,
        threads
    );
    let _ = std::io::stdout().flush();
}
