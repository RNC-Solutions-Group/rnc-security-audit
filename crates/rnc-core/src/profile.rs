//! Bounded, opt-in execution profiling.
//!
//! Wall-clock phases and accumulated worker phases are deliberately separate.
//! A worker-phase total is never elapsed time because multiple workers may be
//! running concurrently.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub const PROFILE_SCHEMA_VERSION: &str = "1";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PhaseStats {
    /// Wall time for main-thread phases; accumulated time for worker phases.
    pub ns: u64,
    pub exclusive_ns: u64,
    pub count: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileSettings {
    pub requested: BTreeMap<String, String>,
    pub effective: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileDocument {
    pub schema_version: String,
    pub engine_version: String,
    pub run_id: String,
    pub settings: ProfileSettings,
    pub phases: BTreeMap<String, PhaseStats>,
    pub worker_phases: BTreeMap<String, PhaseStats>,
    pub counters: BTreeMap<String, u64>,
}

/// Parent relationships used only to calculate exclusive wall time.
///
/// Worker phases have no parent graph; they are accumulated operation time.
const WALL_PARENTS: &[(&str, &str)] = &[
    ("startup.cli", "execution"),
    ("startup.config", "execution"),
    ("rules.load", "execution"),
    ("rules.plan", "execution"),
    ("discovery.filesystem", "discovery"),
    ("discovery.git", "discovery"),
    ("git.open", "discovery.git"),
    ("git.enumerate", "discovery.git"),
    ("git.deltas", "discovery.git"),
    ("git.diff", "discovery.git"),
    ("git.command", "discovery.git"),
    ("scan", "execution"),
    ("reporting", "execution"),
    ("discovery", "execution"),
];

#[derive(Debug)]
pub struct Profiler {
    start: Instant,
    phases: Mutex<BTreeMap<String, PhaseStats>>,
    worker_phases: Mutex<BTreeMap<String, PhaseStats>>,
    counters: Mutex<BTreeMap<String, u64>>,
    requested: Mutex<BTreeMap<String, String>>,
    effective: Mutex<BTreeMap<String, String>>,
}

impl Profiler {
    pub fn new() -> Self {
        Self::from_start(Instant::now())
    }

    pub fn from_start(start: Instant) -> Self {
        Self {
            start,
            phases: Mutex::new(BTreeMap::new()),
            worker_phases: Mutex::new(BTreeMap::new()),
            counters: Mutex::new(BTreeMap::new()),
            requested: Mutex::new(BTreeMap::new()),
            effective: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn started(&self) -> Instant {
        self.start
    }

    pub fn record_wall(&self, name: &str, started: Instant) {
        self.record_wall_duration(name, started.elapsed(), 0, 1);
    }

    pub fn record_wall_bytes(&self, name: &str, started: Instant, bytes: u64, count: u64) {
        self.record_wall_duration(name, started.elapsed(), bytes, count);
    }

    pub fn record_wall_duration(&self, name: &str, duration: Duration, bytes: u64, count: u64) {
        add_phase(&self.phases, name, duration, bytes, count);
    }

    pub fn record_worker(&self, name: &str, duration: Duration, bytes: u64, count: u64) {
        add_phase(&self.worker_phases, name, duration, bytes, count);
    }

    pub fn add_counter(&self, name: &str, value: u64) {
        let mut counters = lock(&self.counters);
        let entry = counters.entry(name.to_string()).or_insert(0);
        *entry = entry.saturating_add(value);
    }

    pub fn set_requested(&self, name: &str, value: impl Into<String>) {
        lock(&self.requested).insert(name.to_string(), value.into());
    }

    pub fn set_effective(&self, name: &str, value: impl Into<String>) {
        lock(&self.effective).insert(name.to_string(), value.into());
    }

    pub fn finish(&self, run_id: &str) -> ProfileDocument {
        let total = self.start.elapsed();
        self.record_wall_duration("execution", total, 0, 1);
        let phases = lock(&self.phases).clone();
        let mut worker_phases = lock(&self.worker_phases).clone();
        for stats in worker_phases.values_mut() {
            stats.exclusive_ns = stats.ns;
        }
        let counters = lock(&self.counters).clone();
        let settings = ProfileSettings {
            requested: lock(&self.requested).clone(),
            effective: lock(&self.effective).clone(),
        };
        ProfileDocument {
            schema_version: PROFILE_SCHEMA_VERSION.to_string(),
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            run_id: run_id.to_string(),
            settings,
            phases: with_exclusive(phases),
            worker_phases,
            counters,
        }
    }
}

impl Default for Profiler {
    fn default() -> Self {
        Self::new()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn add_phase(
    phases: &Mutex<BTreeMap<String, PhaseStats>>,
    name: &str,
    duration: Duration,
    bytes: u64,
    count: u64,
) {
    let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
    let mut phases = lock(phases);
    let entry = phases.entry(name.to_string()).or_default();
    entry.ns = entry.ns.saturating_add(nanos);
    entry.count = entry.count.saturating_add(count);
    entry.bytes = entry.bytes.saturating_add(bytes);
}

fn with_exclusive(mut phases: BTreeMap<String, PhaseStats>) -> BTreeMap<String, PhaseStats> {
    for stats in phases.values_mut() {
        stats.exclusive_ns = stats.ns;
    }
    for (child, parent) in WALL_PARENTS {
        let Some(child_ns) = phases.get(*child).map(|stats| stats.ns) else {
            continue;
        };
        if let Some(parent_stats) = phases.get_mut(*parent) {
            parent_stats.exclusive_ns = parent_stats.exclusive_ns.saturating_sub(child_ns);
        }
    }
    phases
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_separates_wall_and_worker_time() {
        let profiler = Profiler::new();
        let start = Instant::now();
        profiler.record_wall_duration("startup", Duration::from_millis(10), 0, 1);
        profiler.record_wall_duration("startup.cli", Duration::from_millis(4), 0, 1);
        profiler.record_worker("validation", Duration::from_millis(7), 12, 3);
        profiler.add_counter("candidates", 2);
        profiler.set_requested("workers", "auto");
        profiler.set_effective("workers", "4");
        let document = profiler.finish("test-run");
        assert_eq!(document.schema_version, "1");
        assert_eq!(document.settings.requested["workers"], "auto");
        assert_eq!(document.settings.effective["workers"], "4");
        assert_eq!(document.counters["candidates"], 2);
        assert_eq!(document.phases["startup.cli"].exclusive_ns, 4_000_000);
        assert!(document.phases["execution"].ns > 0);
        assert_eq!(document.worker_phases["validation"].ns, 7_000_000);
        assert!(document.phases["execution"].ns > 0);
        assert!(start.elapsed().as_nanos() > 0);
    }
}
