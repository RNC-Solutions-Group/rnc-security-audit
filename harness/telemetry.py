"""Best-effort execution telemetry independent of scanner parsing.

Native process CPU/peak-memory sampling uses OS facilities where available. For
Docker executions, the container name is sampled with ``docker stats``. Missing
facilities produce explicit ``NOT_AVAILABLE`` reasons rather than zero values.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

IS_WINDOWS = sys.platform.startswith("win")


@dataclass
class Telemetry:
    cpu_user_seconds: float | None = None
    cpu_system_seconds: float | None = None
    cpu_total_seconds: float | None = None
    peak_memory_bytes: int | None = None
    cpu_utilization_percent: float | None = None
    sample_count: int = 0
    method: str = "unavailable"
    unavailable_reason: str | None = None
    samples: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "cpu_user_seconds": (
                round(self.cpu_user_seconds, 6)
                if self.cpu_user_seconds is not None
                else None
            ),
            "cpu_system_seconds": (
                round(self.cpu_system_seconds, 6)
                if self.cpu_system_seconds is not None
                else None
            ),
            "cpu_total_seconds": (
                round(self.cpu_total_seconds, 6)
                if self.cpu_total_seconds is not None
                else None
            ),
            "peak_memory_bytes": self.peak_memory_bytes,
            "cpu_utilization_percent": (
                round(self.cpu_utilization_percent, 3)
                if self.cpu_utilization_percent is not None
                else None
            ),
            "sample_count": self.sample_count,
            "method": self.method,
            "unavailable_reason": self.unavailable_reason,
        }


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class _ProcessMemoryCounters(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_uint32),
        ("PageFaultCount", ctypes.c_uint32),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def _filetime_seconds(value: _FileTime) -> float:
    return ((value.high << 32) | value.low) / 10_000_000.0


class ProcessSampler:
    """Sample one process or one named Docker container."""

    def __init__(self, pid: int, argv: list[str] | None = None):
        self.pid = pid
        self.argv = argv or []
        self.telemetry = Telemetry()
        self._stop = threading.Event()
        self._container = _docker_container_name(self.argv)
        if self._container:
            self.telemetry.method = "docker_stats"
        elif IS_WINDOWS:
            self.telemetry.method = "windows_process_times"
        elif sys.platform.startswith("linux"):
            self.telemetry.method = "linux_procfs"
        else:
            self.telemetry.method = "unavailable"
            self.telemetry.unavailable_reason = (
                "no portable CPU/memory sampler for this platform"
            )

    def sample_once(self) -> dict | None:
        if self._container:
            return self._sample_docker()
        if IS_WINDOWS:
            return self._sample_windows()
        if sys.platform.startswith("linux"):
            return self._sample_linux()
        return None

    def run(self, interval: float = 0.05) -> Telemetry:
        while not self._stop.wait(interval):
            self._sample_and_record()
        self._sample_and_record()
        return self.telemetry

    def stop(self) -> None:
        self._stop.set()

    def _sample_and_record(self) -> None:
        sample = self.sample_once()
        if not sample:
            return
        self.telemetry.sample_count += 1
        if self.telemetry.sample_count <= 200:
            self.telemetry.samples.append(sample)
        cpu = sample.get("cpu_total_seconds")
        memory = sample.get("peak_memory_bytes")
        if cpu is not None:
            self.telemetry.cpu_total_seconds = max(
                self.telemetry.cpu_total_seconds or 0.0, cpu
            )
            self.telemetry.cpu_user_seconds = max(
                self.telemetry.cpu_user_seconds or 0.0,
                sample.get("cpu_user_seconds") or 0.0,
            )
            self.telemetry.cpu_system_seconds = max(
                self.telemetry.cpu_system_seconds or 0.0,
                sample.get("cpu_system_seconds") or 0.0,
            )
        if memory is not None:
            self.telemetry.peak_memory_bytes = max(
                self.telemetry.peak_memory_bytes or 0, memory
            )
        if sample.get("cpu_percent") is not None:
            self.telemetry.cpu_utilization_percent = max(
                self.telemetry.cpu_utilization_percent or 0.0,
                sample["cpu_percent"],
            )

    def _sample_windows(self) -> dict | None:
        if not hasattr(ctypes, "windll"):
            return None
        kernel32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi
        handle = kernel32.OpenProcess(0x1000, False, self.pid)
        if not handle:
            self.telemetry.unavailable_reason = "OpenProcess failed"
            return None
        try:
            creation = _FileTime()
            exit_time = _FileTime()
            kernel = _FileTime()
            user = _FileTime()
            if not kernel32.GetProcessTimes(
                handle,
                ctypes.byref(creation),
                ctypes.byref(exit_time),
                ctypes.byref(kernel),
                ctypes.byref(user),
            ):
                self.telemetry.unavailable_reason = "GetProcessTimes failed"
                return None
            counters = _ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            peak = None
            if psapi.GetProcessMemoryInfo(
                handle, ctypes.byref(counters), counters.cb
            ):
                peak = int(counters.PeakWorkingSetSize)
            user_s = _filetime_seconds(user)
            kernel_s = _filetime_seconds(kernel)
            return {
                "cpu_user_seconds": user_s,
                "cpu_system_seconds": kernel_s,
                "cpu_total_seconds": user_s + kernel_s,
                "peak_memory_bytes": peak,
                "source": "windows_process_times",
            }
        finally:
            kernel32.CloseHandle(handle)

    def _sample_linux(self) -> dict | None:
        path = Path(f"/proc/{self.pid}/stat")
        try:
            fields = path.read_text(encoding="utf-8").split()
        except OSError:
            return None
        if len(fields) < 24:
            return None
        ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        page = os.sysconf("SC_PAGE_SIZE")
        user = int(fields[13]) / ticks
        system = int(fields[14]) / ticks
        rss = int(fields[23]) * page
        return {
            "cpu_user_seconds": user,
            "cpu_system_seconds": system,
            "cpu_total_seconds": user + system,
            "peak_memory_bytes": rss,
            "source": "linux_procfs",
        }

    def _sample_docker(self) -> dict | None:
        try:
            result = subprocess.run(
                [
                    "docker",
                    "stats",
                    "--no-stream",
                    "--format",
                    "{{json .}}",
                    self._container,
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0 or not result.stdout.strip():
            return None
        try:
            document = json.loads(result.stdout.strip().splitlines()[-1])
        except ValueError:
            return None
        mem = _parse_docker_memory(document.get("MemUsage", ""))
        cpu = _parse_percent(document.get("CPUPerc", ""))
        return {
            "cpu_percent": cpu if cpu else None,
            "peak_memory_bytes": mem if mem and mem > 0 else None,
            "source": "docker_stats",
        }


def _parse_percent(text: str) -> float | None:
    try:
        return float(text.strip().rstrip("%"))
    except (TypeError, ValueError):
        return None


def _parse_docker_memory(text: str) -> int | None:
    used = str(text).split("/")[0].strip()
    units = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "kB": 1000, "MB": 1000**2, "GB": 1000**3}
    for unit, multiplier in units.items():
        if used.endswith(unit):
            try:
                return int(float(used[: -len(unit)].strip()) * multiplier)
            except ValueError:
                return None
    return None


def _docker_container_name(argv: list[str]) -> str | None:
    if not argv or Path(str(argv[0])).name.lower() not in ("docker", "docker.exe"):
        return None
    try:
        index = argv.index("--name")
    except ValueError:
        return None
    return argv[index + 1] if index + 1 < len(argv) else None


def start_process_sampler(pid: int, argv: list[str]) -> tuple[ProcessSampler, threading.Thread]:
    sampler = ProcessSampler(pid, argv)
    thread = threading.Thread(target=sampler.run, daemon=True)
    thread.start()
    return sampler, thread


def host_metadata() -> dict:
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": platform.python_version(),
        "hostname_kind": "redacted",
        "cpu_count": os.cpu_count(),
        "capacity": host_capacity(),
    }


def host_capacity() -> dict:
    """Best-effort capacity/contention facts without a third-party dependency."""
    capacity: dict = {
        "cpu_count": os.cpu_count(),
        "memory_bytes": None,
        "disk": None,
        "load_average": None,
        "method": "stdlib",
    }
    try:
        usage = shutil.disk_usage(Path.cwd())
        capacity["disk"] = {
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "used_percent": round(100.0 * usage.used / usage.total, 2)
            if usage.total
            else None,
        }
    except OSError as exc:
        capacity["disk"] = {"available": False, "reason": str(exc)}
    if hasattr(os, "getloadavg"):
        try:
            capacity["load_average"] = [round(value, 3) for value in os.getloadavg()]
        except OSError:
            pass
    if IS_WINDOWS and hasattr(ctypes, "windll"):
        class _MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_uint32),
                ("dwMemoryLoad", ctypes.c_uint32),
                ("ullTotalPhys", ctypes.c_uint64),
                ("ullAvailPhys", ctypes.c_uint64),
                ("ullTotalPageFile", ctypes.c_uint64),
                ("ullAvailPageFile", ctypes.c_uint64),
                ("ullTotalVirtual", ctypes.c_uint64),
                ("ullAvailVirtual", ctypes.c_uint64),
                ("ullAvailExtendedVirtual", ctypes.c_uint64),
            ]
        status = _MemoryStatus()
        status.dwLength = ctypes.sizeof(status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            capacity["memory_bytes"] = int(status.ullTotalPhys)
            capacity["memory_available_bytes"] = int(status.ullAvailPhys)
            capacity["memory_load_percent"] = int(status.dwMemoryLoad)
    elif sys.platform.startswith("linux"):
        try:
            meminfo = Path("/proc/meminfo").read_text(encoding="utf-8")
            values = {}
            for line in meminfo.splitlines():
                key, _, raw = line.partition(":")
                if raw.strip().endswith("kB"):
                    values[key] = int(raw.split()[0]) * 1024
            capacity["memory_bytes"] = values.get("MemTotal")
            capacity["memory_available_bytes"] = values.get("MemAvailable")
            if values.get("MemTotal") and values.get("MemAvailable") is not None:
                capacity["memory_load_percent"] = round(
                    100.0 * (1 - values["MemAvailable"] / values["MemTotal"]), 2
                )
        except (OSError, ValueError):
            pass
    return capacity
