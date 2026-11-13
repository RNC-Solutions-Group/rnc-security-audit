"""Harness-specific exceptions with stable CLI exit semantics."""

from __future__ import annotations


class HarnessError(Exception):
    """A controlled failure: reported to the user, never a scan result."""

    exit_code = 2


class ManifestError(HarnessError):
    """The dataset manifest is missing, malformed, or internally inconsistent."""


class DatasetError(HarnessError):
    """A pinned dataset is unavailable, unverified, or corrupted."""


class ExecutionError(HarnessError):
    """A scanner could not be invoked in a trustworthy way."""


class ReportError(HarnessError):
    """A scanner report could not be read or interpreted."""
