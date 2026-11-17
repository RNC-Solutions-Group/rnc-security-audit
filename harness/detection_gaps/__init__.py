"""Target-level detection-gap analysis for retained current-scoring reports."""

from .analysis import analyse_scanner, build_cross_scanner
from .inputs import (
    InputSelectionError,
    ReportSelection,
    build_lock,
    select_report,
    write_lock,
)
from .reporting import generate_reports
from .sources import (
    DetectionGapError,
    SourceResolver,
    load_canonical_targets,
    load_scanner_evidence,
)

__all__ = [
    "DetectionGapError",
    "InputSelectionError",
    "ReportSelection",
    "SourceResolver",
    "analyse_scanner",
    "build_cross_scanner",
    "build_lock",
    "generate_reports",
    "load_canonical_targets",
    "load_scanner_evidence",
    "select_report",
    "write_lock",
]
