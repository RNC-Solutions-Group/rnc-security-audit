"""Target-level detection-gap analysis for retained current-scoring reports."""

from .analysis import analyse_scanner, build_cross_scanner
from .reporting import generate_reports
from .sources import (
    DetectionGapError,
    SourceResolver,
    load_canonical_targets,
    load_scanner_evidence,
)

__all__ = [
    "DetectionGapError",
    "SourceResolver",
    "analyse_scanner",
    "build_cross_scanner",
    "generate_reports",
    "load_canonical_targets",
    "load_scanner_evidence",
]
