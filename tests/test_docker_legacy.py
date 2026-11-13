"""Run the vendored legacy Docker evidence self-tests under normal discovery."""

from __future__ import annotations

from harness.docker.test_evidence import CoverageAndAggregationTests, FindingAssertionTests

__all__ = ["CoverageAndAggregationTests", "FindingAssertionTests"]
