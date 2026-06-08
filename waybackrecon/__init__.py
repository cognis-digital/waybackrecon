"""WAYBACKRECON - mine archived URLs, params, and endpoints from a Wayback/CDX export.

Defensive historical attack-surface analysis over artifacts you own/are authorized
to review. No network access, no attack capability -- pure offline triage.
"""
from .core import (
    Finding,
    ReconResult,
    analyze,
    parse_cdx_lines,
    severity_rank,
)

TOOL_NAME = "waybackrecon"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "ReconResult",
    "analyze",
    "parse_cdx_lines",
    "severity_rank",
]
