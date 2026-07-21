"""Tacua pilot backend.

This package intentionally uses only the Python standard library.  It is a
non-production vertical slice for exercising Tacua's SDK-owned upload boundary.
"""

__version__ = "0.1.0"

CAPTURE_CONTRACT = "tacua.capture-upload-manifest@1.0.0"
DIAGNOSTIC_CONTRACT = "tacua.diagnostic-envelope@1.0.0"
PROCESSING_JOB_CONTRACT = "tacua.processing-job@1.0.0"

