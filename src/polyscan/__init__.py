"""
PolyScan - Image Polyglot Security Scanner
------------------------------------------
High-performance image polyglot scanner for detecting embedded executables,
scripts, and suspicious content in image files.

Author: petruknisme
"""

__version__ = "1.0.0"
__author__ = "petruknisme"
__email__ = "petruknisme@example.com"
__description__ = "High-performance image polyglot security scanner"

# Core functionality imports
from .core import (
    SeverityLevel,
    DetectionResult,
    AnalysisResult, 
    analyze_image_file,
    collect_target_files,
    export_results_json,
)

__all__ = [
    "SeverityLevel",
    "DetectionResult", 
    "AnalysisResult",
    "analyze_image_file",
    "collect_target_files",
    "export_results_json",
    "__version__",
    "__author__",
    "__email__",
    "__description__",
]