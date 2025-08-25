#!/usr/bin/env python3
"""
PolyScan - Image Polyglot Security Scanner
------------------------------------------
High-performance image polyglot scanner for detecting embedded executables,
scripts, and suspicious content in image files.

Author: petruknisme
"""

import sys
import os
import argparse
import mmap
import json
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Tuple, Optional, List, Dict, Iterator, Union, Any
from dataclasses import dataclass, asdict
from enum import Enum
import time
import psutil
from collections import defaultdict
import hashlib

# Color support for better output readability
try:
    from colorama import init, Fore, Back, Style
    init()
    HAS_COLOR = True
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = RESET = ''
    class Back:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = RESET = ''  
    class Style:
        DIM = NORMAL = BRIGHT = RESET_ALL = ''
    HAS_COLOR = False

class SeverityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class DetectionResult:
    offset: int
    description: str
    marker_type: str
    severity: SeverityLevel
    file_extension: str = ""
    
@dataclass
class AnalysisResult:
    file_path: str
    size_bytes: int
    format: Optional[str]
    end_marker_offset: Optional[int]
    trailing_bytes: int
    has_trailing_data: bool
    embedded_detections: List[DetectionResult]
    text_detections: List[str]
    notes: List[str]
    carved_files: List[str]
    processing_method: str
    file_hash: Optional[str] = None
    processing_time: float = 0.0

# Image format signatures
IMAGE_SIGNATURES = {
    "png": b"\x89PNG\r\n\x1a\n",
    "jpg": b"\xff\xd8", 
    "jpeg": b"\xff\xd8",
    "gif": b"GIF8",
    "bmp": b"BM",
    "webp": b"RIFF",  # Followed by 'WEBP' at offset 8
    "tiff": b"II*\x00",  # Little endian TIFF
    "tiff_be": b"MM\x00*",  # Big endian TIFF
    "ico": b"\x00\x00\x01\x00",
}

# End-of-image markers
END_MARKERS = {
    "png": b"IEND\xaeB`\x82",
    "jpg": b"\xff\xd9",
    "jpeg": b"\xff\xd9", 
    "gif": b"\x3b",
}

# Embedded content markers with severity classification
EMBEDDED_MARKERS: List[Tuple[bytes, str, str, SeverityLevel]] = [
    (b"MZ", "PE/COFF executable header", ".exe", SeverityLevel.HIGH),
    (b"\x7fELF", "ELF executable header", ".elf", SeverityLevel.HIGH),
    (b"#!/", "Script shebang", ".sh", SeverityLevel.MEDIUM),
    (b"PK\x03\x04", "ZIP archive header", ".zip", SeverityLevel.MEDIUM),
    (b"\x89PNG\r\n\x1a\n", "Nested PNG image", ".png", SeverityLevel.LOW),
    (b"\xff\xd8\xff", "Nested JPEG image", ".jpg", SeverityLevel.LOW),
    (b"\x50\x4b\x05\x06", "ZIP end of central directory", ".zip", SeverityLevel.MEDIUM),
    (b"\x1f\x8b\x08", "GZIP compressed data", ".gz", SeverityLevel.MEDIUM),
    (b"%PDF", "PDF document", ".pdf", SeverityLevel.MEDIUM),
    (b"{\x5c\x72\x74\x66", "RTF document", ".rtf", SeverityLevel.MEDIUM),
]

# Suspicious text patterns
TEXT_PATTERNS = [
    b"/bin/bash",
    b"/bin/sh",
    b"#!/usr/bin/env", 
    b"#!/bin/bash",
    b"#!/bin/sh",
    b"powershell",
    b"cmd.exe",
    b"#!/usr/bin/python",
    b"#!/usr/bin/python3",
    b"eval(",
    b"exec(",
    b"system(",
    b"shell_exec",
    b"base64_decode",
    b"wget ",
    b"curl ",
]

# Configuration constants
CHUNK_SIZE = 64 * 1024 * 1024  # 64MB chunks
MMAP_THRESHOLD = 10 * 1024 * 1024  # Use mmap for files > 10MB
MAX_WORKERS = min(32, (os.cpu_count() or 1) + 4)
SUPPORTED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff", ".tif", ".ico"}
PRE_EOI_SCAN_LIMIT = 5000  # Only scan last 5KB before EOI for embedded content

class PerformanceMonitor:
    def __init__(self):
        self.start_time = time.time()
        self.files_processed = 0
        self.bytes_processed = 0
        self.detections_found = 0
        self.process = psutil.Process()
        
    def update(self, file_size: int, detection_count: int = 0):
        self.files_processed += 1
        self.bytes_processed += file_size
        self.detections_found += detection_count
        
    def get_stats(self) -> Dict[str, float]:
        elapsed = time.time() - self.start_time
        memory_mb = self.process.memory_info().rss / 1024 / 1024
        
        return {
            'elapsed_seconds': elapsed,
            'files_per_second': self.files_processed / max(elapsed, 0.001),
            'mb_per_second': (self.bytes_processed / 1024 / 1024) / max(elapsed, 0.001),
            'memory_mb': memory_mb,
            'files_processed': self.files_processed,
            'bytes_processed': self.bytes_processed,
            'detections_found': self.detections_found
        }

def calculate_file_hash(file_path: str) -> Optional[str]:
    """Calculate SHA-256 hash of file for identification"""
    try:
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (IOError, OSError):
        return None

def detect_image_format(data_view) -> Optional[str]:
    """Detect image format from file signature"""
    for fmt, sig in IMAGE_SIGNATURES.items():
        if len(data_view) >= len(sig) and data_view[:len(sig)] == sig:
            if fmt == "webp":
                # Verify WEBP by checking for 'WEBP' at offset 8
                if len(data_view) >= 12 and data_view[8:12] == b"WEBP":
                    return fmt
            elif fmt == "tiff_be":
                return "tiff"  # Normalize big-endian TIFF
            else:
                return fmt
    return None

def find_pattern_occurrences(data_view, pattern: bytes, start: int = 0, end: Optional[int] = None) -> List[int]:
    """Efficiently find all occurrences of a pattern in data"""
    if end is None:
        end = len(data_view)
    
    positions = []
    
    # Use direct slice searching for memory views to avoid full conversion
    if hasattr(data_view, 'find'):
        # Works with bytes objects
        pos = start
        while pos < end:
            found = data_view.find(pattern, pos, end)
            if found == -1:
                break
            positions.append(found)
            pos = found + 1
    else:
        # For memory-mapped objects, search in smaller chunks to avoid full conversion
        chunk_size = min(CHUNK_SIZE, end - start)
        pos = start
        
        while pos < end:
            chunk_end = min(pos + chunk_size, end)
            # Only convert the chunk we need
            chunk = bytes(data_view[pos:chunk_end])
            
            chunk_pos = 0
            while chunk_pos < len(chunk):
                found = chunk.find(pattern, chunk_pos)
                if found == -1:
                    break
                positions.append(pos + found)
                chunk_pos = found + 1
            
            # Move to next chunk with overlap to catch patterns spanning chunks
            pos = chunk_end - len(pattern) + 1
            if pos <= start:
                break
                
    return positions

def find_last_occurrence(data_view, pattern: bytes) -> int:
    """Find the last occurrence of a pattern using proper rfind"""
    try:
        if hasattr(data_view, 'rfind'):
            return data_view.rfind(pattern)
        else:
            # For memory-mapped data, convert to bytes for rfind
            data_bytes = bytes(data_view)
            return data_bytes.rfind(pattern)
    except (MemoryError, OSError):
        # Fallback for very large files
        return -1

def scan_embedded_markers(data_view, start: int = 0, end: Optional[int] = None) -> List[DetectionResult]:
    """Scan for embedded executable and archive markers"""
    if end is None:
        end = len(data_view)
    
    detections = []
    for marker, desc, ext, severity in EMBEDDED_MARKERS:
        positions = find_pattern_occurrences(data_view, marker, start, end)
        for pos in positions:
            detections.append(DetectionResult(
                offset=pos,
                description=desc,
                marker_type="embedded",
                severity=severity,
                file_extension=ext
            ))
    
    return detections

def scan_text_patterns(data_view, start: int = 0, end: Optional[int] = None) -> List[str]:
    """Scan for suspicious text patterns"""
    if end is None:
        end = len(data_view)
        
    detections = []
    for pattern in TEXT_PATTERNS:
        positions = find_pattern_occurrences(data_view, pattern, start, end)
        for pos in positions:
            detections.append(f"Suspicious text '{pattern.decode(errors='ignore')}' at offset {pos}")
    
    return detections

def find_end_marker(data_view, fmt: str) -> int:
    """Find the end-of-image marker for known formats"""
    if fmt not in END_MARKERS:
        return len(data_view)  # No specific end marker
    
    marker = END_MARKERS[fmt]
    pos = find_last_occurrence(data_view, marker)
    return pos + len(marker) if pos != -1 else -1

def safe_write_file(path: str, data) -> bool:
    """Safely write data to file with error handling"""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            if hasattr(data, 'read'):
                # Handle file-like objects
                f.write(data.read())
            else:
                f.write(data)
        return True
    except (IOError, OSError, MemoryError) as e:
        print(f"Warning: Could not write {path}: {e}")
        return False

def perform_analysis_core(data_view, file_path: str, carve: bool = False, 
                         outdir: Optional[str] = None, max_carves: int = 10) -> AnalysisResult:
    """Core analysis logic shared between mmap and regular file processing"""
    start_time = time.time()
    
    result = AnalysisResult(
        file_path=file_path,
        size_bytes=len(data_view),
        format=None,
        end_marker_offset=None,
        trailing_bytes=0,
        has_trailing_data=False,
        embedded_detections=[],
        text_detections=[],
        notes=[],
        carved_files=[],
        processing_method="",
        file_hash=calculate_file_hash(file_path)
    )
    
    if len(data_view) == 0:
        result.notes.append("Empty file")
        return result
    
    # Detect image format
    fmt = detect_image_format(data_view)
    result.format = fmt if fmt else "unknown"
    
    if not fmt:
        result.notes.append("Unknown or non-standard image header")
        # Scan entire file for markers
        result.embedded_detections = scan_embedded_markers(data_view)
        result.text_detections = scan_text_patterns(data_view)
        
        # Carving for unknown format
        if carve and outdir and result.embedded_detections:
            base = os.path.splitext(os.path.basename(file_path))[0]
            for i, detection in enumerate(result.embedded_detections[:max_carves]):
                dump_path = os.path.join(outdir, f"{base}.marker{i:02d}{detection.file_extension}")
                if safe_write_file(dump_path, data_view[detection.offset:]):
                    result.carved_files.append(dump_path)
        
        result.processing_time = time.time() - start_time
        return result
    
    # Find end of image marker
    eoi = find_end_marker(data_view, fmt)
    result.end_marker_offset = eoi if eoi != -1 else None
    
    if eoi == -1:
        result.notes.append("End-of-image marker not found; file may be malformed or crafted")
        eoi = len(data_view)
    
    # Analyze trailing data
    if eoi < len(data_view):
        trailing_size = len(data_view) - eoi
        result.trailing_bytes = trailing_size
        result.has_trailing_data = True
        
        # Scan trailing region for embedded content
        trailing_detections = scan_embedded_markers(data_view, eoi)
        result.text_detections = scan_text_patterns(data_view, eoi)
        
        # Adjust offsets to be relative to EOI for trailing content
        for detection in trailing_detections:
            detection.offset = detection.offset - eoi
            result.embedded_detections.append(detection)
        
        # Also scan area just before EOI for embedded content (limited scope)
        pre_eoi_start = max(0, eoi - PRE_EOI_SCAN_LIMIT)
        pre_eoi_detections = scan_embedded_markers(data_view, pre_eoi_start, eoi)
        
        for detection in pre_eoi_detections:
            # Only report if it's a significant finding (not just format signature)
            if detection.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
                result.embedded_detections.append(detection)
        
        # Carve suspicious content
        if carve and outdir:
            base = os.path.splitext(os.path.basename(file_path))[0]
            carved_count = 0
            
            # 1) Raw trailing data
            if trailing_size > 0:
                dump_path = os.path.join(outdir, f"{base}.trailing.bin")
                if safe_write_file(dump_path, data_view[eoi:]):
                    result.carved_files.append(dump_path)
                    carved_count += 1
            
            # 2) Marker-based carving from trailing region
            for i, detection in enumerate([d for d in result.embedded_detections if d.offset >= 0]):
                if carved_count >= max_carves:
                    break
                actual_offset = eoi + detection.offset if detection.offset < 1000 else detection.offset
                dump_path = os.path.join(outdir, f"{base}.marker{i:02d}{detection.file_extension}")
                if safe_write_file(dump_path, data_view[actual_offset:]):
                    result.carved_files.append(dump_path)
                    carved_count += 1
    
    result.processing_time = time.time() - start_time
    return result

def analyze_with_mmap(path: str, carve: bool = False, outdir: Optional[str] = None, 
                     max_carves: int = 10) -> AnalysisResult:
    """Memory-mapped file analysis for large files"""
    try:
        with open(path, "rb") as f:
            file_size = os.path.getsize(path)
            
            if file_size == 0:
                return AnalysisResult(
                    file_path=path, size_bytes=0, format=None,
                    end_marker_offset=None, trailing_bytes=0, has_trailing_data=False,
                    embedded_detections=[], text_detections=[], notes=["Empty file"],
                    carved_files=[], processing_method="mmap"
                )
            
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                result = perform_analysis_core(mm, path, carve, outdir, max_carves)
                result.processing_method = "mmap"
                return result
                
    except (IOError, OSError, ValueError) as e:
        return AnalysisResult(
            file_path=path, size_bytes=0, format=None,
            end_marker_offset=None, trailing_bytes=0, has_trailing_data=False,
            embedded_detections=[], text_detections=[], 
            notes=[f"Error processing file: {e}"],
            carved_files=[], processing_method="mmap_error"
        )

def analyze_regular_file(path: str, carve: bool = False, outdir: Optional[str] = None, 
                        max_carves: int = 10) -> AnalysisResult:
    """Regular file reading analysis for smaller files"""
    try:
        with open(path, "rb") as f:
            data = f.read()
        
        result = perform_analysis_core(data, path, carve, outdir, max_carves)
        result.processing_method = "regular"
        return result
        
    except (IOError, OSError, MemoryError) as e:
        return AnalysisResult(
            file_path=path, size_bytes=0, format=None,
            end_marker_offset=None, trailing_bytes=0, has_trailing_data=False,
            embedded_detections=[], text_detections=[],
            notes=[f"Error processing file: {e}"],
            carved_files=[], processing_method="regular_error"
        )

def analyze_image_file(path: str, carve: bool = False, outdir: Optional[str] = None, 
                      max_carves: int = 10) -> AnalysisResult:
    """Main analysis function - chooses optimal method based on file size"""
    try:
        file_size = os.path.getsize(path)
        
        if file_size >= MMAP_THRESHOLD:
            return analyze_with_mmap(path, carve, outdir, max_carves)
        else:
            return analyze_regular_file(path, carve, outdir, max_carves)
            
    except (IOError, OSError) as e:
        return AnalysisResult(
            file_path=path, size_bytes=0, format=None,
            end_marker_offset=None, trailing_bytes=0, has_trailing_data=False,
            embedded_detections=[], text_detections=[],
            notes=[f"Error accessing file: {e}"],
            carved_files=[], processing_method="error"
        )

def process_single_file(args_tuple) -> AnalysisResult:
    """Worker function for multiprocessing"""
    path, carve, outdir, max_carves = args_tuple
    return analyze_image_file(path, carve, outdir, max_carves)

def collect_target_files(paths: List[str], recursive: bool, custom_extensions: Optional[set] = None) -> List[str]:
    """Collect all image files to process"""
    targets = []
    extensions = custom_extensions or SUPPORTED_EXTENSIONS
    
    for p in paths:
        if os.path.isdir(p):
            if recursive:
                for root, _, files in os.walk(p):
                    for fn in files:
                        if os.path.splitext(fn.lower())[1] in extensions:
                            targets.append(os.path.join(root, fn))
            else:
                try:
                    for fn in os.listdir(p):
                        filepath = os.path.join(p, fn)
                        if (os.path.isfile(filepath) and 
                            os.path.splitext(fn.lower())[1] in extensions):
                            targets.append(filepath)
                except (PermissionError, OSError) as e:
                    print(f"Warning: Cannot access directory {p}: {e}")
        else:
            if os.path.isfile(p):
                targets.append(p)
            else:
                print(f"Warning: File not found: {p}")
    
    return list(dict.fromkeys(targets))  # Remove duplicates

def colorize_text(text: str, color: str, enabled: bool = True) -> str:
    """Apply color to text if color support is available"""
    if not enabled or not HAS_COLOR:
        return text
    
    color_map = {
        'red': Fore.RED,
        'green': Fore.GREEN,
        'yellow': Fore.YELLOW,
        'blue': Fore.BLUE,
        'cyan': Fore.CYAN,
        'magenta': Fore.MAGENTA,
        'white': Fore.WHITE,
        'bright': Style.BRIGHT,
        'dim': Style.DIM
    }
    
    return f"{color_map.get(color, '')}{text}{Style.RESET_ALL}"

def format_severity(severity: SeverityLevel, use_color: bool = True) -> str:
    """Format severity level with appropriate coloring"""
    severity_colors = {
        SeverityLevel.LOW: 'cyan',
        SeverityLevel.MEDIUM: 'yellow', 
        SeverityLevel.HIGH: 'red',
        SeverityLevel.CRITICAL: 'red'
    }
    
    text = severity.value.upper()
    if severity == SeverityLevel.CRITICAL:
        text = f"{Style.BRIGHT}{text}"
    
    return colorize_text(text, severity_colors[severity], use_color)

def export_results_json(results: List[AnalysisResult], output_file: str) -> bool:
    """Export analysis results to JSON format"""
    try:
        # Convert dataclass results to dictionaries
        json_data = []
        for result in results:
            result_dict = asdict(result)
            # Convert enums to strings for JSON serialization
            for detection in result_dict['embedded_detections']:
                detection['severity'] = detection['severity']['value'] if isinstance(detection['severity'], dict) else detection['severity']
            json_data.append(result_dict)
        
        with open(output_file, 'w') as f:
            json.dump(json_data, f, indent=2, default=str)
        return True
    except (IOError, OSError, json.JSONEncodeError) as e:
        print(f"Error exporting JSON: {e}")
        return False

def print_analysis_results(results: List[AnalysisResult], use_color: bool = True):
    """Print formatted analysis results"""
    print(colorize_text("="*70, 'bright', use_color))
    print(colorize_text("POLYSCAN ANALYSIS RESULTS", 'bright', use_color))
    print(colorize_text("="*70, 'bright', use_color))
    
    for result in results:
        print(f"\nFile: {colorize_text(result.file_path, 'cyan', use_color)}")
        print(f"Size: {result.size_bytes:,} bytes")
        print(f"Format: {result.format or 'unknown'}")
        print(f"Hash: {result.file_hash or 'N/A'}")
        print(f"Processing: {result.processing_method} ({result.processing_time:.3f}s)")
        
        if result.end_marker_offset is not None:
            print(f"End-of-image marker: offset {result.end_marker_offset}")
            
        if result.has_trailing_data:
            print(colorize_text(
                f"Trailing bytes: {result.trailing_bytes:,}  <-- POSSIBLE POLYGLOT/APPENDED DATA",
                'red', use_color
            ))
            
        if result.embedded_detections:
            print(colorize_text("Embedded markers / suspicious indicators:", 'yellow', use_color))
            
            # Group by severity for better display
            detections_by_severity = defaultdict(list)
            for detection in result.embedded_detections:
                detections_by_severity[detection.severity].append(detection)
            
            for severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW]:
                if severity in detections_by_severity:
                    for detection in sorted(detections_by_severity[severity], key=lambda x: x.offset):
                        severity_text = format_severity(severity, use_color)
                        if detection.offset < 1000:  # Trailing data (relative offset)
                            location = f"EOI+{detection.offset}"
                        else:
                            location = f"{detection.offset}"
                        print(f"  - [{severity_text}] {detection.description} at offset {location}")
                
        if result.text_detections:
            print(colorize_text("Suspicious text indicators:", 'yellow', use_color))
            for detection in sorted(set(result.text_detections)):
                print(f"  - {detection}")
                
        if result.notes:
            print("Notes:")
            for note in result.notes:
                print(f"  - {note}")
                
        if result.carved_files:
            print(colorize_text("Carved artifacts:", 'green', use_color))
            for carved_file in result.carved_files:
                print(f"  - {carved_file}")

def main():
    parser = argparse.ArgumentParser(
        description="PolyScan - Advanced Image Polyglot Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s image.png                    # Analyze single image
  %(prog)s samples/ -r --carve          # Recursively scan directory and carve findings
  %(prog)s *.jpg --json results.json   # Analyze JPEGs and export to JSON
  %(prog)s images/ -j 8 --stats         # Use 8 workers and show performance stats
        """
    )
    
    parser.add_argument("paths", nargs="+", help="Image files or directories to scan")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively scan directories")
    parser.add_argument("--carve", action="store_true", help="Carve suspicious content to files")
    parser.add_argument("-o", "--outdir", default="output", help="Output directory for carved artifacts (default: output)")
    parser.add_argument("--max-carves", type=int, default=10, help="Maximum marker-based carves per file (default: 10)")
    parser.add_argument("-j", "--jobs", type=int, default=MAX_WORKERS, help=f"Number of parallel workers (default: {MAX_WORKERS})")
    parser.add_argument("--no-parallel", action="store_true", help="Disable parallel processing")
    parser.add_argument("--stats", action="store_true", help="Show performance statistics")
    parser.add_argument("--json", metavar="FILE", help="Export results to JSON file")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--extensions", help="Custom file extensions (comma-separated, e.g., '.png,.jpg')")
    
    args = parser.parse_args()
    
    # Process custom extensions if provided
    custom_exts = None
    if args.extensions:
        custom_exts = {ext.strip().lower() for ext in args.extensions.split(',')}
        custom_exts = {ext if ext.startswith('.') else f'.{ext}' for ext in custom_exts}
    
    # Collect target files
    print("Collecting target files...")
    files = collect_target_files(args.paths, args.recursive, custom_exts)
    
    if not files:
        print("No image files found to process.")
        return 1
    
    print(f"Found {len(files)} files to process")
    
    # Initialize performance monitoring
    perf_monitor = PerformanceMonitor() if args.stats else None
    use_color = HAS_COLOR and not args.no_color
    
    results = []
    
    if args.no_parallel or len(files) == 1:
        # Sequential processing
        print("Processing files sequentially...")
        for i, file_path in enumerate(files, 1):
            print(f"Processing [{i}/{len(files)}]: {os.path.basename(file_path)}")
            
            try:
                result = analyze_image_file(file_path, args.carve, args.outdir, args.max_carves)
                results.append(result)
                
                if perf_monitor:
                    perf_monitor.update(result.size_bytes, len(result.embedded_detections))
                    
            except Exception as e:
                print(f"[ERROR] {file_path}: {e}")
                continue
    else:
        # Parallel processing  
        print(f"Processing files in parallel with {args.jobs} workers...")
        
        worker_args = [(fpath, args.carve, args.outdir, args.max_carves) for fpath in files]
        
        with ProcessPoolExecutor(max_workers=args.jobs) as executor:
            future_to_file = {
                executor.submit(process_single_file, arg): arg[0] 
                for arg in worker_args
            }
            
            for i, future in enumerate(as_completed(future_to_file), 1):
                file_path = future_to_file[future]
                print(f"Completed [{i}/{len(files)}]: {os.path.basename(file_path)}")
                
                try:
                    result = future.result()
                    results.append(result)
                    
                    if perf_monitor:
                        perf_monitor.update(result.size_bytes, len(result.embedded_detections))
                        
                except Exception as e:
                    print(f"[ERROR] {file_path}: {e}")
                    continue
    
    # Display results
    any_findings = any(r.has_trailing_data or r.embedded_detections or r.text_detections for r in results)
    
    print_analysis_results(results, use_color)
    
    if not any_findings:
        print(colorize_text("\nNo obvious polyglot indicators found in the scanned files.", 'green', use_color))
    
    # Export to JSON if requested
    if args.json:
        if export_results_json(results, args.json):
            print(f"\nResults exported to: {args.json}")
        else:
            print("\nFailed to export JSON results")
    
    # Performance statistics
    if perf_monitor and args.stats:
        stats = perf_monitor.get_stats()
        print(colorize_text(f"\n{'='*70}", 'bright', use_color))
        print(colorize_text("POLYSCAN PERFORMANCE STATISTICS", 'bright', use_color))
        print(colorize_text("="*70, 'bright', use_color))
        print(f"Files processed: {stats['files_processed']}")
        print(f"Data processed: {stats['bytes_processed'] / 1024 / 1024:.1f} MB")
        print(f"Detections found: {stats['detections_found']}")
        print(f"Processing time: {stats['elapsed_seconds']:.2f} seconds")
        print(f"Files per second: {stats['files_per_second']:.2f}")
        print(f"MB per second: {stats['mb_per_second']:.2f}")
        print(f"Peak memory usage: {stats['memory_mb']:.1f} MB")
        
        # Summary by processing method
        method_counts = defaultdict(int)
        for result in results:
            method_counts[result.processing_method] += 1
        
        print(f"\nProcessing methods used:")
        for method, count in method_counts.items():
            print(f"  - {method}: {count} files")
    
    return 0 if not any_findings else 1

if __name__ == "__main__":
    sys.exit(main())
