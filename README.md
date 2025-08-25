# PolyScan - Image Polyglot Security Scanner

PolyScan is a high-performance security scanner designed to detect and extract embedded executables, scripts, and suspicious content hidden within image files. It's specifically built for defensive security analysis and forensic investigation of image polyglots.

## Features

- **Multi-format Support**: PNG, JPEG, GIF, BMP, WebP, TIFF, ICO
- **High Performance**: Memory-mapped processing for large files, multiprocessing support
- **Comprehensive Detection**: Embedded executables (PE, ELF), scripts, archives, nested images
- **Severity Classification**: Risk-based classification (LOW/MEDIUM/HIGH/CRITICAL)
- **Content Carving**: Extract suspicious artifacts for further analysis
- **JSON Export**: Machine-readable output for automation and integration
- **Colored Output**: Enhanced terminal display with severity-based coloring

## Installation

### Using pipx (Recommended)

```bash
# Install globally with pipx
pipx install polyscan
```

### Using uv (Modern Python Package Manager)

```bash
# Install globally
uv tool install polyscan

# Or install in a virtual environment
uv add polyscan
```

### Using pip

```bash
# Install from PyPI (when published)
pip install polyscan

# Or install from source
git clone https://github.com/aancw/polyscan.git
cd polyscan
pip install .
```

### Development Installation

```bash
git clone https://github.com/aancw/polyscan.git
cd polyscan

# Using uv (recommended)
uv sync --dev

# Using pip
pip install -e .[dev]
```

## Quick Start

```bash
# Analyze a single image
python polyscan.py image.png

# Scan directory recursively and carve suspicious content
python polyscan.py samples/ -r --carve -o output/

# Parallel processing with JSON export
python polyscan.py images/ -j 8 --json results.json --stats

# Custom file extensions
python polyscan.py files/ --extensions ".png,.jpg,.custom"
```

## Usage Examples

### Basic Analysis

```bash
python polyscan.py suspicious_image.png
```

### Batch Processing with Carving

```bash
python polyscan.py samples/ -r --carve -o carved_artifacts/
```

### High-Performance Scanning

```bash
python polyscan.py large_dataset/ -r -j 16 --stats --json scan_results.json
```

## Detection Capabilities

### Image Formats

- PNG (Portable Network Graphics)
- JPEG/JPG (Joint Photographic Experts Group)
- GIF (Graphics Interchange Format)
- BMP (Bitmap)
- WebP (Web Picture format)
- TIFF (Tagged Image File Format)
- ICO (Icon format)

### Embedded Content Detection

- **Executables**: PE/COFF (Windows), ELF (Linux/Unix)
- **Scripts**: Shell scripts, Python, PowerShell commands
- **Archives**: ZIP, GZIP compressed data
- **Documents**: PDF, RTF files
- **Nested Images**: Additional image files within images

### Suspicious Text Patterns

- Shell commands and script interpreters
- System execution functions
- Network utilities (wget, curl)
- Base64 encoding indicators
- Code injection patterns

## Command Line Options

```
usage: polyscan.py [-h] [-r] [--carve] [-o OUTDIR] [--max-carves MAX_CARVES]
                   [-j JOBS] [--no-parallel] [--stats] [--json FILE]
                   [--no-color] [--extensions EXTENSIONS]
                   paths [paths ...]

PolyScan - Advanced Image Polyglot Security Scanner

positional arguments:
  paths                 Image files or directories to scan

options:
  -h, --help            show this help message and exit
  -r, --recursive       Recursively scan directories
  --carve               Carve suspicious content to files
  -o OUTDIR, --outdir OUTDIR
                        Output directory for carved artifacts (default: output)
  --max-carves MAX_CARVES
                        Maximum marker-based carves per file (default: 10)
  -j JOBS, --jobs JOBS  Number of parallel workers
  --no-parallel         Disable parallel processing
  --stats               Show performance statistics
  --json FILE           Export results to JSON file
  --no-color            Disable colored output
  --extensions EXTENSIONS
                        Custom file extensions (comma-separated)
```

## Output Format

### Terminal Output

PolyScan provides colored, structured output showing:

- File information (path, size, format, hash)
- Processing method and timing
- Detected embedded content with severity levels
- Suspicious text patterns
- Carved artifact locations

### JSON Export

Machine-readable format containing:

- Complete analysis results
- File hashes for identification
- Detailed detection information
- Processing metadata
- Performance metrics

## Performance

- **Processing Speed**: 60+ files/second (parallel mode)
- **Memory Efficiency**: Memory-mapped processing for large files
- **Scalability**: Configurable worker processes
- **File Size Support**: Optimized for files from KB to GB range

## Security Considerations

PolyScan is designed for **defensive security analysis only**:

- ✅ Malware analysis and forensic investigation
- ✅ Security research and threat hunting
- ✅ Incident response and digital forensics
- ❌ Should not be used for malicious purposes

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**petruknisme**

## Acknowledgments

- Built for defensive security and forensic analysis
- Inspired by the need for efficient polyglot detection in image files
- Thanks to the security research community for sharing polyglot techniques

