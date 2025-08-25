# PolyScan Project Structure

## Package Layout

```
polyscan/
├── pyproject.toml          # Modern Python packaging configuration
├── README.md               # Main documentation
├── LICENSE                 # MIT license
├── MANIFEST.in            # Package manifest
├── requirements.txt        # Optional dependencies
├── .python-version        # Python version specification
├── src/                   # Source code directory
│   └── polyscan/          # Main package
│       ├── __init__.py    # Package initialization and exports
│       ├── cli.py         # Command-line interface entry point
│       └── core.py        # Core scanning functionality
├── samples/               # Test samples directory
│   ├── test_polyglot_sample.png
│   ├── malware.jpeg
│   └── test_sample*.{png,jpg,gif}
├── sample_script/         # Sample generation utilities
│   └── create_test_polyglot.py
├── output/                # Default output directory for carved files
└── dist/                  # Built packages (created by build tools)
    ├── polyscan-1.0.0.tar.gz
    └── polyscan-1.0.0-py3-none-any.whl
```

## Key Files

### Configuration Files
- **pyproject.toml**: Modern Python packaging with optional dependencies and tool configuration
- **requirements.txt**: Optional dependencies for enhanced features
- **.python-version**: Minimum Python version (3.8+)
- **MANIFEST.in**: Package manifest for source distribution

### Source Code
- **src/polyscan/__init__.py**: Package exports and metadata
- **src/polyscan/cli.py**: Command-line interface entry point
- **src/polyscan/core.py**: Core scanning engine with all functionality

### Package Features
- ✅ **uv compatible**: Modern Python package manager support
- ✅ **pipx compatible**: Global CLI installation
- ✅ **Optional dependencies**: Modular feature installation
- ✅ **Entry points**: Proper CLI command registration
- ✅ **Type hints**: Full type annotation support
- ✅ **Modern packaging**: PEP 517/518 compliant

## Installation Methods

### Development Installation
```bash
# Using uv (recommended)
uv sync --dev

# Using pip
pip install -e .[all]
```

### Global Installation
```bash
# Using pipx (recommended for CLI tools)
pipx install polyscan[all]

# Using uv tool
uv tool install polyscan[all]
```

### Virtual Environment Installation
```bash
# Using uv
uv add polyscan[all]

# Using pip
pip install polyscan[all]
```

## Optional Dependencies

- **color**: `colorama>=0.4.4` - Colored terminal output
- **performance**: `psutil>=5.8.0` - Performance monitoring
- **all**: Both color and performance features

## Build and Distribution

```bash
# Build packages
uv build

# Results in:
# dist/polyscan-1.0.0.tar.gz        # Source distribution
# dist/polyscan-1.0.0-py3-none-any.whl  # Wheel distribution
```