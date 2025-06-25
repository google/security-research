# Security Research Tools

A collection of security research and analysis tools for vulnerability research, analysis, and reporting.

## 🛠️ Available Tools

### CVE Parser
**Location**: `tools/cve-parser/`

A Python CLI tool that parses the [google/security-research](https://github.com/google/security-research) repository and extracts vulnerability metadata (CVE IDs, component types, and folder paths) into JSON and CSV formats.

**Features:**
- 🔍 Recursive scanning of security research repositories
- 📄 Processes `.md`, `.txt`, and `.patch` files
- 🎯 CVE detection using regex patterns
- 📊 Multiple output formats (JSON, CSV, HTML)
- 📈 Statistical analysis and reporting
- 🗂️ Component classification
- 📅 Date extraction from filenames and content

**Quick Start:**
```bash
cd tools/cve-parser
python cve_parser.py --repo-dir /path/to/security-research --output-dir ./output --html-report
```

**Demo:**
```bash
cd tools/cve-parser
python demo.py --demo
```

For detailed documentation, see [`tools/cve-parser/README.md`](tools/cve-parser/README.md)

---

## 🚀 Getting Started

1. **Clone this repository:**
   ```bash
   git clone https://github.com/yourusername/security-tools.git
   cd security-tools
   ```

2. **Navigate to a specific tool:**
   ```bash
   cd tools/cve-parser
   ```

3. **Follow the tool-specific documentation**

## 📁 Repository Structure

```
security-tools/
├── README.md                     # This file - main repository overview
├── .gitignore                    # Git ignore rules
├── tools/                        # Collection of security tools
│   ├── cve-parser/               # CVE extraction and analysis tool
│   │   ├── README.md             # Detailed tool documentation
│   │   ├── cve_parser.py         # Main CLI tool
│   │   ├── test_cve_parser.py    # Unit tests
│   │   ├── demo.py               # Demo script
│   │   └── requirements.txt      # Python dependencies
│   └── ...                       # Future tools will be added here
└── docs/                         # Shared documentation (future)
```

## 🎯 Tool Categories

### 📊 **Analysis Tools**
- **CVE Parser** - Extract and analyze CVE data from security research repositories

### 🔍 **Scanning Tools**
*Coming soon...*

### 🛡️ **Security Utilities**
*Coming soon...*

### 📈 **Reporting Tools**
*Coming soon...*

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Adding a New Tool

1. Create a new directory under `tools/your-tool-name/`
2. Include a detailed `README.md` with:
   - Tool description and purpose
   - Installation instructions
   - Usage examples
   - Documentation
3. Add appropriate tests
4. Update this main README to include your tool

### Tool Requirements

- **Python**: Use Python 3.7+ with minimal external dependencies
- **Documentation**: Comprehensive README with examples
- **Testing**: Include unit tests
- **CLI**: Provide command-line interface with help
- **Error Handling**: Robust error handling and user feedback

## 📋 Standards

All tools in this repository follow these standards:

- **PEP8 compliant** Python code
- **Type hints** where appropriate
- **Comprehensive error handling**
- **Detailed documentation** with examples
- **Unit tests** with good coverage
- **CLI interface** with argparse
- **Consistent output formats** (JSON, CSV, etc.)

## 🔧 Development

### Setting up Development Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/security-tools.git
cd security-tools

# Each tool has its own requirements
cd tools/cve-parser
pip install -r requirements.txt

# Run tests
python test_cve_parser.py
```

### Testing

Each tool includes its own test suite. Run tests from the tool's directory:

```bash
cd tools/tool-name
python test_tool.py
```

## 📄 License

This repository is provided for educational and research purposes. Please respect the licenses of any external repositories or data sources when using these tools.

## 🔗 Related Projects

- [google/security-research](https://github.com/google/security-research) - Google's security research repository
- [CVE Details](https://www.cvedetails.com/) - CVE vulnerability database
- [MITRE CVE](https://cve.mitre.org/) - Official CVE database

## 📞 Support

For tool-specific issues:
1. Check the tool's individual README in `tools/tool-name/README.md`
2. Review the tool's help: `python tool.py --help`
3. Run any included demo scripts

For general repository issues:
1. Check this README
2. Review the repository structure
3. Ensure you're using compatible Python versions (3.7+)

---

*This repository is actively maintained and new tools are added regularly. Star this repository to stay updated with the latest security research tools!* 