# Security Research

This project hosts security advisories and their accompanying
proof-of-concepts related to research conducted at Google which impact
non-Google owned code.

We believe that vulnerability disclosure is a two-way street. Vendors,
as well as researchers, must act responsibly. This is why Google adheres
to a 90-day disclosure deadline. We notify vendors of vulnerabilities
immediately, with details shared in public with the defensive community
after 90 days, or sooner if the vendor releases a fix.

You can read up on our full policy at:
https://www.google.com/about/appsecurity/.

## Advisories

The disclosure of vulnerabilities are all in the form of security
advisories, which can be browsed in the [Security
Advisories](https://github.com/google/security-research/security/advisories?state=published)
page.

---

## 🛠️ Research Tools

### CVE Parser
**Location**: `tools/cve-parser/`

A Python CLI tool that parses security research repositories and extracts vulnerability metadata (CVE IDs, component types, and folder paths) into JSON and CSV formats.

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

# License & Patents

The advisories and patches posted here are free and open source.

See [LICENSE](https://github.com/google/security-research/blob/master/LICENSE) for
further details.

# Contributing

The easiest way to contribute to our security research projects is to
correct the patches when you see mistakes.

Please read up our
[Contribution](https://github.com/google/security-research/blob/master/CONTRIBUTING.md)
policy.
