#!/usr/bin/env python3
"""
CVE Parser for google/security-research repository

This tool recursively scans the google/security-research repository
and extracts CVE metadata into JSON and CSV formats.
"""

import argparse
import csv
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class CVEParser:
    """Parser for extracting CVE information from security research files."""
    
    # Regex pattern for CVE IDs
    CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}')
    
    # File extensions to scan
    SCAN_EXTENSIONS = {'.md', '.txt', '.patch'}
    
    # Default folders to scan if none specified
    DEFAULT_FOLDERS = ['kernel', 'chromium', 'android', 'exploits']
    
    def __init__(self, repo_dir: str, output_dir: str, folders: Optional[List[str]] = None):
        """
        Initialize CVE parser.
        
        Args:
            repo_dir: Path to the google/security-research repository
            output_dir: Directory to save output files
            folders: List of specific folders to scan (optional)
        """
        self.repo_dir = Path(repo_dir)
        self.output_dir = Path(output_dir)
        self.folders = folders or []
        self.cve_data: List[Dict] = []
        
        # Validate directories
        if not self.repo_dir.exists():
            raise FileNotFoundError(f"Repository directory not found: {repo_dir}")
        
        # Create output directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def _guess_date_from_filename(self, filename: str) -> Optional[str]:
        """
        Extract date from filename if present.
        
        Args:
            filename: Name of the file to parse
            
        Returns:
            Date string if found, None otherwise
        """
        # Common date patterns in filenames
        date_patterns = [
            r'(\d{4}-\d{2}-\d{2})',  # YYYY-MM-DD
            r'(\d{4}_\d{2}_\d{2})',  # YYYY_MM_DD
            r'(\d{8})',              # YYYYMMDD
        ]
        
        for pattern in date_patterns:
            match = re.search(pattern, filename)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_date_from_content(self, content: str) -> Optional[str]:
        """
        Extract date from file content if present.
        
        Args:
            content: File content to parse
            
        Returns:
            Date string if found, None otherwise
        """
        # Look for common date patterns in content
        date_patterns = [
            r'(?:Date|Published|Reported):\s*(\d{4}-\d{2}-\d{2})',
            r'(\d{4}-\d{2}-\d{2})',  # Simple YYYY-MM-DD
        ]
        
        for pattern in date_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _get_component_from_path(self, file_path: Path) -> str:
        """
        Extract component name from file path.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Component name based on the folder structure
        """
        # Get relative path from repo root
        try:
            rel_path = file_path.relative_to(self.repo_dir)
            parts = rel_path.parts
            
            if parts:
                # Use the first folder as component
                return parts[0]
            
        except ValueError:
            # Path is not relative to repo_dir
            pass
        
        return "unknown"
    
    def _scan_file(self, file_path: Path) -> List[Dict]:
        """
        Scan a single file for CVE information.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            List of CVE data dictionaries found in the file
        """
        cve_entries = []
        
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Find all CVE IDs in the content
            cve_matches = self.CVE_PATTERN.findall(content)
            
            if cve_matches:
                # Get component and relative path
                component = self._get_component_from_path(file_path)
                rel_path = str(file_path.relative_to(self.repo_dir))
                
                # Try to extract date information
                date_from_filename = self._guess_date_from_filename(file_path.name)
                date_from_content = self._extract_date_from_content(content)
                discovered_date = date_from_filename or date_from_content
                
                # Create entry for each unique CVE found
                for cve_id in set(cve_matches):  # Use set to avoid duplicates
                    entry = {
                        'cve_id': cve_id,
                        'component': component,
                        'file_path': rel_path,
                    }
                    
                    # Add date if found
                    if discovered_date:
                        entry['date'] = discovered_date
                    
                    cve_entries.append(entry)
                    
        except Exception as e:
            print(f"Warning: Error reading file {file_path}: {e}", file=sys.stderr)
        
        return cve_entries
    
    def _get_folders_to_scan(self) -> List[Path]:
        """
        Get list of folders to scan.
        
        Returns:
            List of Path objects for folders to scan
        """
        if self.folders:
            # Use specified folders
            folder_paths = []
            for folder in self.folders:
                folder_path = self.repo_dir / folder
                if folder_path.exists() and folder_path.is_dir():
                    folder_paths.append(folder_path)
                else:
                    print(f"Warning: Folder '{folder}' not found in repository", file=sys.stderr)
            return folder_paths
        else:
            # Scan all top-level directories
            return [p for p in self.repo_dir.iterdir() if p.is_dir() and not p.name.startswith('.')]
    
    def scan_repository(self) -> None:
        """Scan the repository for CVE information."""
        print("Scanning repository for CVE information...")
        
        folders_to_scan = self._get_folders_to_scan()
        
        if not folders_to_scan:
            print("No folders found to scan", file=sys.stderr)
            return
        
        total_files = 0
        total_cves = 0
        
        for folder in folders_to_scan:
            print(f"Scanning folder: {folder.name}")
            
            # Recursively scan all files in the folder
            for file_path in folder.rglob('*'):
                if file_path.is_file() and file_path.suffix in self.SCAN_EXTENSIONS:
                    total_files += 1
                    cve_entries = self._scan_file(file_path)
                    self.cve_data.extend(cve_entries)
                    total_cves += len(cve_entries)
        
        print(f"Scan complete. Found {total_cves} CVE references in {total_files} files.")
    
    def save_json(self, filename: str = "cve_data.json") -> None:
        """
        Save CVE data to JSON file.
        
        Args:
            filename: Name of the JSON file to create
        """
        output_path = self.output_dir / filename
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.cve_data, f, indent=2, ensure_ascii=False)
            print(f"JSON data saved to: {output_path}")
        except Exception as e:
            print(f"Error saving JSON file: {e}", file=sys.stderr)
    
    def save_csv(self, filename: str = "cve_data.csv") -> None:
        """
        Save CVE data to CSV file.
        
        Args:
            filename: Name of the CSV file to create
        """
        output_path = self.output_dir / filename
        
        if not self.cve_data:
            print("No CVE data to save", file=sys.stderr)
            return
        
        try:
            # Get all unique keys from the data
            fieldnames = set()
            for entry in self.cve_data:
                fieldnames.update(entry.keys())
            fieldnames = sorted(fieldnames)
            
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.cve_data)
            
            print(f"CSV data saved to: {output_path}")
        except Exception as e:
            print(f"Error saving CSV file: {e}", file=sys.stderr)
    
    def generate_summary_report(self) -> Dict:
        """
        Generate summary statistics for the CVE data.
        
        Returns:
            Dictionary containing summary statistics
        """
        if not self.cve_data:
            return {}
        
        # Count CVEs by component
        component_counts = {}
        unique_cves = set()
        
        for entry in self.cve_data:
            component = entry['component']
            cve_id = entry['cve_id']
            
            component_counts[component] = component_counts.get(component, 0) + 1
            unique_cves.add(cve_id)
        
        summary = {
            'total_cve_references': len(self.cve_data),
            'unique_cves': len(unique_cves),
            'components': component_counts,
            'scan_timestamp': datetime.now().isoformat()
        }
        
        return summary
    
    def save_html_report(self, filename: str = "cve_report.html") -> None:
        """
        Generate and save an HTML report.
        
        Args:
            filename: Name of the HTML file to create
        """
        output_path = self.output_dir / filename
        summary = self.generate_summary_report()
        
        if not summary:
            print("No data available for HTML report", file=sys.stderr)
            return
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CVE Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background-color: #f4f4f4; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .component-table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        .component-table th, .component-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        .component-table th {{ background-color: #f2f2f2; }}
        .footer {{ margin-top: 40px; font-size: 0.9em; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>CVE Analysis Report</h1>
        <p>Generated on: {summary['scan_timestamp']}</p>
    </div>
    
    <div class="summary">
        <h2>Summary Statistics</h2>
        <ul>
            <li><strong>Total CVE References:</strong> {summary['total_cve_references']}</li>
            <li><strong>Unique CVEs:</strong> {summary['unique_cves']}</li>
            <li><strong>Components Analyzed:</strong> {len(summary['components'])}</li>
        </ul>
    </div>
    
    <div class="components">
        <h2>CVE Count by Component</h2>
        <table class="component-table">
            <thead>
                <tr>
                    <th>Component</th>
                    <th>CVE References</th>
                </tr>
            </thead>
            <tbody>
"""
        
        # Add component rows sorted by count (descending)
        sorted_components = sorted(summary['components'].items(), key=lambda x: x[1], reverse=True)
        for component, count in sorted_components:
            html_content += f"""
                <tr>
                    <td>{component}</td>
                    <td>{count}</td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
    </div>
    
    <div class="footer">
        <p>This report was generated by the CVE Parser tool for the google/security-research repository.</p>
    </div>
</body>
</html>
"""
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"HTML report saved to: {output_path}")
        except Exception as e:
            print(f"Error saving HTML report: {e}", file=sys.stderr)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Parse google/security-research repository for CVE information",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --repo-dir /path/to/security-research --output-dir ./output
  %(prog)s --repo-dir ./security-research --output-dir ./results --folders kernel android
  %(prog)s --repo-dir ./security-research --output-dir ./output --html-report
        """
    )
    
    parser.add_argument(
        '--repo-dir',
        required=True,
        help='Path to the local clone of the google/security-research repository'
    )
    
    parser.add_argument(
        '--output-dir',
        required=True,
        help='Directory to save the generated JSON and CSV files'
    )
    
    parser.add_argument(
        '--folders',
        nargs='*',
        help='Optional list of folder names to limit scanning (e.g., kernel android chromium)'
    )
    
    parser.add_argument(
        '--html-report',
        action='store_true',
        help='Generate an HTML summary report (optional)'
    )
    
    parser.add_argument(
        '--json-file',
        default='cve_data.json',
        help='Name of the JSON output file (default: cve_data.json)'
    )
    
    parser.add_argument(
        '--csv-file',
        default='cve_data.csv',
        help='Name of the CSV output file (default: cve_data.csv)'
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize parser
        cve_parser = CVEParser(
            repo_dir=args.repo_dir,
            output_dir=args.output_dir,
            folders=args.folders
        )
        
        # Scan repository
        cve_parser.scan_repository()
        
        # Save outputs
        cve_parser.save_json(args.json_file)
        cve_parser.save_csv(args.csv_file)
        
        # Generate HTML report if requested
        if args.html_report:
            cve_parser.save_html_report()
        
        # Print summary
        summary = cve_parser.generate_summary_report()
        if summary:
            print("\n=== Summary ===")
            print(f"Total CVE references found: {summary['total_cve_references']}")
            print(f"Unique CVEs: {summary['unique_cves']}")
            print(f"Components analyzed: {len(summary['components'])}")
            
            print("\nTop components by CVE count:")
            sorted_components = sorted(summary['components'].items(), key=lambda x: x[1], reverse=True)
            for component, count in sorted_components[:5]:  # Show top 5
                print(f"  {component}: {count}")
        
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main() 