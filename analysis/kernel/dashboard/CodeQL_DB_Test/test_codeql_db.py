#!/usr/bin/env python3
"""
Standalone CodeQL Linux Kernel Database Quality Test Suite (`test_codeql_db.py`)
===============================================================================
Evaluates a single CodeQL database (`linux_codeql_db_v*`) purely on its own
intrinsic structural health, self-consistency, and completeness—without
relying on external reference databases or hardcoded version-specific counts.

Evaluates 21 intrinsic checks across 5 domains:
  1. Build-Tracer & EDG Extractor Log Forensics (`<db>/log/build-tracer.log`)
  2. Intrinsic Compilation-to-Extraction Coverage & Cross-Subsystem Parity (`extraction_coverage.ql`)
  3. Intra-Procedural AST & Control-Flow Integrity (`ast_corruption.ql`)
  4. Call-Graph & Ops Table Definition Resolution Rates (`callgraph_completeness.ql`)
  5. Universal Kernel Anchor Subgraph Integrity (`kernel_invariants.ql`)
"""

import argparse
import csv
import io
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class CheckResult:
    domain: str
    name: str
    status: str  # "PASS", "WARN", "FAIL"
    metric_str: str
    expected_str: str
    detail: str


class StandaloneCodeQLDBValidator:
    def __init__(self, db_path: Path, codeql_bin: str, ram_mb: int = 16000, threads: int = 8):
        self.db_path = db_path.resolve()
        self.codeql_bin = codeql_bin
        self.ram_mb = ram_mb
        self.threads = threads
        self.script_dir = Path(__file__).resolve().parent
        self.results: List[CheckResult] = []

    def add_check(self, domain: str, name: str, status: str, metric_str: str, expected_str: str, detail: str):
        self.results.append(CheckResult(domain, name, status, metric_str, expected_str, detail))

    # -------------------------------------------------------------------------
    # Domain 1: Build-Tracer & EDG Extractor Log Forensics
    # -------------------------------------------------------------------------
    def check_build_tracer_log(self) -> Dict[str, int]:
        domain = "1. Extractor & Build-Tracer Log Forensics"
        log_dir = self.db_path / "log"
        log_files = sorted(log_dir.glob("build-tracer*.log")) if log_dir.exists() else []

        stats = {
            "log_size_mb": 0,
            "intercepted_compiles": 0,
            "edg_errors": 0,
            "tu_aborts": 0,
            "typeof_unqual_errors": 0,
            "seg_gs_errors": 0,
        }

        if not log_files:
            self.add_check(
                domain,
                "Build-Tracer Log Presence",
                "WARN",
                "No build-tracer.log found",
                "Present in <db>/log/",
                "Cannot inspect EDG compiler frontend diagnostics without build-tracer.log.",
            )
            return stats

        main_log = log_files[0]
        size_mb = main_log.stat().st_size / (1024 * 1024)
        stats["log_size_mb"] = round(size_mb, 2)

        re_intercept = re.compile(r"Intercepted call to compiler")
        re_error = re.compile(r'error: |catastrophic error:', re.IGNORECASE)
        re_abort = re.compile(r"Error limit reached\.", re.IGNORECASE)
        re_typeof = re.compile(r'identifier "(pto_tmp__|pao_tmp__|pscr_ret__)"|error:[^-\n]*\b__typeof_unqual__\b')
        re_seg_gs = re.compile(r'error:[^-\n]*\b__seg_(gs|fs)\b')

        with open(main_log, "r", errors="replace") as f:
            for line in f:
                if "Intercepted call" in line and re_intercept.search(line):
                    stats["intercepted_compiles"] += 1
                if "error:" in line or "Error limit" in line or "catastrophic" in line:
                    if re_abort.search(line):
                        stats["tu_aborts"] += 1
                    if re_error.search(line):
                        stats["edg_errors"] += 1
                        if re_typeof.search(line):
                            stats["typeof_unqual_errors"] += 1
                        if re_seg_gs.search(line):
                            stats["seg_gs_errors"] += 1

        # Check 1.1: Translation Unit Aborts ("Error limit reached.")
        tu_aborts = stats["tu_aborts"]
        self.add_check(
            domain,
            "EDG Translation Unit Aborts (`Error limit reached.`)",
            "PASS" if tu_aborts == 0 else "FAIL",
            f"{tu_aborts:,} aborted TUs",
            "0 aborted TUs",
            "When EDG hits 100 parse errors in a .c file, it aborts extracting the rest of the translation unit.",
        )

        # Check 1.2: C23 __typeof_unqual__ Macro Compatibility
        tu_err = stats["typeof_unqual_errors"]
        self.add_check(
            domain,
            "C23 `__typeof_unqual__` Macro Compatibility (`percpu-defs.h`)",
            "PASS" if tu_err == 0 else "FAIL",
            f"{tu_err:,} errors",
            "0 errors",
            "Triggered when CONFIG_CC_HAS_TYPEOF_UNQUAL=y without -D__typeof_unqual__=__typeof__ in KCFLAGS.",
        )

        # Check 1.3: GCC Named Address Space Compatibility (__seg_gs / __seg_fs)
        seg_err = stats["seg_gs_errors"]
        self.add_check(
            domain,
            "Named Address Space Compatibility (`__seg_gs` / `__seg_fs`)",
            "PASS" if seg_err == 0 else "FAIL",
            f"{seg_err:,} errors",
            "0 errors",
            "Triggered when building with GCC instead of Clang (CONFIG_CC_HAS_NAMED_AS=y).",
        )

        return stats

    # -------------------------------------------------------------------------
    # Execute Modular CodeQL Test Queries in One Shared Session
    # -------------------------------------------------------------------------
    def run_modular_queries(self) -> Dict[str, List[Dict[str, str]]]:
        queries = [
            "extraction_coverage.ql",
            "ast_corruption.ql",
            "callgraph_completeness.ql",
            "kernel_invariants.ql",
        ]
        query_paths = [str(self.script_dir / q) for q in queries]

        cmd = [
            self.codeql_bin,
            "database",
            "run-queries",
            f"--ram={self.ram_mb}",
            f"--threads={self.threads}",
            str(self.db_path),
        ] + query_paths

        print(f"[*] Evaluating {len(queries)} standalone CodeQL quality queries on {self.db_path.name}...")
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode != 0:
            print(f"[!] Error running CodeQL test queries:\n{res.stderr}", file=sys.stderr)
            sys.exit(2)

        parsed_outputs: Dict[str, List[Dict[str, str]]] = {}
        results_dir = self.db_path / "results" / "codeql-db-test-queries"

        try:
            for q in queries:
                q_stem = q.replace(".ql", "")
                bqrs_path = results_dir / f"{q_stem}.bqrs"
                if not bqrs_path.exists():
                    matches = list((self.db_path / "results").rglob(f"{q_stem}.bqrs"))
                    if matches:
                        bqrs_path = matches[0]

                decode_cmd = [
                    self.codeql_bin,
                    "bqrs",
                    "decode",
                    str(bqrs_path),
                    "--format=csv",
                ]
                dec = subprocess.run(decode_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
                reader = csv.DictReader(io.StringIO(dec.stdout))
                parsed_outputs[q_stem] = list(reader)
        finally:
            # Clean up temporary BQRS files created inside the DB results directory
            if results_dir.exists():
                shutil.rmtree(results_dir, ignore_errors=True)

        return parsed_outputs

    # -------------------------------------------------------------------------
    # Domain 2: Intrinsic Compilation-to-Extraction Coverage & Subsystem Parity
    # -------------------------------------------------------------------------
    def evaluate_extraction_coverage(self, rows: List[Dict[str, str]], log_stats: Dict[str, int]):
        domain = "2. Intrinsic Compilation-to-Extraction Completeness"
        by_scope = {r["scope"]: r for r in rows}

        glob = by_scope.get("GLOBAL", {})
        comp_global = int(glob.get("compiledCFiles", 0))
        extr_global = int(glob.get("extractedCFiles", 0))
        drop_global = int(glob.get("droppedCFiles", 0))
        rate_global = (extr_global / max(comp_global, 1)) * 100.0

        # Check 1.4 (in Domain 1): EDG Parse Error Density per Compiled .c File
        edg_errors = log_stats.get("edg_errors", 0)
        err_per_file = edg_errors / max(comp_global, 1)
        status_err = "PASS" if err_per_file < 0.05 else ("WARN" if err_per_file < 1.0 else "FAIL")
        self.results.insert(
            1,
            CheckResult(
                "1. Extractor & Build-Tracer Log Forensics",
                "EDG Parse Error Density (`edg_errors / compiled_c_files`)",
                status_err,
                f"{edg_errors:,} errors across {comp_global:,} files ({err_per_file:.2f} errors / file)",
                "< 0.05 errors / compiled file",
                "High EDG error density indicates unparsed GNU C / C23 macros corrupting extracted ASTs.",
            ),
        )

        # Check 2.1: Global Compiled .c Extraction Rate
        status_glob = "PASS" if rate_global >= 85.0 else ("WARN" if rate_global >= 80.0 else "FAIL")
        self.add_check(
            domain,
            "Global Compiled `.c` Extraction Rate (`extracted / compiled`)",
            status_glob,
            f"{rate_global:.2f}% ({extr_global:,} / {comp_global:,} files; {drop_global:,} dropped)",
            ">= 85.0% of compiled .c files",
            "Measures what % of .c files compiled during build yielded valid AST function definitions.",
        )

        # Calculate internal core baseline extraction rate (mm + kernel + security)
        core_comp = sum(int(by_scope.get(s, {}).get("compiledCFiles", 0)) for s in ["mm", "kernel", "security"])
        core_extr = sum(int(by_scope.get(s, {}).get("extractedCFiles", 0)) for s in ["mm", "kernel", "security"])
        core_rate = (core_extr / max(core_comp, 1)) * 100.0

        # Check 2.2: Core Subsystems Baseline Extraction Rate (mm + kernel + security)
        self.add_check(
            domain,
            "Core Subsystems Extraction Rate (`mm/` + `kernel/` + `security/`)",
            "PASS" if core_rate >= 92.0 else "FAIL",
            f"{core_rate:.2f}% ({core_extr:,} / {core_comp:,} files)",
            ">= 92.0% extraction rate",
            "Establishes the internal baseline extraction rate for this kernel build.",
        )

        # Check 2.3: fs/ Subsystem Extraction Parity (Self-referential against core_rate)
        fs_comp = int(by_scope.get("fs", {}).get("compiledCFiles", 0))
        fs_extr = int(by_scope.get("fs", {}).get("extractedCFiles", 0))
        fs_drop = int(by_scope.get("fs", {}).get("droppedCFiles", 0))
        fs_rate = (fs_extr / max(fs_comp, 1)) * 100.0
        fs_gap = core_rate - fs_rate

        status_fs = "PASS" if (fs_rate >= 85.0 and fs_gap <= 12.0) else ("WARN" if fs_rate >= 75.0 else "FAIL")
        self.add_check(
            domain,
            "`fs/` Subsystem Extraction Rate & Parity vs. Core Baseline",
            status_fs,
            f"{fs_rate:.2f}% ({fs_extr:,}/{fs_comp:,} files; {fs_drop} dropped | gap: -{fs_gap:.1f}%)",
            ">= 85.0% (within 12% of core baseline)",
            "Severe drop in fs/ indicates mid-file EDG aborts in VFS/filesystem headers.",
        )

        # Check 2.4: net/ Subsystem Extraction Parity (Self-referential against core_rate)
        net_comp = int(by_scope.get("net", {}).get("compiledCFiles", 0))
        net_extr = int(by_scope.get("net", {}).get("extractedCFiles", 0))
        net_drop = int(by_scope.get("net", {}).get("droppedCFiles", 0))
        net_rate = (net_extr / max(net_comp, 1)) * 100.0
        net_gap = core_rate - net_rate

        status_net = "PASS" if (net_rate >= 70.0 and net_gap <= 26.0) else ("WARN" if net_rate >= 65.0 else "FAIL")
        self.add_check(
            domain,
            "`net/` Subsystem Extraction Rate & Parity vs. Core Baseline",
            status_net,
            f"{net_rate:.2f}% ({net_extr:,}/{net_comp:,} files; {net_drop} dropped | gap: -{net_gap:.1f}%)",
            ">= 70.0% (within 26% of core baseline)",
            "Severe drop in net/ indicates mid-file EDG aborts in sk_buff/percpu/sch_generic headers.",
        )

    # -------------------------------------------------------------------------
    # Domain 3: Intra-Procedural AST & Control-Flow Integrity (`ErrorExpr`)
    # -------------------------------------------------------------------------
    def evaluate_ast_corruption(self, rows: List[Dict[str, str]]):
        domain = "3. Intra-Procedural AST & Control-Flow Integrity"
        r = rows[0] if rows else {}

        total_err = int(r.get("totalErrorExprs", 0))
        total_funcs = max(int(r.get("totalDefinedFunctions", 1)), 1)
        corrupt_funcs = int(r.get("corruptedFunctions", 0))
        cond_err = int(r.get("conditionErrorExprs", 0))
        call_err = int(r.get("callArgErrorExprs", 0))
        corrupt_pct = (corrupt_funcs / total_funcs) * 100.0

        # Check 3.1: Total ErrorExpr AST Black Holes
        self.add_check(
            domain,
            "Total Intra-Procedural `ErrorExpr` AST Nodes",
            "PASS" if total_err == 0 else "FAIL",
            f"{total_err:,} ErrorExpr nodes",
            "0 ErrorExpr nodes",
            "Each ErrorExpr represents an unparseable C expression replaced with an AST black hole.",
        )

        # Check 3.2: Corrupted Kernel Functions Percentage
        self.add_check(
            domain,
            "Percentage of Kernel Functions with AST Corruption",
            "PASS" if corrupt_funcs == 0 else "FAIL",
            f"{corrupt_pct:.2f}% ({corrupt_funcs:,} / {total_funcs:,} functions)",
            "0.00% (0 corrupted functions)",
            "Functions containing ErrorExpr nodes suffer broken local data-flow and control-flow.",
        )

        # Check 3.3: Branch Condition AST Corruption
        self.add_check(
            domain,
            "Branch Condition AST Corruption (`IfStmt` / `Loop` conditions)",
            "PASS" if cond_err == 0 else "FAIL",
            f"{cond_err:,} corrupted branch conditions",
            "0 corrupted branch conditions",
            "Corrupted branch conditions break control-flow dominance (dominates(condition, call)).",
        )

        # Check 3.4: Call Argument & Target AST Corruption
        self.add_check(
            domain,
            "Call Site Argument / Target AST Corruption (`Call` / `ExprCall`)",
            "PASS" if call_err == 0 else "FAIL",
            f"{call_err:,} corrupted call arguments",
            "0 corrupted call arguments",
            "Corrupted call arguments break call target resolution and allocation size tracking.",
        )

    # -------------------------------------------------------------------------
    # Domain 4: Call-Graph & Operations Table Definition Resolution Rates
    # -------------------------------------------------------------------------
    def evaluate_callgraph_completeness(self, rows: List[Dict[str, str]]):
        domain = "4. Intrinsic Call-Graph & Ops Table Resolution"
        r = rows[0] if rows else {}

        tot_calls = max(int(r.get("totalCFunctionCalls", 1)), 1)
        res_calls = int(r.get("resolvedCFunctionCalls", 0))
        unres_calls = int(r.get("unresolvedCFunctionCalls", 0))
        glob_res_rate = (res_calls / tot_calls) * 100.0

        fs_tot = max(int(r.get("fsTotalCalls", 1)), 1)
        fs_res = int(r.get("fsResolvedCalls", 0))
        fs_res_rate = (fs_res / fs_tot) * 100.0

        net_tot = max(int(r.get("netTotalCalls", 1)), 1)
        net_res = int(r.get("netResolvedCalls", 0))
        net_res_rate = (net_res / net_tot) * 100.0

        ops_tot = max(int(r.get("opsTotalFuncPtrs", 1)), 1)
        ops_res = int(r.get("opsResolvedFuncPtrs", 0))
        ops_unres = int(r.get("opsUnresolvedFuncPtrs", 0))
        ops_res_rate = (ops_res / ops_tot) * 100.0

        # Check 4.1: Global Direct FunctionCall Definition Resolution Rate
        status_glob_calls = "PASS" if glob_res_rate >= 97.5 else ("WARN" if glob_res_rate >= 95.0 else "FAIL")
        self.add_check(
            domain,
            "Global Direct `FunctionCall` Target Definition Resolution Rate",
            status_glob_calls,
            f"{glob_res_rate:.2f}% ({res_calls:,} / {tot_calls:,} resolved; {unres_calls:,} unresolved)",
            ">= 97.5% resolved to defined functions",
            "When TUs abort, callers in other files reference declarations whose definitions were dropped.",
        )

        # Check 4.2: fs/ Direct Call Resolution Rate
        status_fs_calls = "PASS" if fs_res_rate >= 98.0 else ("WARN" if fs_res_rate >= 95.0 else "FAIL")
        self.add_check(
            domain,
            "`fs/` Direct Call Target Definition Resolution Rate",
            status_fs_calls,
            f"{fs_res_rate:.2f}% ({fs_res:,} / {fs_tot:,} resolved; {fs_tot - fs_res:,} unresolved)",
            ">= 98.0% resolved to defined functions",
            "Measures internal call graph completeness across VFS and filesystem implementations.",
        )

        # Check 4.3: net/ Direct Call Resolution Rate
        status_net_calls = "PASS" if net_res_rate >= 97.5 else ("WARN" if net_res_rate >= 95.0 else "FAIL")
        self.add_check(
            domain,
            "`net/` Direct Call Target Definition Resolution Rate",
            status_net_calls,
            f"{net_res_rate:.2f}% ({net_res:,} / {net_tot:,} resolved; {net_tot - net_res:,} unresolved)",
            ">= 97.5% resolved to defined functions",
            "Measures internal call graph completeness across socket and networking layers.",
        )

        # Check 4.4: Kernel Operations Struct Function-Pointer Resolution Rate
        status_ops = "PASS" if ops_res_rate >= 99.0 else ("WARN" if ops_res_rate >= 97.0 else "FAIL")
        self.add_check(
            domain,
            "Operations Table (`file_operations`/`proto_ops`) Pointer Resolution",
            status_ops,
            f"{ops_res_rate:.2f}% ({ops_res:,} / {ops_tot:,} resolved; {ops_unres:,} missing bodies)",
            ">= 99.0% of ops function pointers have extracted bodies",
            "Unresolved ops pointers sever indirect dispatch edges in ops_edges.ql.",
        )

    # -------------------------------------------------------------------------
    # Domain 5: Universal Kernel Anchor Subgraph Invariants
    # -------------------------------------------------------------------------
    def evaluate_kernel_invariants(self, rows: List[Dict[str, str]]):
        domain = "5. Universal Kernel Anchor Subgraph Invariants"
        by_anchor = {r["anchorName"]: r for r in rows}

        for anchor in ["__sys_setsockopt", "sk_setsockopt", "unix_stream_connect", "vfs_write", "vfs_read"]:
            info = by_anchor.get(anchor)
            if not info or int(info.get("hasValidBody", 0)) == 0:
                self.add_check(
                    domain,
                    f"Core Kernel Anchor `{anchor}` Subgraph Integrity",
                    "FAIL",
                    "MISSING BODY (Function definition dropped by extractor)",
                    "Defined with valid AST body, resolved callees & 0 ErrorExprs",
                    f"Core kernel entry point `{anchor}` has no extracted AST body (aborted translation unit).",
                )
                continue

            callees = int(info.get("directCallees", 0))
            resolved = int(info.get("resolvedCallees", 0))
            unresolved = int(info.get("unresolvedCallees", 0))
            two_hop_unres = int(info.get("twoHopUnresolved", 0))
            err_exprs = int(info.get("calleeErrorExprs", 0))

            # Up to 1 direct callee and 3 2-hop callees may be architecture assembly (.S) helpers (e.g. copy_from_user)
            max_allowed_unresolved = 1
            is_healthy = (unresolved <= max_allowed_unresolved) and (two_hop_unres <= 3) and (err_exprs == 0) and (callees >= 5)

            status = "PASS" if is_healthy else "FAIL"
            self.add_check(
                domain,
                f"Core Kernel Anchor `{anchor}` Subgraph Integrity",
                status,
                f"Callees: {resolved}/{callees} resolved (1-hop unres: {unresolved}, 2-hop unres: {two_hop_unres}) | ErrorExprs: {err_exprs}",
                f"<= {max_allowed_unresolved} 1-hop unres, <= 3 2-hop unres (asm) & 0 ErrorExprs",
                f"Verifies 1-hop & 2-hop call neighborhood integrity around built-in kernel anchor `{anchor}`.",
            )

    # -------------------------------------------------------------------------
    # Run All Checks & Render Report
    # -------------------------------------------------------------------------
    def run_all(self) -> int:
        print("=" * 96)
        print(f"  STANDALONE CODEQL KERNEL DATABASE QUALITY TEST SUITE")
        print(f"  Target Database : {self.db_path}")
        print("=" * 96)

        log_stats = self.check_build_tracer_log()
        q_results = self.run_modular_queries()
        self.evaluate_extraction_coverage(q_results.get("extraction_coverage", []), log_stats)
        self.evaluate_ast_corruption(q_results.get("ast_corruption", []))
        self.evaluate_callgraph_completeness(q_results.get("callgraph_completeness", []))
        self.evaluate_kernel_invariants(q_results.get("kernel_invariants", []))

        current_domain = ""
        pass_cnt = sum(1 for c in self.results if c.status == "PASS")
        warn_cnt = sum(1 for c in self.results if c.status == "WARN")
        fail_cnt = sum(1 for c in self.results if c.status == "FAIL")

        for c in self.results:
            if c.domain != current_domain:
                current_domain = c.domain
                print(f"\n[{current_domain}]")
            tag = f"[{c.status}]"
            print(f"  {tag:6s} {c.name}")
            print(f"         Metric  : {c.metric_str}")
            print(f"         Target  : {c.expected_str}")
            if c.status != "PASS":
                print(f"         Detail  : {c.detail}")

        print("\n" + "=" * 96)
        verdict = "HEALTHY (100% READY FOR DASHBOARD QUERIES)" if fail_cnt == 0 else f"DEGRADED ({fail_cnt} CRITICAL FAILURES DETECTED)"
        print(f"  VERDICT: {len(self.results)} checks  |  {pass_cnt} PASS  |  {warn_cnt} WARN  |  {fail_cnt} FAIL  -->  {verdict}")
        print("=" * 96)
        return 0 if fail_cnt == 0 else 1


def main():
    parser = argparse.ArgumentParser(description="Standalone CodeQL Linux Kernel Database Quality Validator")
    parser.add_argument("--codeql-db", required=True, help="Path to the raw CodeQL database directory")
    default_codeql = shutil.which("codeql") or str(
        Path.home() / "kernel_codeql_workspace" / "codeql-home" / "codeql" / "codeql"
    )
    parser.add_argument(
        "--codeql-bin",
        default=default_codeql,
        help="Path to codeql CLI executable",
    )
    parser.add_argument("--ram", type=int, default=16000, help="RAM limit in MB for CodeQL query evaluation")
    parser.add_argument("--threads", type=int, default=8, help="Thread count for CodeQL query evaluation")
    args = parser.parse_args()

    db_path = Path(args.codeql_db)
    if not db_path.exists():
        print(f"[!] Error: CodeQL database directory not found: {db_path}", file=sys.stderr)
        sys.exit(2)

    validator = StandaloneCodeQLDBValidator(db_path, args.codeql_bin, args.ram, args.threads)
    sys.exit(validator.run_all())


if __name__ == "__main__":
    main()
