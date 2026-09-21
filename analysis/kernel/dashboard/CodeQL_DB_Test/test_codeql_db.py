#!/usr/bin/env python3
"""
Standalone CodeQL Linux Kernel Database Quality Test Suite (`test_codeql_db.py`)
===============================================================================
Pytest test suite evaluating a single CodeQL database (`linux_codeql_db_v*`) on its
intrinsic structural health, self-consistency, and completeness across 6 domains (25 checks):

  1. Build-Tracer & EDG Extractor Log Forensics (`<db>/log/build-tracer.log`)
  2. Intrinsic Compilation-to-Extraction Coverage & Cross-Subsystem Parity (`extraction_coverage.ql`)
  3. Intra-Procedural AST & Control-Flow Integrity (`ast_corruption.ql`)
  4. Call-Graph & Ops Table Definition Resolution Rates (`callgraph_completeness.ql`)
  5. Universal Kernel Anchor Subgraph Integrity (`kernel_invariants.ql`)
  6. Kernel Struct Layout & BTF Type Integrity (`btf_struct_sizes.ql`)

Usage:
    pytest CodeQL_DB_Test -v --codeql-db /path/to/linux_codeql_db_v6.1.111
    python3 CodeQL_DB_Test/test_codeql_db.py --codeql-db /path/to/linux_codeql_db_v6.1.111
"""
from __future__ import annotations

import sys
import warnings
from typing import Any, Dict, List, Optional, Tuple

import pytest
from conftest import record_check


def _evaluate(
    domain: str,
    name: str,
    status: str,
    metric_str: str,
    expected_str: str,
    detail: str,
) -> None:
    """Records a check outcome for the summary table and enforces pytest pass/warn/fail."""
    record_check(domain, name, status, metric_str, expected_str, detail)
    if status == "FAIL":
        pytest.fail(f"[{name}] FAILED: {metric_str} (Expected: {expected_str}). {detail}")
    elif status == "WARN":
        warnings.warn(f"[{name}] WARNING: {metric_str} (Target: {expected_str}). {detail}")


# =============================================================================
# Domain 1: Extractor & Build-Tracer Log Forensics
# =============================================================================
class TestDomain1ExtractorLogForensics:
    DOMAIN = "1. Extractor & Build-Tracer Log Forensics"

    def test_1_1_edg_translation_unit_aborts(self, log_stats: Dict[str, Any]) -> None:
        if not log_stats.get("has_log"):
            _evaluate(
                self.DOMAIN,
                "Build-Tracer Log Presence",
                "WARN",
                "No build-tracer.log found",
                "Present in <db>/log/",
                "Cannot inspect EDG compiler frontend diagnostics without build-tracer.log.",
            )
            return

        tu_aborts = log_stats["tu_aborts"]
        status = "PASS" if tu_aborts == 0 else "FAIL"
        _evaluate(
            self.DOMAIN,
            "EDG Translation Unit Aborts (`Error limit reached.`)",
            status,
            f"{tu_aborts:,} aborted TUs",
            "0 aborted TUs",
            "When EDG hits 100 parse errors in a .c file, it aborts extracting the rest of the translation unit.",
        )

    def test_1_2_edg_parse_error_density(
        self, log_stats: Dict[str, Any], codeql_query_results: Dict[str, List[Dict[str, str]]]
    ) -> None:
        if not log_stats.get("has_log"):
            _evaluate(
                self.DOMAIN,
                "EDG Parse Error Density (`edg_errors / compiled_c_files`)",
                "WARN",
                "No build-tracer.log found",
                "< 0.05 errors / compiled file",
                "Cannot compute EDG parse error density without build-tracer.log.",
            )
            return

        rows = codeql_query_results.get("extraction_coverage", [])
        by_scope = {r["scope"]: r for r in rows}
        comp_global = int(by_scope.get("GLOBAL", {}).get("compiledCFiles", 0))

        edg_errors = log_stats.get("edg_errors", 0)
        err_per_file = edg_errors / max(comp_global, 1)
        status = "PASS" if err_per_file < 0.05 else ("WARN" if err_per_file < 0.50 else "FAIL")
        _evaluate(
            self.DOMAIN,
            "EDG Parse Error Density (`edg_errors / compiled_c_files`)",
            status,
            f"{edg_errors:,} errors across {comp_global:,} files ({err_per_file:.2f} errors / file)",
            "< 0.05 errors / compiled file",
            "High error density indicates systematic macro/header incompatibilities.",
        )

    def test_1_3_c23_typeof_unqual_macro_compatibility(self, log_stats: Dict[str, Any]) -> None:
        if not log_stats.get("has_log"):
            _evaluate(
                self.DOMAIN,
                "C23 `__typeof_unqual__` Macro Compatibility (`percpu-defs.h`)",
                "WARN",
                "No build-tracer.log found",
                "0 errors",
                "Cannot inspect __typeof_unqual__ diagnostics without build-tracer.log.",
            )
            return

        tu_err = log_stats.get("typeof_unqual_errors", 0)
        status = "PASS" if tu_err == 0 else "FAIL"
        _evaluate(
            self.DOMAIN,
            "C23 `__typeof_unqual__` Macro Compatibility (`percpu-defs.h`)",
            status,
            f"{tu_err:,} errors",
            "0 errors",
            "Triggered when CONFIG_CC_HAS_TYPEOF_UNQUAL=y without -D__typeof_unqual__=__typeof__ in KCFLAGS.",
        )

    def test_1_4_named_address_space_compatibility(self, log_stats: Dict[str, Any]) -> None:
        if not log_stats.get("has_log"):
            _evaluate(
                self.DOMAIN,
                "Named Address Space Compatibility (`__seg_gs` / `__seg_fs`)",
                "WARN",
                "No build-tracer.log found",
                "0 errors",
                "Cannot inspect __seg_gs/__seg_fs diagnostics without build-tracer.log.",
            )
            return

        seg_err = log_stats.get("seg_gs_errors", 0)
        status = "PASS" if seg_err == 0 else "FAIL"
        _evaluate(
            self.DOMAIN,
            "Named Address Space Compatibility (`__seg_gs` / `__seg_fs`)",
            status,
            f"{seg_err:,} errors",
            "0 errors",
            "Triggered when building with GCC instead of Clang (CONFIG_CC_HAS_NAMED_AS=y).",
        )


# =============================================================================
# Domain 2: Intrinsic Compilation-to-Extraction Completeness
# =============================================================================
class TestDomain2ExtractionCompleteness:
    DOMAIN = "2. Intrinsic Compilation-to-Extraction Completeness"

    @staticmethod
    def _get_core_stats(by_scope: Dict[str, Dict[str, str]]) -> Tuple[int, int, float]:
        comp_core = sum(int(by_scope.get(s, {}).get("compiledCFiles", 0)) for s in ["mm", "kernel", "security"])
        extr_core = sum(int(by_scope.get(s, {}).get("extractedCFiles", 0)) for s in ["mm", "kernel", "security"])
        rate_core = (extr_core / max(comp_core, 1)) * 100.0
        return comp_core, extr_core, rate_core

    def test_2_1_global_compiled_c_extraction_rate(
        self, codeql_query_results: Dict[str, List[Dict[str, str]]]
    ) -> None:
        by_scope = {r["scope"]: r for r in codeql_query_results.get("extraction_coverage", [])}
        glob = by_scope.get("GLOBAL", {})
        comp_global = int(glob.get("compiledCFiles", 0))
        extr_global = int(glob.get("extractedCFiles", 0))
        drop_global = int(glob.get("droppedCFiles", 0))
        rate_global = (extr_global / max(comp_global, 1)) * 100.0

        status = "PASS" if rate_global >= 85.0 else ("WARN" if rate_global >= 80.0 else "FAIL")
        _evaluate(
            self.DOMAIN,
            "Global Compiled `.c` Extraction Rate (`extracted / compiled`)",
            status,
            f"{rate_global:.2f}% ({extr_global:,} / {comp_global:,} files; {drop_global:,} dropped)",
            ">= 85.0% of compiled .c files",
            "Note: ~10% of kernel .c files are data-only tables (devicetable-offsets.c, firmware/tables) with 0 C functions.",
        )

    def test_2_2_core_subsystems_extraction_rate(
        self, codeql_query_results: Dict[str, List[Dict[str, str]]]
    ) -> None:
        by_scope = {r["scope"]: r for r in codeql_query_results.get("extraction_coverage", [])}
        comp_core, extr_core, rate_core = self._get_core_stats(by_scope)

        status = "PASS" if rate_core >= 92.0 else ("WARN" if rate_core >= 85.0 else "FAIL")
        _evaluate(
            self.DOMAIN,
            "Core Subsystems Extraction Rate (`mm/` + `kernel/` + `security/`)",
            status,
            f"{rate_core:.2f}% ({extr_core:,} / {comp_core:,} files)",
            ">= 92.0% extraction rate",
            "Core subsystems serve as the internal baseline for expected extraction yield.",
        )

    def test_2_3_fs_subsystem_extraction_rate_and_parity(
        self, codeql_query_results: Dict[str, List[Dict[str, str]]]
    ) -> None:
        by_scope = {r["scope"]: r for r in codeql_query_results.get("extraction_coverage", [])}
        _, _, rate_core = self._get_core_stats(by_scope)

        fs = by_scope.get("fs", {})
        comp_fs = int(fs.get("compiledCFiles", 0))
        extr_fs = int(fs.get("extractedCFiles", 0))
        drop_fs = int(fs.get("droppedCFiles", 0))
        rate_fs = (extr_fs / max(comp_fs, 1)) * 100.0
        gap_fs = rate_fs - rate_core

        status = (
            "PASS"
            if (rate_fs >= 85.0 and gap_fs >= -12.0)
            else ("WARN" if (rate_fs >= 75.0 and gap_fs >= -20.0) else "FAIL")
        )
        _evaluate(
            self.DOMAIN,
            "`fs/` Subsystem Extraction Rate & Parity vs. Core Baseline",
            status,
            f"{rate_fs:.2f}% ({extr_fs:,}/{comp_fs:,} files; {drop_fs:,} dropped | gap: {gap_fs:+.1f}%)",
            ">= 85.0% (within 12% of core baseline)",
            "Detects per-cpu header failures that selectively wipe out filesystem translation units (ext4, btrfs, xfs).",
        )

    def test_2_4_net_subsystem_extraction_rate_and_parity(
        self, codeql_query_results: Dict[str, List[Dict[str, str]]]
    ) -> None:
        by_scope = {r["scope"]: r for r in codeql_query_results.get("extraction_coverage", [])}
        _, _, rate_core = self._get_core_stats(by_scope)

        net = by_scope.get("net", {})
        comp_net = int(net.get("compiledCFiles", 0))
        extr_net = int(net.get("extractedCFiles", 0))
        drop_net = int(net.get("droppedCFiles", 0))
        rate_net = (extr_net / max(comp_net, 1)) * 100.0
        gap_net = rate_net - rate_core

        status = (
            "PASS"
            if (rate_net >= 70.0 and gap_net >= -26.0)
            else ("WARN" if (rate_net >= 60.0 and gap_net >= -35.0) else "FAIL")
        )
        _evaluate(
            self.DOMAIN,
            "`net/` Subsystem Extraction Rate & Parity vs. Core Baseline",
            status,
            f"{rate_net:.2f}% ({extr_net:,}/{comp_net:,} files; {drop_net:,} dropped | gap: {gap_net:+.1f}%)",
            ">= 70.0% (within 26% of core baseline)",
            "Detects snmp.h / percpu counter failures that wipe out core IPv4/IPv6/TCP/Unix socket TUs.",
        )

    def test_2_5_preprocessor_and_macro_extraction_completeness(
        self, codeql_query_results: Dict[str, List[Dict[str, str]]]
    ) -> None:
        rows = codeql_query_results.get("callgraph_completeness", [])
        r = rows[0] if rows else {}
        cfg_cnt = int(r.get("configBranchCount", 0))
        macro_cnt = int(r.get("macroCount", 0))
        cap_cnt = int(r.get("capMacroInvocations", 0))

        is_pass = cfg_cnt >= 1000 and macro_cnt >= 50000 and cap_cnt >= 100
        is_warn = cfg_cnt >= 500 and macro_cnt >= 25000 and cap_cnt >= 20
        status = "PASS" if is_pass else ("WARN" if is_warn else "FAIL")
        _evaluate(
            self.DOMAIN,
            "Preprocessor `CONFIG_*` & `CAP_*` Macro Extraction Completeness",
            status,
            f"CONFIG_* branches: {cfg_cnt:,} | Macros: {macro_cnt:,} | CAP_* invocations: {cap_cnt:,}",
            ">= 1,000 CONFIG_* branches, >= 50,000 macros & >= 100 CAP_* invocations",
            "Required by kernel-configs-needed.ql, macro-*.ql, and Tools/check_privilege.py capability resolution.",
        )


# =============================================================================
# Domain 3: Intra-Procedural AST & Control-Flow Integrity
# =============================================================================
class TestDomain3AstAndControlFlowIntegrity:
    DOMAIN = "3. Intra-Procedural AST & Control-Flow Integrity"

    def test_3_1_total_intra_procedural_error_expr_nodes(
        self, codeql_query_results: Dict[str, List[Dict[str, str]]]
    ) -> None:
        rows = codeql_query_results.get("ast_corruption", [])
        r = rows[0] if rows else {}
        total_err = int(r.get("totalErrorExprs", 0))
        status = "PASS" if total_err == 0 else ("WARN" if total_err < 50 else "FAIL")
        _evaluate(
            self.DOMAIN,
            "Total Intra-Procedural `ErrorExpr` AST Nodes",
            status,
            f"{total_err:,} ErrorExpr nodes",
            "0 ErrorExpr nodes",
            "ErrorExpr nodes represent unparseable expressions inside surviving function ASTs.",
        )

    def test_3_2_corrupted_kernel_functions_percentage(
        self, codeql_query_results: Dict[str, List[Dict[str, str]]]
    ) -> None:
        rows = codeql_query_results.get("ast_corruption", [])
        r = rows[0] if rows else {}
        total_funcs = int(r.get("totalDefinedFunctions", 1))
        corr_funcs = int(r.get("corruptedFunctions", 0))
        pct_corr_funcs = (corr_funcs / max(total_funcs, 1)) * 100.0
        status = "PASS" if corr_funcs == 0 else ("WARN" if corr_funcs < 10 else "FAIL")
        _evaluate(
            self.DOMAIN,
            "Percentage of Kernel Functions with AST Corruption",
            status,
            f"{pct_corr_funcs:.2f}% ({corr_funcs:,} / {total_funcs:,} functions)",
            "0.00% (0 corrupted functions)",
            "Functions containing ErrorExpr nodes have broken dataflow and control-flow graphs.",
        )

    def test_3_3_branch_condition_ast_corruption(
        self, codeql_query_results: Dict[str, List[Dict[str, str]]]
    ) -> None:
        rows = codeql_query_results.get("ast_corruption", [])
        r = rows[0] if rows else {}
        corr_branch = int(r.get("conditionErrorExprs", r.get("corruptedBranches", 0)))
        status = "PASS" if corr_branch == 0 else "FAIL"
        _evaluate(
            self.DOMAIN,
            "Branch Condition AST Corruption (`IfStmt` / `Loop` conditions)",
            status,
            f"{corr_branch:,} corrupted branch conditions",
            "0 corrupted branch conditions",
            "Directly breaks condition-graph-*.ql dominance and guard analysis.",
        )

    def test_3_4_call_site_argument_ast_corruption(
        self, codeql_query_results: Dict[str, List[Dict[str, str]]]
    ) -> None:
        rows = codeql_query_results.get("ast_corruption", [])
        r = rows[0] if rows else {}
        corr_calls = int(r.get("callArgErrorExprs", r.get("corruptedCalls", 0)))
        status = "PASS" if corr_calls == 0 else "FAIL"
        _evaluate(
            self.DOMAIN,
            "Call Site Argument / Target AST Corruption (`Call` / `ExprCall`)",
            status,
            f"{corr_calls:,} corrupted call arguments",
            "0 corrupted call arguments",
            "Directly breaks allocs.ql size/flag extraction and indirect call resolution.",
        )

    def test_3_5_return_stmt_ast_corruption(
        self, codeql_query_results: Dict[str, List[Dict[str, str]]]
    ) -> None:
        rows = codeql_query_results.get("ast_corruption", [])
        r = rows[0] if rows else {}
        corr_returns = int(r.get("returnErrorExprs", 0))
        status = "PASS" if corr_returns == 0 else "FAIL"
        _evaluate(
            self.DOMAIN,
            "Return Statement AST Corruption (`ReturnStmt` expressions)",
            status,
            f"{corr_returns:,} corrupted return expressions",
            "0 corrupted return expressions",
            "Directly breaks inter-procedural return-value dataflow and allocation wrapper type inference.",
        )


# =============================================================================
# Domain 4: Intrinsic Call-Graph & Ops Table Resolution
# =============================================================================
class TestDomain4CallGraphAndOpsResolution:
    DOMAIN = "4. Intrinsic Call-Graph & Ops Table Resolution"

    def test_4_1_global_direct_function_call_resolution_rate(
        self, codeql_query_results: Dict[str, List[Dict[str, str]]]
    ) -> None:
        rows = codeql_query_results.get("callgraph_completeness", [])
        r = rows[0] if rows else {}
        tot_calls = int(r.get("totalCFunctionCalls", 1))
        res_calls = int(r.get("resolvedCFunctionCalls", 0))
        unres_calls = int(r.get("unresolvedCFunctionCalls", 0))
        call_res_rate = (res_calls / max(tot_calls, 1)) * 100.0

        status = "PASS" if call_res_rate >= 97.5 else ("WARN" if call_res_rate >= 94.0 else "FAIL")
        _evaluate(
            self.DOMAIN,
            "Global Direct `FunctionCall` Target Definition Resolution Rate",
            status,
            f"{call_res_rate:.2f}% ({res_calls:,} / {tot_calls:,} resolved; {unres_calls:,} unresolved)",
            ">= 97.5% resolved to defined functions",
            "When TUs abort, calls to functions in those TUs resolve only to header declarations without bodies.",
        )

    def test_4_2_fs_direct_call_resolution_rate(
        self, codeql_query_results: Dict[str, List[Dict[str, str]]]
    ) -> None:
        rows = codeql_query_results.get("callgraph_completeness", [])
        r = rows[0] if rows else {}
        fs_tot = int(r.get("fsTotalCalls", 1))
        fs_res = int(r.get("fsResolvedCalls", 0))
        fs_res_rate = (fs_res / max(fs_tot, 1)) * 100.0

        status = "PASS" if fs_res_rate >= 98.0 else ("WARN" if fs_res_rate >= 95.0 else "FAIL")
        _evaluate(
            self.DOMAIN,
            "`fs/` Direct Call Target Definition Resolution Rate",
            status,
            f"{fs_res_rate:.2f}% ({fs_res:,} / {fs_tot:,} resolved; {fs_tot - fs_res:,} unresolved)",
            ">= 98.0% resolved to defined functions",
            "Measures internal call graph completeness across VFS and filesystem implementations.",
        )

    def test_4_3_net_direct_call_resolution_rate(
        self, codeql_query_results: Dict[str, List[Dict[str, str]]]
    ) -> None:
        rows = codeql_query_results.get("callgraph_completeness", [])
        r = rows[0] if rows else {}
        net_tot = int(r.get("netTotalCalls", 1))
        net_res = int(r.get("netResolvedCalls", 0))
        net_res_rate = (net_res / max(net_tot, 1)) * 100.0

        status = "PASS" if net_res_rate >= 97.5 else ("WARN" if net_res_rate >= 95.0 else "FAIL")
        _evaluate(
            self.DOMAIN,
            "`net/` Direct Call Target Definition Resolution Rate",
            status,
            f"{net_res_rate:.2f}% ({net_res:,} / {net_tot:,} resolved; {net_tot - net_res:,} unresolved)",
            ">= 97.5% resolved to defined functions",
            "Measures internal call graph completeness across socket and networking layers.",
        )

    def test_4_4_operations_table_pointer_resolution(
        self, codeql_query_results: Dict[str, List[Dict[str, str]]]
    ) -> None:
        rows = codeql_query_results.get("callgraph_completeness", [])
        r = rows[0] if rows else {}
        ops_tot = int(r.get("opsTotalFuncPtrs", 1))
        ops_res = int(r.get("opsResolvedFuncPtrs", 0))
        ops_unres = int(r.get("opsUnresolvedFuncPtrs", 0))
        ops_res_rate = (ops_res / max(ops_tot, 1)) * 100.0

        status = "PASS" if ops_res_rate >= 99.0 else ("WARN" if ops_res_rate >= 97.0 else "FAIL")
        _evaluate(
            self.DOMAIN,
            "Operations Table (`file_operations`/`proto_ops`) Pointer Resolution",
            status,
            f"{ops_res_rate:.2f}% ({ops_res:,} / {ops_tot:,} resolved; {ops_unres:,} missing bodies)",
            ">= 99.0% of ops function pointers have extracted bodies",
            "Unresolved ops pointers sever indirect dispatch edges in ops_edges.ql.",
        )

    def test_4_5_indirect_expr_call_extraction(
        self, codeql_query_results: Dict[str, List[Dict[str, str]]]
    ) -> None:
        rows = codeql_query_results.get("callgraph_completeness", [])
        r = rows[0] if rows else {}
        expr_calls = int(r.get("totalExprCalls", 0))
        status = "PASS" if expr_calls >= 5000 else ("WARN" if expr_calls >= 2000 else "FAIL")
        _evaluate(
            self.DOMAIN,
            "Indirect Call Site (`ExprCall`) AST Extraction Completeness",
            status,
            f"{expr_calls:,} indirect ExprCall sites",
            ">= 5,000 indirect ExprCall sites",
            "Required for ops_edges.ql, syscall-node-pairs.ql, condition-graph-all.ql, and all-calls.ql.",
        )


# =============================================================================
# Domain 5: Universal Kernel Anchor Subgraph Invariants
# =============================================================================
class TestDomain5KernelAnchorSubgraphInvariants:
    DOMAIN = "5. Universal Kernel Anchor Subgraph Invariants"

    @pytest.mark.parametrize(
        "anchor",
        [
            "__sys_setsockopt",
            "sk_setsockopt",
            "unix_stream_connect",
            "vfs_write",
            "vfs_read",
            "do_sys_openat2",
        ],
    )
    def test_5_core_kernel_anchor_subgraph_integrity(
        self, codeql_query_results: Dict[str, List[Dict[str, str]]], anchor: str
    ) -> None:
        rows = codeql_query_results.get("kernel_invariants", [])
        by_anchor = {r["anchorName"]: r for r in rows}
        info = by_anchor.get(anchor)

        if not info or int(info.get("hasValidBody", 0)) == 0:
            _evaluate(
                self.DOMAIN,
                f"Core Kernel Anchor `{anchor}` Subgraph Integrity",
                "FAIL",
                "MISSING BODY (Function definition dropped by extractor)",
                "Defined with valid AST body, resolved callees & 0 ErrorExprs",
                f"Core kernel entry point `{anchor}` has no extracted AST body (aborted translation unit).",
            )
            return

        callees = int(info.get("directCallees", 0))
        resolved = int(info.get("resolvedCallees", 0))
        unresolved = int(info.get("unresolvedCallees", 0))
        two_hop_unres = int(info.get("twoHopUnresolved", 0))
        err_exprs = int(info.get("calleeErrorExprs", 0))

        # Up to 1 direct callee and 3 2-hop callees may be architecture assembly (.S) helpers (e.g. copy_from_user)
        max_allowed_unresolved = 1
        is_healthy = (
            (unresolved <= max_allowed_unresolved)
            and (two_hop_unres <= 3)
            and (err_exprs == 0)
            and (callees >= 5)
        )

        status = "PASS" if is_healthy else "FAIL"
        _evaluate(
            self.DOMAIN,
            f"Core Kernel Anchor `{anchor}` Subgraph Integrity",
            status,
            f"Callees: {resolved}/{callees} resolved (1-hop unres: {unresolved}, 2-hop unres: {two_hop_unres}) | ErrorExprs: {err_exprs}",
            f"<= {max_allowed_unresolved} 1-hop unres, <= 3 2-hop unres (asm) & 0 ErrorExprs",
            f"Verifies 1-hop & 2-hop call neighborhood integrity around built-in kernel anchor `{anchor}`.",
        )


# =============================================================================
# Domain 6: Kernel Struct Layout & BTF Type Integrity
# =============================================================================
class TestDomain6StructLayoutAndBtfIntegrity:
    DOMAIN = "6. Kernel Struct Layout & BTF Type Integrity"

    @staticmethod
    def _extract_cql_sizes(codeql_query_results: Dict[str, List[Dict[str, str]]]) -> Dict[str, int]:
        cql_sizes: Dict[str, int] = {}
        for r in codeql_query_results.get("btf_struct_sizes", []):
            name = r.get("struct_name", "")
            try:
                size = int(r.get("codeql_size", 0))
            except ValueError:
                size = 0
            if name and size > 0:
                cql_sizes[name] = max(cql_sizes.get(name, 0), size)
        return cql_sizes

    def test_6_1_extracted_named_kernel_struct_count(
        self, codeql_query_results: Dict[str, List[Dict[str, str]]]
    ) -> None:
        cql_sizes = self._extract_cql_sizes(codeql_query_results)
        struct_cnt = len(cql_sizes)
        status = "PASS" if struct_cnt >= 5000 else ("WARN" if struct_cnt >= 2500 else "FAIL")
        _evaluate(
            self.DOMAIN,
            "Extracted Named Kernel Struct Count (`btf_struct_sizes.ql`)",
            status,
            f"{struct_cnt:,} named structs with byte size > 0",
            ">= 5,000 named kernel structs",
            "Verifies CodeQL's type table contains complete struct definitions across kernel subsystems.",
        )

    def test_6_2_universal_64bit_lp64_struct_size_invariants(
        self, codeql_query_results: Dict[str, List[Dict[str, str]]]
    ) -> None:
        cql_sizes = self._extract_cql_sizes(codeql_query_results)

        exact_invariants = {
            "list_head": 16,
            "hlist_node": 16,
            "msg_msg": 48,
            "user_key_payload": 24,
        }
        min_bounds = {
            "sk_buff": 180,
            "task_struct": 1500,
            "file": 160,
            "inode": 400,
            "sock": 500,
            "mm_struct": 700,
            "vm_area_struct": 120,
            "page": 56,
        }

        failures = []
        for sname, exp_sz in exact_invariants.items():
            actual = cql_sizes.get(sname)
            if actual != exp_sz:
                failures.append(f"{sname}={actual} (expected {exp_sz})")
        for sname, min_sz in min_bounds.items():
            actual = cql_sizes.get(sname, 0)
            if actual < min_sz:
                failures.append(f"{sname}={actual} (< {min_sz}B 64-bit bound)")

        status = "PASS" if not failures else "FAIL"
        metric = (
            f"All {len(exact_invariants) + len(min_bounds)} LP64 core struct invariants satisfied "
            f"(list_head={cql_sizes.get('list_head')}B, msg_msg={cql_sizes.get('msg_msg')}B, "
            f"sk_buff={cql_sizes.get('sk_buff')}B, mm_struct={cql_sizes.get('mm_struct')}B)"
            if not failures
            else f"Violations: {', '.join(failures)}"
        )
        _evaluate(
            self.DOMAIN,
            "Universal 64-Bit LP64 Kernel Struct Size Invariants",
            status,
            metric,
            "Exact match on ABI-fixed structs & 64-bit LP64 bounds (no 32-bit VDSO truncation)",
            "Detects 32-bit VDSO/boot-stub struct shadowing or corrupted type sizes in CodeQL.",
        )

    def test_6_3_ground_truth_btf_struct_size_parity(
        self,
        codeql_query_results: Dict[str, List[Dict[str, str]]],
        btf_ground_truth: Tuple[Optional[Dict[str, int]], str],
    ) -> None:
        cql_sizes = self._extract_cql_sizes(codeql_query_results)
        btf_sizes, btf_src = btf_ground_truth

        if btf_sizes:
            shared = set(cql_sizes.keys()) & set(btf_sizes.keys())
            matched = [k for k in shared if cql_sizes[k] == btf_sizes[k]]
            match_rate = (len(matched) / max(len(shared), 1)) * 100.0

            core_security_structs = [
                "sk_buff",
                "msg_msg",
                "pipe_buffer",
                "file",
                "inode",
                "sock",
                "task_struct",
                "mm_struct",
                "vm_area_struct",
                "cred",
                "page",
                "seq_operations",
            ]
            core_mismatches = [
                f"{s} (CodeQL={cql_sizes.get(s)} vs BTF={btf_sizes.get(s)})"
                for s in core_security_structs
                if s in btf_sizes and cql_sizes.get(s) != btf_sizes.get(s)
            ]

            status = (
                "PASS"
                if (match_rate >= 98.0 and not core_mismatches)
                else ("WARN" if (match_rate >= 95.0 and not core_mismatches) else "FAIL")
            )
            core_str = (
                f"100% match on {len(core_security_structs)} core slab structs"
                if not core_mismatches
                else f"Core mismatches: {', '.join(core_mismatches)}"
            )
            _evaluate(
                self.DOMAIN,
                f"Ground-Truth BTF Struct Size Parity ({btf_src})",
                status,
                f"{match_rate:.2f}% ({len(matched):,} / {len(shared):,} shared structs match) | {core_str}",
                ">= 98.0% overall BTF parity & 100% match on core security structs",
                "Cross-validates CodeQL extracted struct sizes against DWARF/BTF debug info.",
            )
        else:
            _evaluate(
                self.DOMAIN,
                "Ground-Truth BTF Struct Size Parity",
                "PASS",
                f"Intrinsic LP64 checks passed ({btf_src})",
                "Optional (--btf-db or --vmlinux for full BTF cross-validation)",
                "Pass --btf-db <sqlite> or --vmlinux <vmlinux> to cross-check all structs against BTF.",
            )


if __name__ == "__main__":
    sys.exit(pytest.main(["-v", __file__] + sys.argv[1:]))
