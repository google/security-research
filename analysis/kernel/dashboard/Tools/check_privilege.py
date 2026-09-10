#!/usr/bin/env python3
"""
Tools/check_privilege.py: Gating-Aware Privilege and Attack-Surface Reachability Analysis.

Answers the fundamental security triage question:
"Is this line reachable from an unprivileged user?"

Crosses static callgraph paths from userspace syscall entry points with CodeQL condition
dominator tables (capable, ns_capable) to determine whether every path passes through
a capability gate, or if an ungated route exists.

Outputs:
  - "REACHABLE WITH NO PRIVILEGE (UNGATED)" (Unprivileged userspace access)
  - "REACHABLE BEHIND USER NAMESPACE CAPABILITY" (User namespace capability required)
  - "REACHABLE, BUT ONLY BEHIND CAP_SYS_ADMIN" (Root capability in init_user_ns required)
  - "UNREACHABLE" (Inaccessible from userspace syscalls)
"""

import argparse
from collections import deque
import heapq
import json
import os
import re
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

# Try importing shared utilities from Tools.find_paths or find_paths
try:
    from Tools.find_paths import (
        ensure_indexes,
        get_enclosing_function,
        get_reachable_syscalls,
        get_callers,
        is_syscall_root,
        is_line_covered_by_syzkaller,
        get_syzkaller_coverage,
    )
except ImportError:
    from find_paths import (
        ensure_indexes,
        get_enclosing_function,
        get_reachable_syscalls,
        get_callers,
        is_syscall_root,
        is_line_covered_by_syzkaller,
        get_syzkaller_coverage,
    )

LOCATION_RE = re.compile(r"^(.+):(\d+):(\d+):(\d+):(\d+)$")

# Cost model for Dijkstra path finding (favoring unprivileged/ungated paths)
COST_UNGATED = 1
COST_NS_CAPABLE = 10_000
COST_CAPABLE = 1_000_000


def clean_file_path(path: str) -> str:
    """Normalize file path by removing leading slashes and linux/ repository prefixes."""
    return path.lstrip("/").replace("linux/", "")


def load_capability_map(conn: sqlite3.Connection) -> Dict[str, str]:
    """
    Dynamically extract capability number-to-name mapping directly from the database.
    Correlates condition definitions with macroinvocation_locations in the SQLite DB.
    """
    cur = conn.cursor()
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='macroinvocation_locations'"
    )
    if not cur.fetchone():
        return {}

    try:
        cur.execute("""
            SELECT macroinvocation_name, file_path, start_line
            FROM macroinvocation_locations
            WHERE macroinvocation_name LIKE 'CAP_%'
        """)
        macro_invs: Dict[Tuple[str, int], List[str]] = {}
        for m_name, f_path, s_line in cur.fetchall():
            clean_f = clean_file_path(f_path)
            macro_invs.setdefault((clean_f, s_line), []).append(m_name)

        cur.execute("""
            SELECT argument, definition
            FROM conditions
            WHERE type IN ('capable', 'ns_capable') AND argument NOT IN ('cap', 'cap_setid')
        """)
        counts: Dict[str, Dict[str, int]] = {}
        for arg, def_loc in cur.fetchall():
            m = LOCATION_RE.match(def_loc)
            if m:
                f = clean_file_path(m.group(1))
                l = int(m.group(2))
                names = macro_invs.get((f, l), [])
                for name in names:
                    counts.setdefault(arg, {}).setdefault(name, 0)
                    counts[arg][name] += 1

        cap_map: Dict[str, str] = {}
        for arg, name_counts in counts.items():
            best_name = max(name_counts.items(), key=lambda x: x[1])[0]
            cap_map[arg] = best_name
        return cap_map
    except sqlite3.Error:
        return {}


def format_capability(
    c_type: str, arg: str, cap_map: Optional[Dict[str, str]] = None
) -> str:
    """Format capability check name nicely, e.g. capable(CAP_SYS_ADMIN), dynamically resolved from DB."""
    cap_name = None
    if cap_map and str(arg) in cap_map:
        cap_name = cap_map[str(arg)]
    elif str(arg).isdigit():
        cap_name = f"CAP_{arg}"
    else:
        cap_name = str(arg)
    return f"{c_type}({cap_name})"


def deduplicate_gates(gates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate gates, preferring concrete numeric capability checks over generic 'cap' parameters.
    """
    if not gates:
        return []

    has_concrete_capable = any(
        g["type"] == "capable" and g["argument"] not in ("cap", "cap_setid")
        for g in gates
    )

    filtered = []
    for g in gates:
        # Filter out internal macro expansion ns_capable(cap) when a concrete capable() check exists
        if has_concrete_capable and g["type"] == "ns_capable" and g["argument"] in ("cap", "cap_setid"):
            continue
        filtered.append(g)

    seen = {}
    for g in filtered:
        loc = g.get("condition") or g.get("definition") or g.get("call_location") or ""
        key = (g["type"], g["argument"], loc)
        seen[key] = g
    return list(seen.values())


def load_condition_gates(
    conn: sqlite3.Connection, verbose: bool = False
) -> Tuple[
    Dict[Tuple[str, int], List[Dict[str, Any]]],
    Dict[str, List[Dict[str, Any]]],
    Dict[str, str],
]:
    """
    Load all capability condition gates from the database into in-memory lookup structures:
      1. call_gates: (clean_file_path, line) -> list of gate definitions
      2. func_gates: function_name -> list of gate definitions inside that function
      3. cap_map: argument -> macro name (e.g. '21' -> 'CAP_SYS_ADMIN') extracted from DB
    Takes ~50ms and allows microsecond-level path gating checks.
    """
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='conditions'")
    if not cur.fetchone():
        return {}, {}, {}

    cap_map = load_capability_map(conn)

    cur.execute("""
        SELECT type, argument, call_location, definition, condition, call
        FROM conditions
        WHERE type IN ('capable', 'ns_capable')
    """)
    rows = cur.fetchall()

    call_gates: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
    def_files: Set[str] = set()
    condition_records = []

    for c_type, arg, call_loc, def_loc, cond_loc, call_name in rows:
        gate_obj = {
            "type": c_type,
            "argument": arg,
            "cap_str": format_capability(c_type, arg, cap_map=cap_map),
            "call": call_name,
            "call_location": call_loc,
            "definition": def_loc,
            "condition": cond_loc,
        }
        condition_records.append(gate_obj)

        if call_loc:
            m = LOCATION_RE.match(call_loc)
            if m:
                f, s_line, _, e_line, _ = m.groups()
                f_clean = clean_file_path(f)
                for l in range(int(s_line), int(e_line) + 1):
                    call_gates.setdefault((f_clean, l), []).append(gate_obj)

        if def_loc:
            m = LOCATION_RE.match(def_loc)
            if m:
                def_files.add(clean_file_path(m.group(1)))

    # Deduplicate call gates at each (file, line)
    for k in call_gates:
        call_gates[k] = deduplicate_gates(call_gates[k])

    # Build func_gates by associating definition lines with function_locations
    func_gates: Dict[str, List[Dict[str, Any]]] = {}
    file_list = list(def_files)
    batch_size = 500
    file_funcs: Dict[str, List[Tuple[str, int, int]]] = {}

    for i in range(0, len(file_list), batch_size):
        batch = file_list[i : i + batch_size]
        placeholders = ",".join("?" for _ in batch)
        cur.execute(
            f"""
            SELECT file_path, function_name, start_line, end_line
            FROM function_locations
            WHERE file_path IN ({placeholders})
        """,
            batch,
        )
        for f, fn, s, e in cur.fetchall():
            file_funcs.setdefault(clean_file_path(f), []).append((fn, s, e))

    for g in condition_records:
        def_loc = g["definition"]
        if not def_loc:
            continue
        m = LOCATION_RE.match(def_loc)
        if not m:
            continue
        f_clean = clean_file_path(m.group(1))
        def_line = int(m.group(2))

        for fn_name, s_line, e_line in file_funcs.get(f_clean, []):
            if s_line <= def_line <= e_line:
                func_gate_obj = dict(g)
                func_gate_obj["check_line"] = def_line
                func_gate_obj["fn_span"] = (s_line, e_line)
                func_gates.setdefault(fn_name, []).append(func_gate_obj)

    for fn in func_gates:
        func_gates[fn] = deduplicate_gates(func_gates[fn])

    if verbose:
        print(
            f"Loaded {len(call_gates)} call-site gates and {len(func_gates)}"
            f" function-level gates ({len(cap_map)} capability names mapped from DB).",
            file=sys.stderr,
        )

    return call_gates, func_gates, cap_map


def get_call_site_gates(
    call_gates: Dict[Tuple[str, int], List[Dict[str, Any]]],
    func_gates: Dict[str, List[Dict[str, Any]]],
    file_path: str,
    line_number: Optional[int],
    caller_fn: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieve all capability gates applying to a specific line or call site.
    Combines direct call-site domination and function-level early-exit checks.
    """
    if line_number is None:
        return []

    f_clean = clean_file_path(file_path)
    gates = list(call_gates.get((f_clean, line_number), []))

    if caller_fn and caller_fn in func_gates:
        for fg in func_gates[caller_fn]:
            # If line is after or at the capability check in caller_fn
            if line_number >= fg.get("check_line", 0):
                gates.append(fg)

    return deduplicate_gates(gates)


def find_best_privilege_path(
    conn: sqlite3.Connection,
    target_fn: str,
    target_file: str,
    target_line: int,
    call_gates: Dict[Tuple[str, int], List[Dict[str, Any]]],
    func_gates: Dict[str, List[Dict[str, Any]]],
    cap_map: Optional[Dict[str, str]] = None,
    target_syscall: Optional[str] = None,
    syzk_conn: Optional[sqlite3.Connection] = None,
    max_depth: int = 25,
) -> Tuple[Optional[str], List[Dict[str, Any]], Optional[List[Dict[str, Any]]]]:
    """
    Search for the optimal path from userspace syscalls to target_fn:target_line using Dijkstra search.
    Edge weights:
      - Ungated hop: 1
      - ns_capable hop: 10,000
      - capable (root) hop: 1,000,000

    Guarantees finding an ungated path first if one exists, otherwise finds minimal capability requirement.
    Returns:
      (verdict, all_gates_on_path, path)
    """
    cur = conn.cursor()
    reachable_set: Optional[Set[str]] = None
    prune_to_reachable = False

    if target_syscall:
        cur.execute(
            "SELECT DISTINCT function FROM syscall_node WHERE syscall = ?",
            (target_syscall,),
        )
        reachable_set = {r[0] for r in cur.fetchall()}
        reachable_set.add(target_syscall)
        base_name = target_syscall.replace("__do_sys_", "").replace("__se_sys_", "")
        for prefix in ["__do_sys_", "__se_sys_", "__x64_sys_", "__ia32_sys_"]:
            reachable_set.add(f"{prefix}{base_name}")
        if target_fn in reachable_set:
            prune_to_reachable = True

    # 1. Check if the target line itself is already gated
    target_gates = get_call_site_gates(
        call_gates, func_gates, target_file, target_line, caller_fn=target_fn
    )

    init_cost = 0
    for g in target_gates:
        if g["type"] == "capable":
            init_cost += COST_CAPABLE
        elif g["type"] == "ns_capable":
            init_cost += COST_NS_CAPABLE

    target_syzk_cov = is_line_covered_by_syzkaller(syzk_conn, target_file, target_line)

    start_step = {
        "function": target_fn,
        "file": target_file,
        "line": target_line,
        "call_site_line": None,
        "call_type": "target",
        "details": "",
        "gates": target_gates,
        "syzk_covered": target_syzk_cov,
    }

    # If the target function itself IS a syscall entry point
    if is_syscall_root(target_fn, target_syscall):
        all_gates = list(target_gates)
        verdict = classify_gates(all_gates, cap_map=cap_map)
        return verdict, all_gates, [start_step]

    # Priority queue: (cost, hop_count, tie_breaker, curr_fn, curr_file, curr_line, path)
    counter = 0
    pq = [(init_cost, 0, counter, target_fn, target_file, target_line, [start_step])]
    best_dist = {target_fn: init_cost}

    while pq:
        cost, hops, _, curr_fn, curr_file, curr_line, path = heapq.heappop(pq)

        if cost > best_dist.get(curr_fn, float("inf")):
            continue

        if is_syscall_root(curr_fn, target_syscall):
            # Collect all gates encountered across the entire path
            all_path_gates = []
            for step in path:
                for g in step.get("gates", []):
                    all_path_gates.append(g)
            all_path_gates = deduplicate_gates(all_path_gates)
            verdict = classify_gates(all_path_gates, cap_map=cap_map)
            return verdict, all_path_gates, path

        if hops >= max_depth:
            continue

        callers = get_callers(conn, curr_fn)
        for (
            caller_fn,
            caller_file,
            caller_line,
            call_site_line,
            call_type,
            details,
        ) in callers:
            if prune_to_reachable and caller_fn not in reachable_set:
                continue

            edge_gates = get_call_site_gates(
                call_gates,
                func_gates,
                caller_file,
                call_site_line,
                caller_fn=caller_fn,
            )

            edge_cost = COST_UNGATED
            for g in edge_gates:
                if g["type"] == "capable":
                    edge_cost += COST_CAPABLE
                elif g["type"] == "ns_capable":
                    edge_cost += COST_NS_CAPABLE

            new_cost = cost + edge_cost
            if new_cost < best_dist.get(caller_fn, float("inf")):
                best_dist[caller_fn] = new_cost
                counter += 1
                step_cov = is_line_covered_by_syzkaller(
                    syzk_conn, caller_file, call_site_line or caller_line
                )
                step = {
                    "function": caller_fn,
                    "file": caller_file,
                    "line": caller_line,
                    "call_site_line": call_site_line,
                    "call_type": call_type,
                    "details": details,
                    "gates": edge_gates,
                    "syzk_covered": step_cov,
                }
                heapq.heappush(
                    pq,
                    (
                        new_cost,
                        hops + 1,
                        counter,
                        caller_fn,
                        caller_file,
                        caller_line,
                        [step] + path,
                    ),
                )

    return None, [], None


def classify_gates(
    gates: List[Dict[str, Any]], cap_map: Optional[Dict[str, str]] = None
) -> str:
    """Classify reachability verdict based on capability gates on the route."""
    if not gates:
        return "REACHABLE WITH NO PRIVILEGE (UNGATED)"

    has_capable = any(g["type"] == "capable" for g in gates)
    has_ns_capable = any(g["type"] == "ns_capable" for g in gates)

    if not has_capable and has_ns_capable:
        return "REACHABLE BEHIND USER NAMESPACE CAPABILITY"

    # Specific CAP_SYS_ADMIN check
    for g in gates:
        if g["type"] == "capable":
            cap_str = format_capability(g["type"], g["argument"], cap_map=cap_map)
            if "CAP_SYS_ADMIN" in cap_str or g["argument"] in ("21", "CAP_SYS_ADMIN"):
                return "REACHABLE, BUT ONLY BEHIND CAP_SYS_ADMIN"

    # Any other root capability
    root_caps = [
        format_capability(g["type"], g["argument"], cap_map=cap_map)
        for g in gates
        if g["type"] == "capable"
    ]
    if root_caps:
        return f"REACHABLE, BUT ONLY BEHIND {root_caps[0]}"

    return "REACHABLE WITH NO PRIVILEGE (UNGATED)"


def analyze_target_privilege(
    db_file: str,
    file_path: str,
    line_number: int,
    target_syscall: Optional[str] = None,
    syzkaller_db: Optional[str] = None,
    all_syscalls: bool = False,
    limit_syscalls: int = 5,
    max_depth: int = 25,
    is_function_entry: bool = False,
    verbose: bool = False,
) -> Tuple[Dict[str, Any], str, Dict[str, Any], List[Dict[str, Any]]]:
    """
    Main programmatic interface for privilege reachability analysis.
    Returns:
      (target_info, overall_verdict, primary_result, all_results)
    """
    if not os.path.isfile(db_file):
        raise FileNotFoundError(f"Database file not found: {db_file}")

    conn = sqlite3.connect(db_file)
    ensure_indexes(conn, verbose=verbose)

    syzk_conn = (
        sqlite3.connect(syzkaller_db)
        if syzkaller_db and os.path.isfile(syzkaller_db)
        else None
    )

    fn_info = get_enclosing_function(conn, file_path, line_number)
    if not fn_info:
        conn.close()
        if syzk_conn:
            syzk_conn.close()
        raise ValueError(f"No enclosing function found for {file_path}:{line_number}")

    fn_name, canonical_file, start_line, end_line = fn_info
    reachable_syscalls = get_reachable_syscalls(conn, fn_name)
    syzk_info = get_syzkaller_coverage(
        syzk_conn, canonical_file, line_number, fn_span=(start_line, end_line)
    )

    target_info = {
        "function": fn_name,
        "file": canonical_file,
        "line": line_number,
        "span": (start_line, end_line),
        "is_function_entry": is_function_entry,
        "all_syscalls": reachable_syscalls,
        "syzkaller": syzk_info,
    }

    # If not reachable by any syscall and not a syscall root itself
    if not reachable_syscalls and not is_syscall_root(fn_name, target_syscall):
        conn.close()
        if syzk_conn:
            syzk_conn.close()
        return target_info, "UNREACHABLE", {}, []

    call_gates, func_gates, cap_map = load_condition_gates(conn, verbose=verbose)
    target_info["internal_gates"] = func_gates.get(fn_name, [])

    all_results = []
    primary_result = {}

    if target_syscall:
        if not target_syscall.startswith("__do_sys_") and not target_syscall.startswith("__se_sys_"):
            matched = [
                s
                for s in reachable_syscalls
                if s.endswith(f"_{target_syscall}") or s == target_syscall
            ]
            eval_syscalls = matched if matched else [f"__do_sys_{target_syscall}"]
        else:
            eval_syscalls = [target_syscall]

        for sc in eval_syscalls:
            verdict, gates, path = find_best_privilege_path(
                conn,
                fn_name,
                canonical_file,
                line_number,
                call_gates,
                func_gates,
                cap_map=cap_map,
                target_syscall=sc,
                syzk_conn=syzk_conn,
                max_depth=max_depth,
            )
            if path:
                res = {
                    "syscall": sc,
                    "verdict": verdict,
                    "gates": gates,
                    "path": path,
                }
                all_results.append(res)

        if all_results:
            primary_result = all_results[0]
            overall_verdict = primary_result["verdict"]
        else:
            overall_verdict = "UNREACHABLE"

    elif all_syscalls:
        # Check all reachable syscalls up to limit
        for sc in reachable_syscalls[:limit_syscalls]:
            verdict, gates, path = find_best_privilege_path(
                conn,
                fn_name,
                canonical_file,
                line_number,
                call_gates,
                func_gates,
                cap_map=cap_map,
                target_syscall=sc,
                syzk_conn=syzk_conn,
                max_depth=max_depth,
            )
            if path:
                all_results.append({
                    "syscall": sc,
                    "verdict": verdict,
                    "gates": gates,
                    "path": path,
                })

        # Overall verdict is ungated if ANY syscall is ungated
        has_ungated = any(
            r["verdict"] == "REACHABLE WITH NO PRIVILEGE (UNGATED)"
            for r in all_results
        )
        has_userns = any(
            r["verdict"] == "REACHABLE BEHIND USER NAMESPACE CAPABILITY"
            for r in all_results
        )

        if has_ungated:
            overall_verdict = "REACHABLE WITH NO PRIVILEGE (UNGATED)"
            ungated_results = [
                r for r in all_results if r["verdict"] == "REACHABLE WITH NO PRIVILEGE (UNGATED)"
            ]
            primary_result = min(ungated_results, key=lambda r: len(r.get("path", [])))
        elif has_userns:
            overall_verdict = "REACHABLE BEHIND USER NAMESPACE CAPABILITY"
            userns_results = [
                r for r in all_results if r["verdict"] == "REACHABLE BEHIND USER NAMESPACE CAPABILITY"
            ]
            primary_result = min(userns_results, key=lambda r: len(r.get("path", [])))
        elif all_results:
            primary_result = min(all_results, key=lambda r: len(r.get("path", [])))
            overall_verdict = primary_result["verdict"]
        else:
            overall_verdict = "UNREACHABLE"
    else:
        # Global search for closest/lowest-privilege path across ANY syscall
        verdict, gates, path = find_best_privilege_path(
            conn,
            fn_name,
            canonical_file,
            line_number,
            call_gates,
            func_gates,
            cap_map=cap_map,
            target_syscall=None,
            syzk_conn=syzk_conn,
            max_depth=max_depth,
        )
        if path:
            root_sc = path[0]["function"]
            primary_result = {
                "syscall": root_sc,
                "verdict": verdict,
                "gates": gates,
                "path": path,
            }
            all_results = [primary_result]
            overall_verdict = verdict
        else:
            overall_verdict = "UNREACHABLE"

    conn.close()
    if syzk_conn:
        syzk_conn.close()

    return target_info, overall_verdict, primary_result, all_results


def format_summary(
    target_info: Dict[str, Any],
    overall_verdict: str,
    primary_result: Dict[str, Any],
    all_results: List[Dict[str, Any]],
) -> str:
    """Format human-readable privilege and gating reachability report."""
    out = []
    out.append("=" * 72)
    out.append("TARGET PRIVILEGE & ATTACK-SURFACE ANALYSIS")
    out.append("=" * 72)
    out.append(
        f"Target: {target_info['file']}:{target_info['line']} in function"
        f" '{target_info['function']}'"
    )
    if target_info.get("span"):
        s, e = target_info["span"]
        out.append(f"Function Span: lines {s} - {e}")

    num_sc = len(target_info.get("all_syscalls", []))
    sc_preview = ", ".join(target_info.get("all_syscalls", [])[:5])
    if num_sc > 5:
        sc_preview += "..."
    out.append(f"Reachable Syscalls: {num_sc} syscall(s) ({sc_preview})")

    out.append("-" * 72)
    out.append(f"VERDICT: {overall_verdict}")
    out.append("-" * 72)

    if overall_verdict == "REACHABLE WITH NO PRIVILEGE (UNGATED)":
        out.append("Privilege Level: Unprivileged (No capabilities required)")
        out.append("Gating Status:   Ungated route available from userspace")
        out.append("Access Scope:    Reachable via standard userspace system calls without special privileges.")
    elif overall_verdict == "REACHABLE BEHIND USER NAMESPACE CAPABILITY":
        out.append("Privilege Level: User Namespace Capability (e.g. ns_capable)")
        out.append("Gating Status:   Gated by user namespace capability check")
        out.append("Access Scope:    Reachable within user namespaces (e.g. via CLONE_NEWUSER / unshare -U).")
    elif "CAP_SYS_ADMIN" in overall_verdict:
        out.append("Privilege Level: Privileged Root (CAP_SYS_ADMIN in init_user_ns)")
        out.append("Gating Status:   All paths pass through capable(CAP_SYS_ADMIN)")
        out.append("Access Scope:    Requires administrative privilege in initial namespace.")
    elif overall_verdict.startswith("REACHABLE, BUT ONLY BEHIND"):
        out.append("Privilege Level: Privileged Capability Required")
        out.append(f"Gating Status:   {overall_verdict}")
        out.append("Access Scope:    Requires capability in initial namespace.")
    else:
        out.append("Privilege Level: Unreachable")
        out.append("Gating Status:   No callgraph paths from userspace syscalls")
        out.append("Access Scope:    Kernel-internal or boot execution only.")

    syzk = target_info.get("syzkaller", {})
    if syzk.get("configured"):
        out.append("-" * 72)
        if syzk.get("line_covered"):
            hit_sys = ", ".join(syzk.get("syscalls", [])) or "unknown"
            out.append(
                f"Dynamic Fuzzer Status (Syzkaller): COVERED (Executed via: {hit_sys})"
            )
            out.append(
                "Classification: FULLY PROVEN (Static Call Path + Live Fuzzer Execution)"
            )
        elif syzk.get("fn_covered"):
            out.append(
                f"Dynamic Fuzzer Status (Syzkaller): PARTIALLY COVERED ({syzk.get('fn_covered_lines')} lines in function executed)"
            )
        else:
            out.append(
                "Dynamic Fuzzer Status (Syzkaller): UNCOVERED (0 live executions recorded)"
            )

    internal_gates = target_info.get("internal_gates", [])
    if internal_gates:
        out.append("-" * 72)
        out.append("Internal Function Capability Gates:")
        for ig in internal_gates:
            c_line = ig.get("check_line", "unknown")
            c_loc = ig.get("definition") or f"line {c_line}"
            out.append(f"  * {ig['cap_str']} at {c_loc}")
        if target_info.get("is_function_entry"):
            first_gate_line = internal_gates[0].get("check_line")
            out.append(
                f"  (Note: Function entry at line {target_info['line']} is ungated; "
                f"internal capability check applies starting at line {first_gate_line})"
            )

    if primary_result and primary_result.get("path"):
        path = primary_result["path"]
        sc = primary_result.get("syscall", "unknown")
        out.append("-" * 72)
        out.append(f"Optimal Call Path (via {sc}):")
        for i, step in enumerate(path):
            fn = step["function"]
            f = step["file"]
            l = step["line"]
            cs = step.get("call_site_line")
            gates = step.get("gates", [])
            gate_str = ""
            if gates:
                g_names = [g["cap_str"] for g in gates]
                gate_str = f" [GATED: {', '.join(g_names)}]"
            else:
                gate_str = " [UNGATED]"

            call_info = f" [calls at line {cs}]" if cs else ""
            indent = "  " * (i + 1)

            if i == 0:
                out.append(f"{indent}└── [Syscall Entry] {fn} ({f}:{l}){gate_str}")
            elif i == len(path) - 1:
                out.append(f"{indent}└── [Target Line]   {fn} ({f}:{l}){gate_str}")
            else:
                out.append(f"{indent}└── {fn} ({f}:{l}){call_info}{gate_str}")

        all_gates = primary_result.get("gates", [])
        if all_gates:
            out.append("\nGate Details:")
            for g in all_gates:
                c_loc = g.get("definition") or g.get("call_location") or "unknown"
                out.append(f"  * {g['cap_str']} at {c_loc}")
        else:
            out.append("\nGate Details: None (All steps completely ungated)")

    if len(all_results) > 1:
        out.append("-" * 72)
        out.append("Privilege Breakdown per Syscall:")
        for r in all_results:
            sc = r["syscall"]
            v = r["verdict"]
            g_count = len(r.get("gates", []))
            out.append(f"  * {sc:<30}: {v} ({g_count} gate(s))")

    out.append("=" * 72)
    return "\n".join(out)


def format_tree(
    target_info: Dict[str, Any],
    primary_result: Dict[str, Any],
    all_results: List[Dict[str, Any]],
) -> str:
    """Format call paths as an indented ASCII tree with per-hop gating annotations."""
    out = []
    out.append("=" * 72)
    out.append(
        f"Target: {target_info['file']}:{target_info['line']} in"
        f" {target_info['function']}"
    )
    out.append("=" * 72)

    results_to_show = all_results if all_results else ([primary_result] if primary_result else [])
    for res in results_to_show:
        sc = res.get("syscall", "unknown")
        path = res.get("path", [])
        verdict = res.get("verdict", "unknown")
        out.append(f"\n[Syscall: {sc} -> {verdict}]")
        if not path:
            out.append("  (No path found)")
            continue

        for i, step in enumerate(path):
            indent = "  " * i
            fn = step["function"]
            f = step["file"]
            l = step["line"]
            cs = step.get("call_site_line")
            gates = step.get("gates", [])
            gate_tag = (
                f" [GATED: {', '.join(g['cap_str'] for g in gates)}]"
                if gates
                else " [UNGATED]"
            )
            call_info = f" [calls at L{cs}]" if cs else ""

            if i == 0:
                out.append(f"{indent}└── [Syscall Entry] {fn} ({f}:{l}){gate_tag}")
            elif i == len(path) - 1:
                out.append(f"{indent}└── [Target Line] {fn} ({f}:{l}){gate_tag}")
            else:
                out.append(f"{indent}└── {fn} ({f}:{l}){call_info}{gate_tag}")

    return "\n".join(out)


def format_paths(
    primary_result: Dict[str, Any], all_results: List[Dict[str, Any]]
) -> str:
    """Format call paths as arrow-separated chains with gate annotations."""
    out = []
    results_to_show = all_results if all_results else ([primary_result] if primary_result else [])
    for res in results_to_show:
        path = res.get("path", [])
        if not path:
            continue
        chain = " -> ".join([
            f"{s['function']}({s['file']}:{s.get('call_site_line') or s['line']})"
            + (f"[{','.join(g['cap_str'] for g in s['gates'])}]" if s.get("gates") else "")
            for s in path
        ])
        out.append(f"[{res.get('verdict')}]\n{chain}")
    return "\n\n".join(out)


def main():
    ap = argparse.ArgumentParser(
        description=(
            "Cross syscall reachability with capability condition gates to determine "
            "whether a kernel source line/function is reachable from unprivileged users."
        )
    )
    ap.add_argument(
        "--db",
        required=True,
        help="Path to CodeQL SQLite database",
    )
    ap.add_argument(
        "--syzkaller-db",
        default=None,
        help="Path to Syzkaller coverage SQLite database (optional)",
    )
    ap.add_argument("--file", "-f", help="Kernel source file (e.g. mm/shmem.c)")
    ap.add_argument(
        "--line", "-l", type=int, help="Line number within the kernel source file"
    )
    ap.add_argument(
        "--function", "-fn", help="Direct function name to analyze reachability for"
    )
    ap.add_argument(
        "--syscall",
        "-s",
        help="Target a specific syscall (e.g. memfd_create or __do_sys_keyctl)",
    )
    ap.add_argument(
        "--max-depth",
        type=int,
        default=25,
        help="Maximum call graph traversal depth (default: 25)",
    )
    ap.add_argument(
        "--all-syscalls",
        "-a",
        action="store_true",
        help="Evaluate all reachable syscalls and report privilege per syscall",
    )
    ap.add_argument(
        "--limit-syscalls",
        type=int,
        default=5,
        help="Maximum number of syscall paths to compute when --all-syscalls is set (default: 5)",
    )
    ap.add_argument(
        "--format",
        choices=["summary", "tree", "paths", "json"],
        default="summary",
        help="Output format: summary, tree, paths, json (default: summary)",
    )
    ap.add_argument(
        "--ensure-indexes",
        action="store_true",
        help="Ensure fast SQLite indexes exist on the database and exit",
    )
    ap.add_argument(
        "--verbose", "-v", action="store_true", help="Print debug information"
    )

    args = ap.parse_args()

    if not os.path.isfile(args.db):
        sys.exit(f"Error: Database file not found: {args.db}")

    if args.syzkaller_db and not os.path.isfile(args.syzkaller_db):
        sys.exit(f"Error: Syzkaller database file not found: {args.syzkaller_db}")

    if args.ensure_indexes:
        conn = sqlite3.connect(args.db)
        ensure_indexes(conn, verbose=True)
        conn.close()
        print("Indexes verified successfully.")
        return

    is_function_entry = False
    if args.function and not args.file:
        conn = sqlite3.connect(args.db)
        cur = conn.cursor()
        cur.execute(
            "SELECT file_path, start_line FROM function_locations WHERE function_name = ? LIMIT 1",
            (args.function,),
        )
        row = cur.fetchone()
        conn.close()
        if not row:
            sys.exit(
                f"Error: Function '{args.function}' not found in function_locations table."
            )
        args.file = row[0]
        if args.line is None:
            args.line = row[1]
            is_function_entry = True

    if not args.file or args.line is None:
        ap.print_help()
        sys.exit("\nError: Please provide either (--file AND --line) or --function.")

    try:
        target_info, overall_verdict, primary_result, all_results = (
            analyze_target_privilege(
                args.db,
                args.file,
                args.line,
                target_syscall=args.syscall,
                syzkaller_db=args.syzkaller_db,
                all_syscalls=args.all_syscalls,
                limit_syscalls=args.limit_syscalls,
                max_depth=args.max_depth,
                is_function_entry=is_function_entry,
                verbose=args.verbose,
            )
        )
    except Exception as e:
        sys.exit(f"Error: {e}")

    if args.format == "summary":
        print(
            format_summary(
                target_info, overall_verdict, primary_result, all_results
            )
        )
    elif args.format == "tree":
        print(format_tree(target_info, primary_result, all_results))
    elif args.format == "paths":
        print(format_paths(primary_result, all_results))
    elif args.format == "json":
        data = {
            "target": target_info,
            "overall_verdict": overall_verdict,
            "primary_result": primary_result,
            "all_results": all_results,
        }
        print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()

