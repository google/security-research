#!/usr/bin/env python3
# pylint: disable=duplicate-code,too-many-lines
"""Gating-Aware Privilege and Attack-Surface Reachability Analysis.

Answers the fundamental security triage question:
"Is this line reachable from an unprivileged user?"

Crosses static callgraph paths from userspace syscall entry points with CodeQL
condition dominator tables (capable, ns_capable) to determine whether every path
passes through a capability gate, or if an ungated route exists.

Outputs:
  - "REACHABLE WITH NO PRIVILEGE (UNGATED)"
  - "REACHABLE BEHIND USER NAMESPACE CAPABILITY"
  - "REACHABLE, BUT ONLY BEHIND CAP_SYS_ADMIN"
  - "UNREACHABLE"
"""

import argparse
import heapq
import json
import os
import re
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

# Try importing shared utilities from tools.find_paths or find_paths
try:
    from tools.find_paths import (
        ensure_indexes,
        get_enclosing_function,
        get_kconfig_metadata,
        get_line_configs,
        get_reachable_entries,
        get_reachable_syscalls,
        get_callers,
        is_entry_root,
        is_syscall_root,
        is_line_covered_by_syzkaller,
        get_syzkaller_coverage,
        load_entry_roots,
    )
except ImportError:
    from find_paths import (
        ensure_indexes,
        get_enclosing_function,
        get_kconfig_metadata,
        get_line_configs,
        get_reachable_entries,
        get_reachable_syscalls,
        get_callers,
        is_entry_root,
        is_syscall_root,
        is_line_covered_by_syzkaller,
        get_syzkaller_coverage,
        load_entry_roots,
    )

LOCATION_RE = re.compile(r"^(.+):(\d+):(\d+):(\d+):(\d+)$")

# Cost model for Dijkstra path finding (favoring unprivileged/ungated paths)
COST_UNGATED = 1
COST_INDIRECT_ENTRY = 500
COST_NS_CAPABLE = 10_000
COST_PHYSICAL = 500_000
COST_CAPABLE = 1_000_000


def get_entry_precondition(
    entry_name: str, entry_kind: str = "syscall"
) -> Dict[str, Any]:
    """Return 2D entry precondition metadata for an entry root.

    Dimension 1: attacker_position & baseline cost/gate floor.
    Dimension 2: trigger_directness ('direct' vs 'indirect').
    """
    if entry_kind == "net_rx":
        if entry_name == "packet_rcv":
            return {
                "entry_kind": entry_kind,
                "attacker_position": "local, CAP_NET_RAW",
                "trigger_directness": "direct",
                "baseline_cost": COST_CAPABLE,
                "baseline_gate": {
                    "type": "capable",
                    "argument": "CAP_NET_RAW",
                    "cap_str": "capable(CAP_NET_RAW)",
                    "call": "packet_create (entry baseline)",
                    "call_location": "entry_baseline:packet_rcv",
                    "definition": "entry_baseline:packet_rcv",
                    "condition": "entry_baseline:packet_rcv",
                },
                "entry_note": (
                    "AF_PACKET RX handler (socket creation gated by"
                    " ns_capable/capable(CAP_NET_RAW))"
                ),
            }
        return {
            "entry_kind": entry_kind,
            "attacker_position": "remote, unauthenticated",
            "trigger_directness": "direct",
            "baseline_cost": 0,
            "baseline_gate": None,
            "entry_note": (
                "Network RX handler (remote / unauthenticated packet delivery)"
            ),
        }
    if entry_kind in ("vfs_writeback", "vfs_reclaim"):
        return {
            "entry_kind": entry_kind,
            "attacker_position": "local, unprivileged",
            "trigger_directness": "indirect",
            "baseline_cost": COST_INDIRECT_ENTRY,
            "baseline_gate": None,
            "entry_note": (
                "Indirect kernel-thread trigger (dirty-page writeback or"
                " memory pressure)"
            ),
        }
    if entry_kind == "bpf_entry":
        return {
            "entry_kind": entry_kind,
            "attacker_position": "local, CAP_BPF (default)",
            "trigger_directness": "direct",
            "baseline_cost": COST_CAPABLE,
            "baseline_gate": {
                "type": "capable",
                "argument": "CAP_BPF",
                "cap_str": "capable(CAP_BPF)",
                "call": "sys_bpf (entry baseline)",
                "call_location": f"entry_baseline:{entry_name}",
                "definition": f"entry_baseline:{entry_name}",
                "condition": f"entry_baseline:{entry_name}",
            },
            "entry_note": (
                "BPF helper/kfunc (requires BPF program load;"
                " CAP_BPF/CAP_SYS_ADMIN when"
                " kernel.unprivileged_bpf_disabled != 0)"
            ),
        }
    if entry_kind == "device_usb":
        return {
            "entry_kind": entry_kind,
            "attacker_position": "physical / malicious-device",
            "trigger_directness": "direct",
            "baseline_cost": COST_PHYSICAL,
            "baseline_gate": None,
            "entry_note": (
                "USB driver probe/disconnect (requires physical USB / BadUSB /"
                " usbip / gadget access)"
            ),
        }
    return {
        "entry_kind": entry_kind,
        "attacker_position": "local, unprivileged",
        "trigger_directness": "direct",
        "baseline_cost": 0,
        "baseline_gate": None,
        "entry_note": "",
    }


def clean_file_path(path: str) -> str:
    """Normalize file path by removing leading slashes and linux/ prefixes."""
    return path.lstrip("/").replace("linux/", "")


def load_capability_map(  # pylint: disable=too-many-locals
    conn: sqlite3.Connection,
) -> Dict[str, str]:
    """Extract capability number-to-name mapping directly from the database.

    Correlates condition definitions with macroinvocation_locations in SQLite.
    """
    cur = conn.cursor()
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND"
        " name='macroinvocation_locations'"
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
            WHERE type IN ('capable', 'ns_capable')
              AND argument NOT IN ('cap', 'cap_setid')
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
    """Format capability check name, e.g. capable(CAP_SYS_ADMIN)."""
    cap_name = None
    if cap_map and str(arg) in cap_map:
        cap_name = cap_map[str(arg)]
    elif str(arg).isdigit():
        cap_name = f"CAP_{arg}"
    else:
        cap_name = str(arg)
    return f"{c_type}({cap_name})"


def deduplicate_gates(gates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate gates, preferring concrete capability checks over 'cap'."""
    if not gates:
        return []

    has_concrete_capable = any(
        g["type"] == "capable" and g["argument"] not in ("cap", "cap_setid")
        for g in gates
    )

    filtered = []
    for g in gates:
        # Filter out internal macro expansion ns_capable(cap) when a concrete
        # capable() check exists
        if (
            has_concrete_capable
            and g["type"] == "ns_capable"
            and g["argument"] in ("cap", "cap_setid")
        ):
            continue
        filtered.append(g)

    seen = {}
    for g in filtered:
        loc = (
            g.get("condition")
            or g.get("definition")
            or g.get("call_location")
            or ""
        )
        key = (g["type"], g["argument"], loc)
        seen[key] = g
    return list(seen.values())


def load_condition_gates(  # pylint: disable=too-many-locals,too-many-branches
    conn: sqlite3.Connection, verbose: bool = False
) -> Tuple[
    Dict[Tuple[str, int], List[Dict[str, Any]]],
    Dict[str, List[Dict[str, Any]]],
    Dict[str, str],
]:
    """Load capability condition gates from the DB into lookup structures.

    Returns:
      1. call_gates: (clean_file_path, line) -> list of gate definitions
      2. func_gates: function_name -> list of gate definitions inside function
      3. cap_map: argument -> macro name (e.g. '21' -> 'CAP_SYS_ADMIN')
    """
    cur = conn.cursor()
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND"
        " name='conditions'"
    )
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
            f" function-level gates ({len(cap_map)} capability names mapped).",
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
    """Retrieve all capability gates applying to a specific line or call site.

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


def load_runtime_tunables(  # pylint: disable=too-many-locals,too-many-branches
    conn: sqlite3.Connection,
) -> Tuple[
    Dict[Tuple[str, int], List[Dict[str, Any]]],
    Dict[str, List[Dict[str, Any]]],
]:
    """Load sysctl and module_param guards from conditions table."""
    cur = conn.cursor()
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND"
        " name='conditions'"
    )
    if not cur.fetchone():
        return {}, {}

    cur.execute("""
        SELECT type, argument, call_location, definition, condition, call
        FROM conditions
        WHERE type IN ('sysctl', 'module_param')
          AND argument != '__this_module'
    """)
    rows = cur.fetchall()

    call_tunables: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
    cond_files: Set[str] = set()
    records = []

    for c_type, arg, call_loc, def_loc, cond_loc, call_name in rows:
        tun_obj = {
            "type": c_type,
            "argument": arg,
            "cap_str": f"{c_type}({arg})",
            "call": call_name,
            "call_location": call_loc,
            "definition": def_loc,
            "condition": cond_loc,
        }
        records.append(tun_obj)

        if call_loc:
            m = LOCATION_RE.match(call_loc)
            if m:
                f, s_line, _, e_line, _ = m.groups()
                f_clean = clean_file_path(f)
                for l in range(int(s_line), int(e_line) + 1):
                    call_tunables.setdefault((f_clean, l), []).append(tun_obj)

        if cond_loc:
            m = LOCATION_RE.match(cond_loc)
            if m:
                cond_files.add(clean_file_path(m.group(1)))

    for k, vals in call_tunables.items():
        call_tunables[k] = deduplicate_gates(vals)

    func_tunables: Dict[str, List[Dict[str, Any]]] = {}
    file_list = list(cond_files)
    file_funcs: Dict[str, List[Tuple[str, int, int]]] = {}
    for i in range(0, len(file_list), 500):
        batch = file_list[i : i + 500]
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

    for tun in records:
        cond_loc = tun["condition"]
        if not cond_loc:
            continue
        m = LOCATION_RE.match(cond_loc)
        if not m:
            continue
        f_clean = clean_file_path(m.group(1))
        cond_line = int(m.group(2))
        for fn_name, s_line, e_line in file_funcs.get(f_clean, []):
            if s_line <= cond_line <= e_line:
                ft_obj = dict(tun)
                ft_obj["check_line"] = cond_line
                ft_obj["fn_span"] = (s_line, e_line)
                func_tunables.setdefault(fn_name, []).append(ft_obj)

    for fn, vals in func_tunables.items():
        func_tunables[fn] = deduplicate_gates(vals)

    return call_tunables, func_tunables


def _collect_path_preconditions(
    path: List[Dict[str, Any]],
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """Collect deduplicated CONFIG_* and runtime tunables across a path."""
    seen_cfgs: Set[str] = set()
    cfgs: List[str] = []
    tuns: List[Dict[str, Any]] = []
    for step in path:
        for c in step.get("configs", []):
            if c not in seen_cfgs:
                seen_cfgs.add(c)
                cfgs.append(c)
        for t in step.get("tunables", []):
            tuns.append(t)
    return cfgs, deduplicate_gates(tuns)


def _finalize_root_path(
    root_fn: str,
    entry_kind: str,
    path: List[Dict[str, Any]],
    cap_map: Optional[Dict[str, str]],
) -> Tuple[str, List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Attach 2D entry metadata and baseline gates to a completed root path."""
    pre = get_entry_precondition(root_fn, entry_kind)
    path_copy = [dict(s) for s in path]
    path_copy[0]["entry_kind"] = entry_kind
    path_copy[0]["attacker_position"] = pre["attacker_position"]
    path_copy[0]["trigger_directness"] = pre["trigger_directness"]
    path_copy[0]["entry_note"] = pre["entry_note"]
    root_gates = list(path_copy[0].get("gates", []))
    if pre["baseline_gate"] is not None:
        root_gates.append(pre["baseline_gate"])
        path_copy[0]["gates"] = deduplicate_gates(root_gates)

    all_path_gates = []
    for step in path_copy:
        for g in step.get("gates", []):
            all_path_gates.append(g)
    all_path_gates = deduplicate_gates(all_path_gates)
    verdict = classify_gates(
        all_path_gates, cap_map=cap_map, entry_kind=entry_kind
    )
    return verdict, all_path_gates, path_copy


def _build_result_record(
    sc: str,
    verdict: Optional[str],
    gates: List[Dict[str, Any]],
    path: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build a result dictionary enriched with 2D entry precondition fields."""
    p_cfgs, p_tuns = _collect_path_preconditions(path)
    root_step = path[0]
    ekind = root_step.get("entry_kind", "syscall")
    pre = get_entry_precondition(root_step["function"], ekind)
    return {
        "syscall": sc,
        "entry_kind": ekind,
        "attacker_position": root_step.get(
            "attacker_position", pre["attacker_position"]
        ),
        "trigger_directness": root_step.get(
            "trigger_directness", pre["trigger_directness"]
        ),
        "entry_note": root_step.get("entry_note", pre["entry_note"]),
        "verdict": verdict,
        "gates": gates,
        "configs": p_cfgs,
        "tunables": p_tuns,
        "path": path,
    }


def find_best_privilege_path(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals,too-many-branches,too-many-statements
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
    call_tunables: Optional[Dict[Tuple[str, int], List[Dict[str, Any]]]] = None,
    func_tunables: Optional[Dict[str, List[Dict[str, Any]]]] = None,
) -> Tuple[
    Optional[str], List[Dict[str, Any]], Optional[List[Dict[str, Any]]]
]:
    """Search for optimal path from syscalls/entries to target_fn:target_line.

    Uses Dijkstra search with edge weights:
      - Ungated hop: 1
      - Indirect entry baseline (vfs_writeback / vfs_reclaim): 500
      - ns_capable hop: 10,000
      - Physical USB entry baseline: 500,000
      - capable (root) hop or CAP_BPF/CAP_NET_RAW entry baseline: 1,000,000

    Guarantees finding an ungated path first if one exists, otherwise finds
    minimal capability requirement across all reaching paths.
    """
    cur = conn.cursor()
    reachable_set: Optional[Set[str]] = None
    entry_roots = load_entry_roots(conn)

    if target_syscall:
        cur.execute(
            "SELECT DISTINCT function FROM syscall_node WHERE syscall = ?",
            (target_syscall,),
        )
        reachable_set = {r[0] for r in cur.fetchall()}
        try:
            cur.execute(
                "SELECT DISTINCT function FROM entry_node"
                " WHERE entry = ? OR entry_kind = ?",
                (target_syscall, target_syscall),
            )
            reachable_set.update(r[0] for r in cur.fetchall())
        except sqlite3.Error:
            pass
        reachable_set.add(target_syscall)
        base_name = target_syscall.replace("__do_sys_", "").replace(
            "__se_sys_", ""
        )
        for prefix in ["__do_sys_", "__se_sys_", "__x64_sys_", "__ia32_sys_"]:
            reachable_set.add(f"{prefix}{base_name}")

    # 1. Check if the target line itself is already gated
    target_gates = get_call_site_gates(
        call_gates, func_gates, target_file, target_line, caller_fn=target_fn
    )
    target_tunables = get_call_site_gates(
        call_tunables or {},
        func_tunables or {},
        target_file,
        target_line,
        caller_fn=target_fn,
    )

    init_cost = 0
    for g in target_gates:
        if g["type"] == "capable":
            init_cost += COST_CAPABLE
        elif g["type"] == "ns_capable":
            init_cost += COST_NS_CAPABLE

    target_syzk_cov = is_line_covered_by_syzkaller(
        syzk_conn, target_file, target_line
    )

    start_step = {
        "function": target_fn,
        "file": target_file,
        "line": target_line,
        "call_site_line": None,
        "call_type": "target",
        "details": "",
        "gates": target_gates,
        "configs": get_line_configs(conn, target_file, target_line),
        "tunables": target_tunables,
        "syzk_covered": target_syzk_cov,
    }

    # If the target function itself IS a syscall entry point
    if is_syscall_root(target_fn, target_syscall):
        return _finalize_root_path(target_fn, "syscall", [start_step], cap_map)

    # Priority queue:
    # (cost, hop_count, tie_breaker, curr_fn, curr_file, curr_line, path)
    counter = 0
    pq = [(
        init_cost,
        0,
        counter,
        target_fn,
        target_file,
        target_line,
        [start_step],
    )]
    best_dist: Dict[str, float] = {target_fn: init_cost}

    while pq:
        cost, hops, _, curr_fn, curr_file, _curr_line, path = heapq.heappop(pq)

        if curr_fn == "__TERMINAL__":
            return _finalize_root_path(
                path[0]["function"], curr_file, path, cap_map
            )

        if cost > best_dist.get(curr_fn, float("inf")):
            continue

        if is_syscall_root(curr_fn, target_syscall):
            return _finalize_root_path(curr_fn, "syscall", path, cap_map)

        entry_kind = is_entry_root(curr_fn, target_syscall, entry_roots)
        if entry_kind:
            pre = get_entry_precondition(curr_fn, entry_kind)
            base_cost = pre["baseline_cost"]
            if base_cost == 0:
                return _finalize_root_path(curr_fn, entry_kind, path, cap_map)
            term_cost = cost + base_cost
            if term_cost < best_dist.get("__TERMINAL__", float("inf")):
                best_dist["__TERMINAL__"] = term_cost
                counter += 1
                heapq.heappush(
                    pq,
                    (
                        term_cost,
                        hops,
                        counter,
                        "__TERMINAL__",
                        entry_kind,
                        0,
                        path,
                    ),
                )

        if hops >= max_depth:
            continue

        callers = get_callers(conn, curr_fn)
        has_reachable_caller = reachable_set is not None and any(
            c[0] in reachable_set for c in callers
        )
        can_prune_to_reachable = (
            reachable_set is not None
            and curr_fn in reachable_set
            and has_reachable_caller
            and cost == 0
        )
        for (
            caller_fn,
            caller_file,
            caller_line,
            call_site_line,
            call_type,
            details,
        ) in callers:
            if (
                can_prune_to_reachable
                and caller_fn not in reachable_set
                and call_type not in ("indirect", "async")
            ):
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
                check_line = call_site_line or caller_line
                step_cov = is_line_covered_by_syzkaller(
                    syzk_conn, caller_file, check_line
                )
                edge_tunables = get_call_site_gates(
                    call_tunables or {},
                    func_tunables or {},
                    caller_file,
                    call_site_line,
                    caller_fn=caller_fn,
                )
                step = {
                    "function": caller_fn,
                    "file": caller_file,
                    "line": caller_line,
                    "call_site_line": call_site_line,
                    "call_type": call_type,
                    "details": details,
                    "gates": edge_gates,
                    "configs": get_line_configs(conn, caller_file, check_line),
                    "tunables": edge_tunables,
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
    gates: List[Dict[str, Any]],
    cap_map: Optional[Dict[str, str]] = None,
    entry_kind: str = "syscall",
) -> str:
    """Classify reachability verdict based on capability gates and entry."""
    has_capable = any(g["type"] == "capable" for g in gates)
    has_ns_capable = any(g["type"] == "ns_capable" for g in gates)

    if not has_capable:
        if entry_kind == "device_usb":
            return "REACHABLE VIA PHYSICAL DEVICE (USB)"
        if has_ns_capable:
            return "REACHABLE BEHIND USER NAMESPACE CAPABILITY"
        return "REACHABLE WITH NO PRIVILEGE (UNGATED)"

    # Specific CAP_SYS_ADMIN check
    for g in gates:
        if g["type"] == "capable":
            cap_str = format_capability(
                g["type"], g["argument"], cap_map=cap_map
            )
            if "CAP_SYS_ADMIN" in cap_str or g["argument"] in (
                "21",
                "CAP_SYS_ADMIN",
            ):
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


def _verdict_rank(res: Dict[str, Any]) -> Tuple[int, int, int]:
    """Rank a path result by privilege requirement, directness, and length."""
    v = res.get("verdict", "")
    direct_rank = 0 if res.get("trigger_directness") != "indirect" else 1
    plen = len(res.get("path", []))
    if v == "REACHABLE WITH NO PRIVILEGE (UNGATED)":
        return (0, direct_rank, plen)
    if v == "REACHABLE BEHIND USER NAMESPACE CAPABILITY":
        return (1, direct_rank, plen)
    if v == "REACHABLE VIA PHYSICAL DEVICE (USB)":
        return (2, direct_rank, plen)
    if v.startswith("REACHABLE, BUT ONLY BEHIND") and "CAP_SYS_ADMIN" not in v:
        return (3, direct_rank, plen)
    if "CAP_SYS_ADMIN" in v:
        return (4, direct_rank, plen)
    return (5, direct_rank, plen)


def analyze_target_privilege(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals,too-many-branches,too-many-statements
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
    """Main programmatic interface for privilege reachability analysis.

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
        raise ValueError(
            f"No enclosing function found for {file_path}:{line_number}"
        )

    fn_name, canonical_file, start_line, end_line = fn_info
    reachable_syscalls = get_reachable_syscalls(conn, fn_name)
    reachable_entries = get_reachable_entries(conn, fn_name)
    entry_roots = load_entry_roots(conn)
    syzk_info = get_syzkaller_coverage(
        syzk_conn, canonical_file, line_number, fn_span=(start_line, end_line)
    )
    target_configs = get_line_configs(conn, canonical_file, line_number)

    target_info = {
        "function": fn_name,
        "file": canonical_file,
        "line": line_number,
        "span": (start_line, end_line),
        "is_function_entry": is_function_entry,
        "all_syscalls": reachable_syscalls,
        "all_entries": reachable_entries,
        "configs": target_configs,
        "kconfig_metadata": get_kconfig_metadata(conn, target_configs),
        "syzkaller": syzk_info,
    }

    # If not reachable by any syscall or entry root and not a root itself
    if (
        not reachable_syscalls
        and not reachable_entries
        and not is_syscall_root(fn_name, target_syscall)
        and not is_entry_root(fn_name, target_syscall, entry_roots)
    ):
        conn.close()
        if syzk_conn:
            syzk_conn.close()
        return target_info, "UNREACHABLE", {}, []

    call_gates, func_gates, cap_map = load_condition_gates(
        conn, verbose=verbose
    )
    call_tunables, func_tunables = load_runtime_tunables(conn)
    target_info["internal_gates"] = func_gates.get(fn_name, [])
    target_info["internal_tunables"] = func_tunables.get(fn_name, [])

    all_results = []
    primary_result = {}

    if target_syscall:
        if not target_syscall.startswith(
            "__do_sys_"
        ) and not target_syscall.startswith("__se_sys_"):
            matched = [
                s
                for s in reachable_syscalls
                if s.endswith(f"_{target_syscall}") or s == target_syscall
            ]
            matched_entries = [
                e["entry"]
                for e in reachable_entries
                if target_syscall in {e["entry"], e["entry_kind"]}
            ]
            eval_syscalls = (
                matched + matched_entries
                if (matched or matched_entries)
                else [f"__do_sys_{target_syscall}"]
            )
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
                call_tunables=call_tunables,
                func_tunables=func_tunables,
            )
            if path:
                all_results.append(
                    _build_result_record(sc, verdict, gates, path)
                )

        if all_results:
            primary_result = min(all_results, key=_verdict_rank)
            overall_verdict = primary_result["verdict"]
        else:
            overall_verdict = "UNREACHABLE"

    elif all_syscalls:
        # Check reachable syscalls and non-syscall entries up to limit
        candidates = list(reachable_syscalls) + [
            e["entry"] for e in reachable_entries
        ]
        for sc in candidates[:limit_syscalls]:
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
                call_tunables=call_tunables,
                func_tunables=func_tunables,
            )
            if path:
                all_results.append(
                    _build_result_record(sc, verdict, gates, path)
                )

        if all_results:
            primary_result = min(all_results, key=_verdict_rank)
            overall_verdict = primary_result["verdict"]
        else:
            overall_verdict = "UNREACHABLE"
    else:
        # Global search for lowest-privilege path across ANY syscall or entry
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
            call_tunables=call_tunables,
            func_tunables=func_tunables,
        )
        if path:
            root_sc = path[0]["function"]
            primary_result = _build_result_record(
                root_sc, verdict, gates, path
            )
            all_results = [primary_result]
            overall_verdict = verdict or "UNREACHABLE"
        else:
            overall_verdict = "UNREACHABLE"

    all_cfg_exprs = list(target_configs)
    for res in all_results:
        all_cfg_exprs.extend(res.get("configs", []))
    target_info["kconfig_metadata"] = get_kconfig_metadata(conn, all_cfg_exprs)

    conn.close()
    if syzk_conn:
        syzk_conn.close()

    return target_info, overall_verdict, primary_result, all_results


def _format_kconfig_section(
    target_info: Dict[str, Any], primary_result: Dict[str, Any], out: List[str]
) -> None:
    """Append Kernel Configs and Runtime Tunable sections to summary lines."""
    path_cfgs = primary_result.get("configs") or target_info.get("configs", [])
    kmeta = target_info.get("kconfig_metadata", {})
    if path_cfgs:
        out.append("\nKernel Config Preconditions (CONFIG_*):")
        for cfg_expr in path_cfgs:
            info = kmeta.get(cfg_expr)
            if info:
                details = []
                if info.get("build_val"):
                    details.append(f".config={info['build_val']}")
                if info.get("depends_on"):
                    details.append(f"depends on: {info['depends_on']}")
                suffix = f" ({'; '.join(details)})" if details else ""
                out.append(f"  * {cfg_expr}{suffix}")
            else:
                out.append(f"  * {cfg_expr}")

    path_tuns = primary_result.get("tunables") or target_info.get(
        "internal_tunables", []
    )
    if path_tuns:
        out.append(
            "\nRuntime Tunable Preconditions (sysctl / module_param):"
        )
        for t in path_tuns:
            t_loc = t.get("condition") or t.get("definition") or "unknown"
            out.append(f"  * {t['cap_str']} at {t_loc}")


def format_summary(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
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
    all_entries = target_info.get("all_entries", [])
    if all_entries:
        ent_preview = ", ".join(
            f"{e['entry_kind']}:{e['entry']}" for e in all_entries[:5]
        )
        if len(all_entries) > 5:
            ent_preview += "..."
        out.append(
            f"Reachable Non-Syscall Entries: {len(all_entries)} root(s)"
            f" ({ent_preview})"
        )

    out.append("-" * 72)
    out.append(f"VERDICT: {overall_verdict}")
    out.append("-" * 72)

    if overall_verdict == "REACHABLE WITH NO PRIVILEGE (UNGATED)":
        out.append("Privilege Level: Unprivileged (No capabilities required)")
        out.append("Gating Status:   Ungated route available from userspace")
        out.append(
            "Access Scope:    Reachable via standard userspace system calls"
            " without special privileges."
        )
    elif overall_verdict == "REACHABLE BEHIND USER NAMESPACE CAPABILITY":
        out.append(
            "Privilege Level: User Namespace Capability (e.g. ns_capable)"
        )
        out.append("Gating Status:   Gated by user namespace capability check")
        out.append(
            "Access Scope:    Reachable within user namespaces (e.g. via"
            " CLONE_NEWUSER / unshare -U)."
        )
    elif overall_verdict == "REACHABLE VIA PHYSICAL DEVICE (USB)":
        out.append("Privilege Level: Physical / Malicious USB Device")
        out.append(
            "Gating Status:   Reachable from USB driver probe/disconnect"
        )
        out.append(
            "Access Scope:    Requires physical USB / BadUSB / usbip / gadget"
            " attachment."
        )
    elif "CAP_SYS_ADMIN" in overall_verdict:
        out.append(
            "Privilege Level: Privileged Root (CAP_SYS_ADMIN in init_user_ns)"
        )
        out.append(
            "Gating Status:   All paths pass through capable(CAP_SYS_ADMIN)"
        )
        out.append(
            "Access Scope:    Requires administrative privilege in initial"
            " namespace."
        )
    elif overall_verdict.startswith("REACHABLE, BUT ONLY BEHIND"):
        out.append("Privilege Level: Privileged Capability Required")
        out.append(f"Gating Status:   {overall_verdict}")
        out.append(
            "Access Scope:    Requires capability in initial namespace."
        )
    else:
        out.append("Privilege Level: Unreachable")
        out.append(
            "Gating Status:   No callgraph paths from userspace syscalls"
        )
        out.append("Access Scope:    Kernel-internal or boot execution only.")

    if primary_result:
        ekind = primary_result.get("entry_kind", "syscall")
        apos = primary_result.get("attacker_position", "local, unprivileged")
        tdir = primary_result.get("trigger_directness", "direct")
        out.append(
            f"Entry Surface:   {ekind} ({apos}; trigger: {tdir})"
        )
        if primary_result.get("entry_note"):
            out.append(f"Entry Note:      {primary_result['entry_note']}")
        out.append(
            "Caveat:          Minimum precondition to reach (attack-surface"
            " floor), not exploitability."
        )

    syzk = target_info.get("syzkaller", {})
    if syzk.get("configured"):
        out.append("-" * 72)
        if syzk.get("line_covered"):
            hit_sys = ", ".join(syzk.get("syscalls", [])) or "unknown"
            out.append(
                "Dynamic Fuzzer Status (Syzkaller): COVERED (Executed via:"
                f" {hit_sys})"
            )
            out.append(
                "Classification: FULLY PROVEN (Static Call Path + Live Fuzzer"
                " Execution)"
            )
        elif syzk.get("fn_covered"):
            fn_lines = syzk.get("fn_covered_lines")
            out.append(
                "Dynamic Fuzzer Status (Syzkaller): PARTIALLY COVERED"
                f" ({fn_lines} lines in function executed)"
            )
        else:
            out.append(
                "Dynamic Fuzzer Status (Syzkaller): UNCOVERED (0 live"
                " executions recorded)"
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
                f"  (Note: Function entry at line {target_info['line']} is"
                " ungated; internal capability check applies starting at line"
                f" {first_gate_line})"
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

            step_cfgs = step.get("configs", [])
            cfg_str = (
                f" [Kconfig: {', '.join(step_cfgs)}]" if step_cfgs else ""
            )
            step_tuns = step.get("tunables", [])
            tun_str = (
                f" [Tunable: {', '.join(t['cap_str'] for t in step_tuns)}]"
                if step_tuns
                else ""
            )

            call_info = f" [calls at line {cs}]" if cs else ""
            indent = "  " * (i + 1)

            if i == 0:
                ekind = step.get("entry_kind", "syscall")
                root_lbl = (
                    "[Syscall Entry]"
                    if ekind == "syscall"
                    else f"[Entry: {ekind}]"
                )
                out.append(
                    f"{indent}└── {root_lbl} {fn}"
                    f" ({f}:{l}){gate_str}{cfg_str}{tun_str}"
                )
            elif i == len(path) - 1:
                out.append(
                    f"{indent}└── [Target Line]   {fn}"
                    f" ({f}:{l}){gate_str}{cfg_str}{tun_str}"
                )
            else:
                out.append(
                    f"{indent}└── {fn}"
                    f" ({f}:{l}){call_info}{gate_str}{cfg_str}{tun_str}"
                )

        all_gates = primary_result.get("gates", [])
        if all_gates:
            out.append("\nGate Details:")
            for g in all_gates:
                c_loc = (
                    g.get("definition") or g.get("call_location") or "unknown"
                )
                out.append(f"  * {g['cap_str']} at {c_loc}")
        else:
            out.append("\nGate Details: None (All steps completely ungated)")

        _format_kconfig_section(target_info, primary_result, out)
    elif target_info.get("configs") or target_info.get("internal_tunables"):
        out.append("-" * 72)
        _format_kconfig_section(target_info, primary_result, out)

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


def format_tree(  # pylint: disable=too-many-locals
    target_info: Dict[str, Any],
    primary_result: Dict[str, Any],
    all_results: List[Dict[str, Any]],
) -> str:
    """Format call paths as an indented ASCII tree with gating annotations."""
    out = []
    out.append("=" * 72)
    out.append(
        f"Target: {target_info['file']}:{target_info['line']} in"
        f" {target_info['function']}"
    )
    out.append("=" * 72)

    results_to_show = (
        all_results
        if all_results
        else ([primary_result] if primary_result else [])
    )
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
            step_cfgs = step.get("configs", [])
            cfg_tag = (
                f" [Kconfig: {', '.join(step_cfgs)}]" if step_cfgs else ""
            )
            step_tuns = step.get("tunables", [])
            tun_tag = (
                f" [Tunable: {', '.join(t['cap_str'] for t in step_tuns)}]"
                if step_tuns
                else ""
            )
            call_info = f" [calls at L{cs}]" if cs else ""

            if i == 0:
                ekind = step.get("entry_kind", "syscall")
                root_lbl = (
                    "[Syscall Entry]"
                    if ekind == "syscall"
                    else f"[Entry: {ekind}]"
                )
                out.append(
                    f"{indent}└── {root_lbl} {fn}"
                    f" ({f}:{l}){gate_tag}{cfg_tag}{tun_tag}"
                )
            elif i == len(path) - 1:
                out.append(
                    f"{indent}└── [Target Line] {fn}"
                    f" ({f}:{l}){gate_tag}{cfg_tag}{tun_tag}"
                )
            else:
                out.append(
                    f"{indent}└── {fn}"
                    f" ({f}:{l}){call_info}{gate_tag}{cfg_tag}{tun_tag}"
                )

    return "\n".join(out)


def format_paths(
    primary_result: Dict[str, Any], all_results: List[Dict[str, Any]]
) -> str:
    """Format call paths as arrow-separated chains with gate annotations."""
    out = []
    results_to_show = (
        all_results
        if all_results
        else ([primary_result] if primary_result else [])
    )
    for res in results_to_show:
        path = res.get("path", [])
        if not path:
            continue
        chain = " -> ".join([
            f"{s['function']}"
            f"({s['file']}:{s.get('call_site_line') or s['line']})"
            + (
                f"[{','.join(g['cap_str'] for g in s['gates'])}]"
                if s.get("gates")
                else ""
            )
            for s in path
        ])
        out.append(f"[{res.get('verdict')}]\n{chain}")
    return "\n\n".join(out)


def main() -> None:  # pylint: disable=too-many-statements
    """CLI entry point for check_privilege."""
    ap = argparse.ArgumentParser(
        description=(
            "Cross syscall reachability with capability condition gates to"
            " determine whether a kernel source line/function is reachable"
            " from unprivileged users."
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
    ap.add_argument(
        "--file", "-f", help="Kernel source file (e.g. mm/shmem.c)"
    )
    ap.add_argument(
        "--line",
        "-l",
        type=int,
        help="Line number within the kernel source file",
    )
    ap.add_argument(
        "--function",
        "-fn",
        help="Direct function name to analyze reachability for",
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
        help=(
            "Maximum number of syscall paths to compute when --all-syscalls is"
            " set (default: 5)"
        ),
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
        sys.exit(
            f"Error: Syzkaller database file not found: {args.syzkaller_db}"
        )

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
            "SELECT file_path, start_line FROM function_locations WHERE"
            " function_name = ? LIMIT 1",
            (args.function,),
        )
        row = cur.fetchone()
        conn.close()
        if not row:
            sys.exit(
                f"Error: Function '{args.function}' not found in"
                " function_locations table."
            )
        args.file = row[0]
        if args.line is None:
            args.line = row[1]
            is_function_entry = True

    if not args.file or args.line is None:
        ap.print_help()
        sys.exit(
            "\nError: Please provide either (--file AND --line) or --function."
        )

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
    except Exception as e:  # pylint: disable=broad-exception-caught
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
