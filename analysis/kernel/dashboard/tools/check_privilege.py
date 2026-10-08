#!/usr/bin/env python3
"""Gating-Aware Privilege and Attack-Surface Reachability Analysis.

Answers the fundamental security triage question:
"Is this line reachable from an unprivileged user?"

Crosses static callgraph paths from userspace syscall entry points with CodeQL
condition dominator tables (capable, ns_capable) to determine whether every path
passes through a capability gate, or if an ungated route exists.
"""

import argparse
import heapq
import json
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

from tools.lib.callgraph import (
    format_root_label,
    format_target_banner,
    is_entry_root,
    is_syscall_root,
    iter_pruned_callers,
    load_entry_roots,
    load_target_reachable_set,
    open_databases,
    select_eval_roots,
)
from tools.lib.metadata import (
    add_common_cli_args,
    build_target_info,
    extract_reachability_cli_kwargs,
    get_kconfig_metadata,
    handle_common_cli_setup,
    make_caller_step,
    make_path_step,
)
from tools.lib.privilege import (
    COST_CAPABLE,
    COST_INDIRECT_ENTRY,
    COST_NS_CAPABLE,
    COST_PHYSICAL,
    COST_UNGATED,
    GateList,
    classify_gates,
    deduplicate_gates,
    format_capability,
    get_call_site_gates,
    get_entry_precondition,
    load_capability_map,
    load_condition_gates,
    load_runtime_tunables,
)

__all__ = [
    "COST_UNGATED",
    "COST_INDIRECT_ENTRY",
    "COST_NS_CAPABLE",
    "COST_PHYSICAL",
    "COST_CAPABLE",
    "load_capability_map",
    "format_capability",
    "deduplicate_gates",
    "load_condition_gates",
    "get_call_site_gates",
    "load_runtime_tunables",
    "get_entry_precondition",
    "find_best_privilege_path",
    "classify_gates",
    "analyze_target_privilege",
    "format_summary",
    "format_tree",
    "format_paths",
    "main",
]

_NS_SCOPE_HINTS = {
    "init_user_ns": "init_user_ns (global root)",
    "net_ns": "net->user_ns (CLONE_NEWUSER + CLONE_NEWNET)",
    "s_user_ns": (
        "sb->s_user_ns (CLONE_NEWUSER + CLONE_NEWNS / FS_USERNS_MOUNT)"
    ),
    "mnt_ns": "mnt_ns->user_ns (CLONE_NEWUSER + CLONE_NEWNS)",
    "f_cred": "file->f_cred->user_ns (CLONE_NEWUSER)",
    "user_ns": "user_ns (CLONE_NEWUSER)",
}


def _collect_path_preconditions(
    path: List[Dict[str, Any]],
) -> Tuple[List[str], GateList]:
    """Collect deduplicated CONFIG_* and runtime tunables across a path."""
    seen_cfgs: Set[str] = set()
    cfgs: List[str] = []
    tuns: GateList = []
    for step in path:
        for c in step.get("configs", []):
            if c not in seen_cfgs:
                seen_cfgs.add(c)
                cfgs.append(c)
        tuns.extend(step.get("tunables", []))
    return cfgs, deduplicate_gates(tuns)


def _finalize_root_path(
    root_fn: str,
    entry_kind: str,
    path: List[Dict[str, Any]],
    cap_map: Optional[Dict[str, str]],
) -> Tuple[str, GateList, List[Dict[str, Any]]]:
    """Attach 2D entry metadata and baseline gates to a completed root path."""
    pre = get_entry_precondition(root_fn, entry_kind)
    path_copy = [dict(s) for s in path]
    path_copy[0].update({
        "entry_kind": entry_kind,
        "attacker_position": pre["attacker_position"],
        "trigger_directness": pre["trigger_directness"],
        "entry_note": pre["entry_note"],
    })
    if pre["baseline_gate"] is not None:
        root_gates = list(path_copy[0].get("gates", [])) + [
            pre["baseline_gate"]
        ]
        path_copy[0]["gates"] = deduplicate_gates(root_gates)

    all_path_gates: GateList = []
    for step in path_copy:
        all_path_gates.extend(step.get("gates", []))
    all_path_gates = deduplicate_gates(all_path_gates)
    verdict = classify_gates(
        all_path_gates, cap_map=cap_map, entry_kind=entry_kind
    )
    return verdict, all_path_gates, path_copy


def _build_result_record(
    sc: str,
    verdict: Optional[str],
    gates: GateList,
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


def _gate_cost(gates: GateList, base_cost: int = 0) -> int:
    """Calculate Dijkstra cost contribution for a list of capability gates."""
    cost = base_cost
    for g in gates:
        if g["type"] == "capable":
            cost += COST_CAPABLE
        elif g["type"] == "ns_capable":
            cost += COST_NS_CAPABLE
    return cost


def _relax_privilege_callers(
    conn: sqlite3.Connection,
    state: Tuple[int, int, str, List[Dict[str, Any]]],
    ctx: Dict[str, Any],
) -> None:
    """Relax incoming caller edges during Dijkstra privilege path search."""
    cost, hops, curr_fn, path = state
    callers = iter_pruned_callers(
        conn, curr_fn, ctx["reachable_set"], allow_prune=(cost == 0)
    )
    for caller in callers:
        caller_fn = caller[0]
        edge_gates = get_call_site_gates(
            ctx["call_gates"],
            ctx["func_gates"],
            caller[1],
            caller[3],
            caller_fn=caller_fn,
        )
        new_cost = cost + _gate_cost(edge_gates, base_cost=COST_UNGATED)
        if new_cost < ctx["best_dist"].get(caller_fn, float("inf")):
            ctx["best_dist"][caller_fn] = new_cost
            ctx["counter"] += 1
            edge_tuns = get_call_site_gates(
                ctx["call_tunables"],
                ctx["func_tunables"],
                caller[1],
                caller[3],
                caller_fn=caller_fn,
            )
            step = make_caller_step(
                conn,
                ctx["syzk_conn"],
                caller,
                gates=edge_gates,
                tunables=edge_tuns,
            )
            heapq.heappush(
                ctx["pq"],
                (
                    new_cost,
                    hops + 1,
                    ctx["counter"],
                    caller_fn,
                    caller[1],
                    [step] + path,
                ),
            )


def _init_privilege_search(
    conn: sqlite3.Connection,
    target_fn: str,
    target_file: str,
    target_line: int,
    options: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Initialize start step and Dijkstra search context for privilege path."""
    call_gates = options.get("call_gates", {})
    func_gates = options.get("func_gates", {})
    call_tunables = options.get("call_tunables") or {}
    func_tunables = options.get("func_tunables") or {}
    syzk_conn = options.get("syzk_conn")

    target_gates = get_call_site_gates(
        call_gates, func_gates, target_file, target_line, caller_fn=target_fn
    )
    target_tunables = get_call_site_gates(
        call_tunables,
        func_tunables,
        target_file,
        target_line,
        caller_fn=target_fn,
    )
    init_cost = _gate_cost(target_gates, base_cost=0)
    start_step = make_path_step(
        conn,
        syzk_conn,
        target_fn,
        target_file,
        target_line,
        gates=target_gates,
        tunables=target_tunables,
    )
    ctx: Dict[str, Any] = {
        "call_gates": call_gates,
        "func_gates": func_gates,
        "call_tunables": call_tunables,
        "func_tunables": func_tunables,
        "cap_map": options.get("cap_map"),
        "target_syscall": options.get("target_syscall"),
        "entry_roots": load_entry_roots(conn),
        "reachable_set": load_target_reachable_set(
            conn, options.get("target_syscall")
        ),
        "syzk_conn": syzk_conn,
        "best_dist": {target_fn: float(init_cost)},
        "pq": [(init_cost, 0, 0, target_fn, target_file, [start_step])],
        "counter": 0,
    }
    return start_step, ctx


def find_best_privilege_path(
    conn: sqlite3.Connection,
    target_fn: str,
    target_file: str,
    target_line: int,
    **options: Any,
) -> Tuple[Optional[str], GateList, Optional[List[Dict[str, Any]]]]:
    """Search for optimal path from syscalls or entries to target_fn:line."""
    start_step, ctx = _init_privilege_search(
        conn, target_fn, target_file, target_line, options
    )
    if is_syscall_root(target_fn, ctx["target_syscall"]):
        return _finalize_root_path(
            target_fn, "syscall", [start_step], ctx["cap_map"]
        )

    while ctx["pq"]:
        cost, hops, _, curr_fn, curr_file, path = heapq.heappop(ctx["pq"])
        if curr_fn == "__TERMINAL__":
            return _finalize_root_path(
                path[0]["function"], curr_file, path, ctx["cap_map"]
            )
        if cost > ctx["best_dist"].get(curr_fn, float("inf")):
            continue
        if is_syscall_root(curr_fn, ctx["target_syscall"]):
            return _finalize_root_path(curr_fn, "syscall", path, ctx["cap_map"])

        entry_kind = is_entry_root(
            curr_fn, ctx["target_syscall"], ctx["entry_roots"]
        )
        if entry_kind:
            base_cost = get_entry_precondition(curr_fn, entry_kind)[
                "baseline_cost"
            ]
            if base_cost == 0:
                return _finalize_root_path(
                    curr_fn, entry_kind, path, ctx["cap_map"]
                )
            term_cost = cost + base_cost
            if term_cost < ctx["best_dist"].get("__TERMINAL__", float("inf")):
                ctx["best_dist"]["__TERMINAL__"] = term_cost
                ctx["counter"] += 1
                heapq.heappush(
                    ctx["pq"],
                    (
                        term_cost,
                        hops,
                        ctx["counter"],
                        "__TERMINAL__",
                        entry_kind,
                        path,
                    ),
                )

        if hops < options.get("max_depth", 25):
            _relax_privilege_callers(conn, (cost, hops, curr_fn, path), ctx)

    return None, [], None


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


def _evaluate_privilege_roots(
    conn: sqlite3.Connection,
    syzk_conn: Optional[sqlite3.Connection],
    target_info: Dict[str, Any],
    gate_opts: Dict[str, Any],
    **options: Any,
) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """Run Dijkstra privilege path search across selected candidate roots."""
    eval_roots = select_eval_roots(target_info, **options)
    all_results: List[Dict[str, Any]] = []
    for sc in eval_roots if eval_roots is not None else [None]:
        verdict, gates, path = find_best_privilege_path(
            conn,
            target_info["function"],
            target_info["file"],
            target_info["line"],
            target_syscall=sc,
            syzk_conn=syzk_conn,
            max_depth=options.get("max_depth", 25),
            **gate_opts,
        )
        if path:
            root_name = sc if sc is not None else path[0]["function"]
            all_results.append(
                _build_result_record(root_name, verdict, gates, path)
            )

    if not all_results:
        return "UNREACHABLE", {}, []
    primary = min(all_results, key=_verdict_rank)
    return primary["verdict"] or "UNREACHABLE", primary, all_results


def _load_all_target_gates(
    conn: sqlite3.Connection, target_info: Dict[str, Any], verbose: bool
) -> Dict[str, Any]:
    """Load condition gates and runtime tunables and attach internal gates."""
    call_gates, func_gates, cap_map = load_condition_gates(
        conn, verbose=verbose
    )
    call_tunables, func_tunables = load_runtime_tunables(conn)
    fn_name = target_info["function"]
    target_info["internal_gates"] = func_gates.get(fn_name, [])
    target_info["internal_tunables"] = func_tunables.get(fn_name, [])
    return {
        "call_gates": call_gates,
        "func_gates": func_gates,
        "cap_map": cap_map,
        "call_tunables": call_tunables,
        "func_tunables": func_tunables,
    }


def analyze_target_privilege(
    db_file: str,
    file_path: str,
    line_number: int,
    **options: Any,
) -> Tuple[Dict[str, Any], str, Dict[str, Any], List[Dict[str, Any]]]:
    """Main programmatic interface for privilege reachability analysis."""
    conn, syzk_conn = open_databases(
        db_file,
        syzkaller_db=options.get("syzkaller_db"),
        verbose=options.get("verbose", False),
    )
    target_info = build_target_info(
        conn,
        syzk_conn,
        file_path,
        line_number,
        is_function_entry=options.get("is_function_entry", False),
    )
    target_syscall = options.get("target_syscall")

    if (
        not target_info["all_syscalls"]
        and not target_info["all_entries"]
        and not is_syscall_root(target_info["function"], target_syscall)
        and not is_entry_root(
            target_info["function"], target_syscall, load_entry_roots(conn)
        )
    ):
        conn.close()
        if syzk_conn:
            syzk_conn.close()
        return target_info, "UNREACHABLE", {}, []

    gate_opts = _load_all_target_gates(
        conn, target_info, options.get("verbose", False)
    )
    overall_verdict, primary_result, all_results = _evaluate_privilege_roots(
        conn, syzk_conn, target_info, gate_opts, **options
    )

    all_cfg_exprs = list(target_info["configs"])
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
        out.append("\nRuntime Tunable Preconditions (sysctl / module_param):")
        for t in path_tuns:
            t_loc = t.get("condition") or t.get("definition") or "unknown"
            out.append(f"  * {t['cap_str']} at {t_loc}")


def _format_ns_scope_hint(ns_scope: Optional[str]) -> str:
    """Format a human-readable namespace scope hint for a capability gate."""
    if not ns_scope:
        return ""
    return f" [scope: {_NS_SCOPE_HINTS.get(ns_scope, ns_scope)}]"


def _format_verdict_details(overall_verdict: str) -> List[str]:
    """Return 3-line privilege, gating, and scope summary for a verdict."""
    if overall_verdict == "REACHABLE WITH NO PRIVILEGE (UNGATED)":
        return [
            "Privilege Level: Unprivileged (No capabilities required)",
            "Gating Status:   Ungated route available from userspace",
            (
                "Access Scope:    Reachable via standard userspace system calls"
                " without special privileges."
            ),
        ]
    if overall_verdict == "REACHABLE BEHIND USER NAMESPACE CAPABILITY":
        return [
            "Privilege Level: User Namespace Capability (e.g. ns_capable)",
            "Gating Status:   Gated by user namespace capability check",
            (
                "Access Scope:    Reachable within user namespaces (e.g. via"
                " CLONE_NEWUSER / unshare -U)."
            ),
        ]
    if overall_verdict == "REACHABLE VIA PHYSICAL DEVICE (USB)":
        return [
            "Privilege Level: Physical / Malicious USB Device",
            "Gating Status:   Reachable from USB driver probe/disconnect",
            (
                "Access Scope:    Requires physical USB / BadUSB / usbip /"
                " gadget attachment."
            ),
        ]
    if "CAP_SYS_ADMIN" in overall_verdict:
        return [
            "Privilege Level: Privileged Root (CAP_SYS_ADMIN in init_user_ns)",
            "Gating Status:   All paths pass through capable(CAP_SYS_ADMIN)",
            (
                "Access Scope:    Requires administrative privilege in initial"
                " namespace."
            ),
        ]
    if overall_verdict.startswith("REACHABLE, BUT ONLY BEHIND"):
        return [
            "Privilege Level: Privileged Capability Required",
            f"Gating Status:   {overall_verdict}",
            "Access Scope:    Requires capability in initial namespace.",
        ]
    return [
        "Privilege Level: Unreachable",
        "Gating Status:   No callgraph paths from userspace syscalls",
        "Access Scope:    Kernel-internal or boot execution only.",
    ]


def _format_summary_header(
    target_info: Dict[str, Any],
    overall_verdict: str,
    primary_result: Dict[str, Any],
) -> List[str]:
    """Format header and verdict metadata block for format_summary."""
    out = [
        "=" * 72,
        "TARGET PRIVILEGE & ATTACK-SURFACE ANALYSIS",
        "=" * 72,
        *format_target_banner(target_info),
    ]
    all_sc = target_info.get("all_syscalls", [])
    sc_preview = ", ".join(all_sc[:5]) + ("..." if len(all_sc) > 5 else "")
    out.append(f"Reachable Syscalls: {len(all_sc)} syscall(s) ({sc_preview})")

    all_entries = target_info.get("all_entries", [])
    if all_entries:
        ent_preview = ", ".join(
            f"{e['entry_kind']}:{e['entry']}" for e in all_entries[:5]
        ) + ("..." if len(all_entries) > 5 else "")
        out.append(
            f"Reachable Non-Syscall Entries: {len(all_entries)} root(s)"
            f" ({ent_preview})"
        )

    out.extend(["-" * 72, f"VERDICT: {overall_verdict}", "-" * 72])
    out.extend(_format_verdict_details(overall_verdict))

    if primary_result:
        ekind = primary_result.get("entry_kind", "syscall")
        apos = primary_result.get("attacker_position", "local, unprivileged")
        tdir = primary_result.get("trigger_directness", "direct")
        out.append(f"Entry Surface:   {ekind} ({apos}; trigger: {tdir})")
        if primary_result.get("entry_note"):
            out.append(f"Entry Note:      {primary_result['entry_note']}")
        out.append(
            "Caveat:          Minimum precondition to reach (attack-surface"
            " floor), not exploitability."
        )
    return out


def _format_syzkaller_section(syzk: Dict[str, Any], out: List[str]) -> None:
    """Append Syzkaller fuzzer status section to summary output lines."""
    if not syzk.get("configured"):
        return
    out.append("-" * 72)
    if syzk.get("line_covered"):
        hit_sys = ", ".join(syzk.get("syscalls", [])) or "unknown"
        out.extend([
            (
                "Dynamic Fuzzer Status (Syzkaller): COVERED (Executed via:"
                f" {hit_sys})"
            ),
            (
                "Classification: FULLY PROVEN (Static Call Path + Live Fuzzer"
                " Execution)"
            ),
        ])
    elif syzk.get("fn_covered"):
        out.append(
            "Dynamic Fuzzer Status (Syzkaller): PARTIALLY COVERED"
            f" ({syzk.get('fn_covered_lines')} lines in function executed)"
        )
    else:
        out.append(
            "Dynamic Fuzzer Status (Syzkaller): UNCOVERED (0 live executions"
            " recorded)"
        )


def _format_internal_gates_section(
    target_info: Dict[str, Any], out: List[str]
) -> None:
    """Append internal function capability gates section to summary lines."""
    internal_gates = target_info.get("internal_gates", [])
    if not internal_gates:
        return
    out.extend(["-" * 72, "Internal Function Capability Gates:"])
    seen_ig: Set[str] = set()
    for ig in internal_gates:
        c_line = ig.get("check_line", "unknown")
        c_loc = ig.get("definition") or f"line {c_line}"
        scope_str = _format_ns_scope_hint(ig.get("ns_scope"))
        bullet = f"  * {ig['cap_str']} at {c_loc}{scope_str}"
        if bullet not in seen_ig:
            seen_ig.add(bullet)
            out.append(bullet)
    first_gate_line = min(
        (ig.get("check_line", 0) for ig in internal_gates), default=0
    )
    if (
        target_info.get("is_function_entry")
        and first_gate_line > target_info["line"]
    ):
        out.append(
            f"  (Note: Function entry at line {target_info['line']} is"
            " ungated; internal capability check applies starting at line"
            f" {first_gate_line})"
        )


def _format_step_gate_tags(step: Dict[str, Any]) -> str:
    """Format [GATED/UNGATED], [Kconfig], and [Tunable] tags for a step."""
    gates = step.get("gates", [])
    gate_tag = (
        f" [GATED: {', '.join(g['cap_str'] for g in gates)}]"
        if gates
        else " [UNGATED]"
    )
    step_cfgs = step.get("configs", [])
    cfg_tag = f" [Kconfig: {', '.join(step_cfgs)}]" if step_cfgs else ""
    step_tuns = step.get("tunables", [])
    tun_tag = (
        f" [Tunable: {', '.join(t['cap_str'] for t in step_tuns)}]"
        if step_tuns
        else ""
    )
    return f"{gate_tag}{cfg_tag}{tun_tag}"


def _format_priv_step(
    step: Dict[str, Any],
    idx: int,
    total_steps: int,
    indent_offset: int = 0,
    call_prefix: str = "line ",
) -> str:
    """Format a single call-path step with gate, Kconfig, and tunable tags."""
    indent = "  " * (idx + indent_offset)
    loc = f"{step['function']} ({step['file']}:{step['line']})"
    tags = _format_step_gate_tags(step)
    if idx == 0:
        return f"{indent}└── {format_root_label(step)} {loc}{tags}"
    if idx == total_steps - 1:
        pad = "   " if indent_offset else " "
        return f"{indent}└── [Target Line]{pad}{loc}{tags}"
    cs = step.get("call_site_line")
    call_info = f" [calls at {call_prefix}{cs}]" if cs else ""
    return f"{indent}└── {loc}{call_info}{tags}"


def _format_optimal_path_section(
    target_info: Dict[str, Any], primary_result: Dict[str, Any], out: List[str]
) -> None:
    """Append Optimal Call Path, Gate Details, and Kconfig/Tunable sections."""
    path = primary_result["path"]
    sc = primary_result.get("syscall", "unknown")
    out.extend(["-" * 72, f"Optimal Call Path (via {sc}):"])
    for i, step in enumerate(path):
        out.append(
            _format_priv_step(
                step, i, len(path), indent_offset=1, call_prefix="line "
            )
        )

    all_gates = primary_result.get("gates", [])
    if all_gates:
        out.append("\nGate Details:")
        seen_gd: Set[str] = set()
        for g in all_gates:
            c_loc = g.get("definition") or g.get("call_location") or "unknown"
            scope_str = _format_ns_scope_hint(g.get("ns_scope"))
            bullet = f"  * {g['cap_str']} at {c_loc}{scope_str}"
            if bullet not in seen_gd:
                seen_gd.add(bullet)
                out.append(bullet)
    else:
        out.append("\nGate Details: None (All steps completely ungated)")
    _format_kconfig_section(target_info, primary_result, out)


def format_summary(
    target_info: Dict[str, Any],
    overall_verdict: str,
    primary_result: Dict[str, Any],
    all_results: List[Dict[str, Any]],
) -> str:
    """Format human-readable privilege and gating reachability report."""
    out = _format_summary_header(target_info, overall_verdict, primary_result)
    _format_syzkaller_section(target_info.get("syzkaller", {}), out)
    _format_internal_gates_section(target_info, out)

    if primary_result and primary_result.get("path"):
        _format_optimal_path_section(target_info, primary_result, out)
    elif target_info.get("configs") or target_info.get("internal_tunables"):
        out.append("-" * 72)
        _format_kconfig_section(target_info, primary_result, out)

    if len(all_results) > 1:
        out.extend(["-" * 72, "Privilege Breakdown per Syscall:"])
        for r in all_results:
            g_count = len(r.get("gates", []))
            out.append(
                f"  * {r['syscall']:<30}: {r['verdict']} ({g_count} gate(s))"
            )

    out.append("=" * 72)
    return "\n".join(out)


def format_tree(
    target_info: Dict[str, Any],
    primary_result: Dict[str, Any],
    all_results: List[Dict[str, Any]],
) -> str:
    """Format call paths as an indented ASCII tree with gating annotations."""
    out = [
        "=" * 72,
        (
            f"Target: {target_info['file']}:{target_info['line']} in"
            f" {target_info['function']}"
        ),
        "=" * 72,
    ]
    results_to_show = (
        all_results
        if all_results
        else ([primary_result] if primary_result else [])
    )
    for res in results_to_show:
        path = res.get("path", [])
        out.append(
            f"\n[Syscall: {res.get('syscall', 'unknown')} ->"
            f" {res.get('verdict', 'unknown')}]"
        )
        if not path:
            out.append("  (No path found)")
            continue
        for i, step in enumerate(path):
            out.append(
                _format_priv_step(
                    step, i, len(path), indent_offset=0, call_prefix="L"
                )
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
            (
                f"{s['function']}({s['file']}:"
                f"{s.get('call_site_line') or s['line']})"
            )
            + (
                f"[{','.join(g['cap_str'] for g in s['gates'])}]"
                if s.get("gates")
                else ""
            )
            for s in path
        ])
        out.append(f"[{res.get('verdict')}]\n{chain}")
    return "\n\n".join(out)


def main() -> None:
    """CLI entry point for check_privilege."""
    ap = argparse.ArgumentParser(
        description=(
            "Cross syscall reachability with capability condition gates to"
            " determine whether a kernel source line/function is reachable"
            " from unprivileged users."
        )
    )
    add_common_cli_args(ap, include_reachability_flags=True)
    ap.add_argument(
        "--format",
        choices=["summary", "tree", "paths", "json"],
        default="summary",
        help="Output format: summary, tree, paths, json (default: summary)",
    )

    args = ap.parse_args()
    is_function_entry = handle_common_cli_setup(
        args, ap, resolve_function_to_line=True
    )
    if is_function_entry is None:
        return

    try:
        target_info, overall_verdict, primary_result, all_results = (
            analyze_target_privilege(
                args.db,
                args.file,
                args.line,
                **extract_reachability_cli_kwargs(args, is_function_entry),
            )
        )
    except (FileNotFoundError, ValueError, sqlite3.Error, OSError) as e:
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
        print(
            json.dumps(
                {
                    "target": target_info,
                    "overall_verdict": overall_verdict,
                    "primary_result": primary_result,
                    "all_results": all_results,
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
