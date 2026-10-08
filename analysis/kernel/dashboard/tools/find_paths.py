#!/usr/bin/env python3
"""Find call graph paths from userspace syscall entry points to kernel lines.

Uses CodeQL callgraph data in SQLite and optional Syzkaller coverage data.
"""

import argparse
from collections import deque
import json
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

from tools.lib.callgraph import (
    INDEXES,
    clean_file_path,
    ensure_indexes,
    format_root_label,
    format_target_banner,
    get_callers,
    get_enclosing_function,
    get_function_by_name,
    get_reachable_entries,
    get_reachable_syscalls,
    is_entry_root,
    is_syscall_root,
    iter_pruned_callers,
    load_entry_roots,
    load_target_reachable_set,
    open_databases,
    select_eval_roots,
)
from tools.lib.metadata import (
    CONFIG_TOKEN_RE,
    add_common_cli_args,
    build_target_info,
    extract_reachability_cli_kwargs,
    get_kconfig_metadata,
    get_line_configs,
    get_syzkaller_coverage,
    handle_common_cli_setup,
    is_line_covered_by_syzkaller,
    make_caller_step,
    make_path_step,
)

__all__ = [
    "CONFIG_TOKEN_RE",
    "INDEXES",
    "clean_file_path",
    "ensure_indexes",
    "get_enclosing_function",
    "get_function_by_name",
    "get_syzkaller_coverage",
    "is_line_covered_by_syzkaller",
    "get_callers",
    "is_syscall_root",
    "load_entry_roots",
    "is_entry_root",
    "load_target_reachable_set",
    "get_reachable_syscalls",
    "get_reachable_entries",
    "get_line_configs",
    "get_kconfig_metadata",
    "find_shortest_path",
    "format_tree",
    "format_list",
    "format_mermaid",
    "find_paths_to_line",
    "find_paths_to_function_recursive",
    "main",
]


def find_shortest_path(
    conn: sqlite3.Connection,
    target_fn: str,
    target_file: str,
    target_line: int,
    **options: Any,
) -> Optional[List[Dict[str, Any]]]:
    """Perform a backward BFS from target_fn to target_syscall or any root."""
    target_syscall: Optional[str] = options.get("target_syscall")
    syzk_conn: Optional[sqlite3.Connection] = options.get("syzk_conn")
    reachable_set = load_target_reachable_set(conn, target_syscall)
    entry_roots = load_entry_roots(conn)
    queue = deque([(
        target_fn,
        [make_path_step(conn, syzk_conn, target_fn, target_file, target_line)],
    )])
    visited: Set[str] = {target_fn}

    while queue:
        curr_fn, path = queue.popleft()
        if is_syscall_root(curr_fn, target_syscall):
            path[0]["entry_kind"] = "syscall"
            return path
        entry_kind = is_entry_root(curr_fn, target_syscall, entry_roots)
        if entry_kind:
            path[0]["entry_kind"] = entry_kind
            return path
        if len(path) > options.get("max_depth", 25):
            continue

        for caller in iter_pruned_callers(
            conn, curr_fn, reachable_set, exclude=visited
        ):
            if caller[0] not in visited:
                visited.add(caller[0])
                queue.append((
                    caller[0],
                    [make_caller_step(conn, syzk_conn, caller)] + path,
                ))

    return None


def _format_syzkaller_header(
    syzk: Dict[str, Any], target_line: int
) -> List[str]:
    """Format Syzkaller coverage summary lines for the tree report header."""
    if not syzk.get("configured"):
        return ["Dynamic Coverage (Syzkaller): (Database not configured)"]
    if syzk.get("line_covered"):
        hit_sys = ", ".join(syzk.get("syscalls", [])) or "unknown"
        return [
            (
                "Dynamic Coverage (Syzkaller): COVERED (executed via syscalls:"
                f" {hit_sys})"
            ),
            (
                "Classification: FULLY PROVEN (Static Call Path + Live Fuzzer"
                " Execution)"
            ),
        ]
    if syzk.get("fn_covered"):
        fn_lines = syzk.get("fn_covered_lines")
        return [
            (
                f"Dynamic Coverage (Syzkaller): PARTIALLY COVERED ({fn_lines}"
                f" lines in function executed, but line {target_line} unfuzzed)"
            ),
            (
                "Classification: FUZZING GAP (Function hit, but target"
                " branch/line unfuzzed)"
            ),
        ]
    return [
        "Dynamic Coverage (Syzkaller): UNCOVERED (0 live executions recorded)",
        (
            "Classification: ATTACK SURFACE BLIND SPOT (Statically reachable,"
            " but unfuzzed!)"
        ),
    ]


def _format_tree_header(
    target_info: Dict[str, Any],
    paths_by_syscall: Dict[str, List[Dict[str, Any]]],
) -> List[str]:
    """Format target reachability and coverage header block for format_tree."""
    out = ["=" * 70, *format_target_banner(target_info)]
    all_sys = target_info.get("all_syscalls", list(paths_by_syscall.keys()))
    out.append(
        f"Static Reachability (CodeQL): Reachable from {len(all_sys)}"
        f" syscall(s) ({', '.join(all_sys[:5])}"
        f"{'...' if len(all_sys) > 5 else ''})"
    )
    all_entries = target_info.get("all_entries", [])
    if all_entries:
        ent_strs = [f"{e['entry_kind']}:{e['entry']}" for e in all_entries[:5]]
        out.append(
            f"Non-Syscall Entries (CodeQL): Reachable from {len(all_entries)}"
            f" entry root(s) ({', '.join(ent_strs)}"
            f"{'...' if len(all_entries) > 5 else ''})"
        )
    if target_info.get("configs"):
        out.append(
            f"Kernel Configs (Target): {', '.join(target_info['configs'])}"
        )

    syzk = target_info.get("syzkaller", {})
    out.extend(_format_syzkaller_header(syzk, target_info["line"]))
    out.append("=" * 70)
    return out


def _format_tree_step(
    step: Dict[str, Any], idx: int, total_steps: int, syzk_configured: bool
) -> str:
    """Format a single step line in an ASCII call tree."""
    indent = "  " * idx
    loc = f"{step['function']} ({step['file']}:{step['line']})"
    syzk_tag = ""
    if syzk_configured:
        syzk_tag = (
            " [Syzkaller: Covered]"
            if step.get("syzk_covered")
            else " [Static Only]"
        )
    cfg_list = step.get("configs", [])
    cfg_tag = f" [Kconfig: {', '.join(cfg_list)}]" if cfg_list else ""

    ctype = step.get("call_type")
    type_info = f" [{ctype}]" if ctype and ctype != "target" else ""
    if step.get("details"):
        type_info += f" ({step['details']})"

    if idx == 0:
        return f"{indent}└── {format_root_label(step)} {loc}{syzk_tag}{cfg_tag}"
    if idx == total_steps - 1:
        return f"{indent}└── [Target Line] {loc}{type_info}{syzk_tag}{cfg_tag}"
    cs = step.get("call_site_line")
    call_info = f" [calls at line {cs}]" if cs else ""
    return f"{indent}└── {loc}{call_info}{type_info}{syzk_tag}{cfg_tag}"


def format_tree(
    paths_by_syscall: Dict[str, List[Dict[str, Any]]],
    target_info: Dict[str, Any],
    show_repro: bool = False,
) -> str:
    """Format call paths as an indented ASCII tree with annotations."""
    out = _format_tree_header(target_info, paths_by_syscall)
    syzk = target_info.get("syzkaller", {})
    syzk_configured = bool(syzk.get("configured"))

    for syscall, path in paths_by_syscall.items():
        out.append(f"\n[Call Path from {syscall}]")
        if not path:
            out.append("  (No direct callgraph path found within depth limit)")
            continue
        for i, step in enumerate(path):
            out.append(_format_tree_step(step, i, len(path), syzk_configured))

    if show_repro and syzk.get("progs"):
        out.extend([
            "\n" + "-" * 70,
            "Syzkaller Reproduction Program:",
            "-" * 70,
        ])
        prog = syzk["progs"][0]
        out.append(f"// Prog ID: {prog.get('prog_id')}")
        if prog.get("prog_code"):
            out.append(prog["prog_code"].strip())
        out.append("-" * 70)

    return "\n".join(out)


def format_list(paths_by_syscall: Dict[str, List[Dict[str, Any]]]) -> str:
    """Format call paths as arrow-separated chains."""
    out = []
    for _syscall, path in paths_by_syscall.items():
        if not path:
            continue
        chain = " -> ".join([
            f"{s['function']}"
            f" ({s['file']}:{s.get('call_site_line') or s['line']})"
            for s in path
        ])
        out.append(chain)
    return "\n\n".join(out)


def _add_mermaid_edge(
    s_curr: Dict[str, Any],
    s_next: Dict[str, Any],
    seen_edges: Set[Tuple[str, str, str]],
    node_classes: Dict[str, str],
    lines: List[str],
) -> None:
    """Add a single directed call edge to Mermaid lines if not already seen."""
    src_lbl = f"{s_curr['function']}\\n({s_curr['file']}:{s_curr['line']})"
    dst_lbl = f"{s_next['function']}\\n({s_next['file']}:{s_next['line']})"
    edge_lbl = (
        f"calls at L{s_curr['call_site_line']}"
        if s_curr.get("call_site_line")
        else "calls"
    )
    if s_next.get("details"):
        edge_lbl += f" ({s_next['details']})"

    src_id = f"node_{abs(hash(src_lbl)) % 100000}"
    dst_id = f"node_{abs(hash(dst_lbl)) % 100000}"
    node_classes[src_id] = (
        "covered" if s_curr.get("syzk_covered") else "uncovered"
    )
    node_classes[dst_id] = (
        "covered" if s_next.get("syzk_covered") else "uncovered"
    )

    edge_key = (src_lbl, dst_lbl, edge_lbl)
    if edge_key not in seen_edges:
        seen_edges.add(edge_key)
        lines.append(f'    {src_id}["{src_lbl}"]')
        lines.append(f'    {dst_id}["{dst_lbl}"]')
        lines.append(f'    {src_id} -->|"{edge_lbl}"| {dst_id}')


def format_mermaid(
    paths_by_syscall: Dict[str, List[Dict[str, Any]]],
) -> str:
    """Format call paths as a styled Mermaid diagram with coverage coloring."""
    lines = [
        "```mermaid",
        "graph TD",
        (
            "    classDef covered"
            " fill:#d4edda,stroke:#28a745,stroke-width:2px,color:#155724;"
        ),
        (
            "    classDef uncovered"
            " fill:#fff3cd,stroke:#ffc107,stroke-width:2px,color:#856404;"
        ),
    ]
    seen_edges: Set[Tuple[str, str, str]] = set()
    node_classes: Dict[str, str] = {}

    for path in paths_by_syscall.values():
        for i in range(len(path) - 1):
            _add_mermaid_edge(
                path[i], path[i + 1], seen_edges, node_classes, lines
            )

    for nid, cls in node_classes.items():
        lines.append(f"    class {nid} {cls};")
    lines.append("```")
    return "\n".join(lines)


def find_paths_to_line(
    db_file: str,
    file_path: str,
    line_number: int,
    **options: Any,
) -> Tuple[Dict[str, Any], Dict[str, List[Dict[str, Any]]]]:
    """Main programmatic interface to find callgraph paths to a kernel line."""
    conn, syzk_conn = open_databases(
        db_file,
        syzkaller_db=options.get("syzkaller_db"),
        verbose=options.get("verbose", False),
    )
    target_info = build_target_info(conn, syzk_conn, file_path, line_number)
    if not target_info["all_syscalls"] and not target_info["all_entries"]:
        conn.close()
        if syzk_conn:
            syzk_conn.close()
        return target_info, {}

    paths_by_syscall: Dict[str, List[Dict[str, Any]]] = {}
    eval_roots = select_eval_roots(target_info, **options)
    for sc in eval_roots if eval_roots is not None else [None]:
        path = find_shortest_path(
            conn,
            target_info["function"],
            target_info["file"],
            line_number,
            target_syscall=sc,
            syzk_conn=syzk_conn,
            max_depth=options.get("max_depth", 25),
        )
        if path:
            paths_by_syscall[sc or path[0]["function"]] = path

    all_cfg_exprs = list(target_info["configs"])
    for path in paths_by_syscall.values():
        for step in path:
            all_cfg_exprs.extend(step.get("configs", []))
    target_info["kconfig_metadata"] = get_kconfig_metadata(conn, all_cfg_exprs)

    conn.close()
    if syzk_conn:
        syzk_conn.close()
    return target_info, paths_by_syscall


def find_paths_to_function_recursive(
    db_file: str, function: str, max_depth: int = 25
) -> List[List[Tuple[str, str, int]]]:
    """Backwards compatibility interface with original find_paths.py."""
    conn = sqlite3.connect(db_file)
    ensure_indexes(conn)

    fn_row = get_function_by_name(conn, function)
    if not fn_row:
        conn.close()
        return []

    _fn_name, file_path, start_line, _end_line = fn_row
    results = []
    for sc in get_reachable_syscalls(conn, function)[:10]:
        path = find_shortest_path(
            conn,
            function,
            file_path,
            start_line,
            target_syscall=sc,
            max_depth=max_depth,
        )
        if path:
            results.append([
                (node["function"], node["file"], node["line"]) for node in path
            ])

    conn.close()
    return results


def main() -> None:
    """CLI entry point for find_paths."""
    ap = argparse.ArgumentParser(
        description=(
            "Find call graph reachability paths from syscall entry points to"
            " kernel source lines or functions, correlated with Syzkaller"
            " dynamic coverage."
        )
    )
    add_common_cli_args(ap, include_reachability_flags=True)
    ap.add_argument(
        "--show-repro",
        action="store_true",
        help="Display Syzkaller reproduction program code if covered",
    )
    ap.add_argument(
        "--format",
        choices=["tree", "list", "json", "mermaid"],
        default="tree",
        help="Output format (default: tree)",
    )

    args = ap.parse_args()
    if handle_common_cli_setup(args, ap, resolve_function_to_line=True) is None:
        return

    try:
        target_info, paths = find_paths_to_line(
            args.db,
            args.file,
            args.line,
            **extract_reachability_cli_kwargs(args),
        )
    except (FileNotFoundError, ValueError, sqlite3.Error, OSError) as e:
        sys.exit(f"Error: {e}")

    if not paths:
        print(
            f"No reachability path found for {args.file}:{args.line} (Function:"
            f" {target_info.get('function')}).",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.format == "tree":
        print(format_tree(paths, target_info, show_repro=args.show_repro))
    elif args.format == "list":
        print(format_list(paths))
    elif args.format == "json":
        print(json.dumps({"target": target_info, "paths": paths}, indent=2))
    elif args.format == "mermaid":
        print(format_mermaid(paths))


if __name__ == "__main__":
    main()
