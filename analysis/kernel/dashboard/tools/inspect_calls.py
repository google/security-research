#!/usr/bin/env python3
"""1-Hop & Multi-Hop Callgraph Inspector with Indirect Dispatch Resolution.

Answers the fundamental developer questions during bug triage and navigation:
  1. "Who calls this?" (--callers)
     - Discovers direct callers from CodeQL edge graphs.
     - Discovers indirect callers dispatched via function-pointer structs
       (e.g., inode_operations->link) using the precomputed ops_targets table.
  2. "What does this call?" (--callees)
     - Discovers direct function calls made from within the target function.
     - Discovers indirect dispatch sites (e.g. dir->i_op->link) and resolves
       them to candidate implementations.
  3. "Both directions" (--both, default)
     - Provides 360-degree local context around any function or source line.
"""

import argparse
import json
import sqlite3
import sys
from typing import Any, Dict, List, Tuple

from tools.lib.callgraph import (
    clean_file_path,
    ensure_indexes,
    get_enclosing_function,
    get_function_by_name,
    get_functions_by_name,
)
from tools.lib.inspector import (
    build_callee_tree,
    build_caller_tree,
    check_is_syscall_root,
    get_callees_for_function,
    get_callers_for_function,
    inspect_function_calls,
)
from tools.lib.metadata import (
    add_common_cli_args,
    handle_common_cli_setup,
    is_line_covered_by_syzkaller,
    verify_db_and_indexes,
)
from tools.lib.ops import (
    format_ops_text,
    inspect_function_ops,
    inspect_function_ops_with_conn,
    inspect_ops_slot,
    inspect_ops_slot_with_conn,
)
from tools.lib.privilege import (
    get_call_site_gates,
    load_condition_gates,
)

__all__ = [
    "clean_file_path",
    "ensure_indexes",
    "get_enclosing_function",
    "get_function_by_name",
    "get_functions_by_name",
    "is_line_covered_by_syzkaller",
    "check_is_syscall_root",
    "load_condition_gates",
    "get_call_site_gates",
    "get_callers_for_function",
    "build_caller_tree",
    "get_callees_for_function",
    "build_callee_tree",
    "inspect_function_calls",
    "inspect_ops_slot",
    "inspect_ops_slot_with_conn",
    "inspect_function_ops",
    "inspect_function_ops_with_conn",
    "format_ops_text",
    "format_summary",
    "format_list",
    "main",
]


def _item_prefix_and_tags(
    item: Dict[str, Any], fmt_opts: Dict[str, Any]
) -> Tuple[str, str, str]:
    """Return (indent, tree_prefix, gate_and_coverage_tags) for a tree item."""
    indent = "  " * (fmt_opts.get("indent_level", 1) - 1)
    prefix = f"{indent}└── " if fmt_opts.get("is_last") else f"{indent}├── "
    gate_str = (
        f" [GATED: {', '.join(g['cap_str'] for g in item['gates'])}]"
        if item.get("gates")
        else ""
    )
    cov_str = " [COVERED]" if item.get("syzk_covered") else ""
    return indent, prefix, f"{gate_str}{cov_str}"


def _format_caller_item(
    c: Dict[str, Any], out: List[str], **fmt_opts: Any
) -> None:
    """Format single caller entry and any recursive sub-callers."""
    _indent, prefix, tags = _item_prefix_and_tags(c, fmt_opts)
    cs_line = c.get("call_site_line")
    line_str = f" [calls at line {cs_line}]" if cs_line else ""
    type_str = f" [via {c['dispatch']}]" if c.get("dispatch") else " [direct]"
    syscall_str = " [Syscall Entry]" if c.get("is_syscall") else ""

    out.append(
        f"{prefix}{c['caller']} ({c['file']}:{c['line']})"
        f"{line_str}{type_str}{syscall_str}{tags}"
    )

    sub_callers = c.get("callers", [])
    indent_level = fmt_opts.get("indent_level", 1)
    for sub_idx, sub in enumerate(sub_callers):
        _format_caller_item(
            sub,
            out,
            indent_level=indent_level + 1,
            is_last=sub_idx == len(sub_callers) - 1,
            candidate_limit=fmt_opts.get("candidate_limit", 10),
            show_all=fmt_opts.get("show_all", False),
        )


def _format_indirect_callee(
    c: Dict[str, Any], out: List[str], fmt_opts: Dict[str, Any]
) -> None:
    """Format an indirect dispatch callee site and its candidate targets."""
    indent, prefix, tags = _item_prefix_and_tags(c, fmt_opts)
    cs_line = c.get("call_site_line", "?")
    disp = c.get("dispatch", "indirect dispatch")
    candidates = c.get("candidates", [])
    out.append(
        f"{prefix}[Line {cs_line}] ->{disp} [indirect dispatch:"
        f" {len(candidates)} candidate(s)]{tags}"
    )
    limit = fmt_opts.get("candidate_limit", 10)
    show_all = fmt_opts.get("show_all", False)
    display_cands = candidates if show_all else candidates[:limit]
    sub_indent = indent + ("    " if fmt_opts.get("is_last") else "│   ") + "  "
    for cand in display_cands:
        out.append(
            f"{sub_indent}* {cand['target']} ({cand['file']}:{cand['line']})"
        )
    if not show_all and len(candidates) > limit:
        rem = len(candidates) - limit
        out.append(
            f"{sub_indent}... and {rem} more candidate(s) (use --all to show"
            " all)"
        )


def _format_callee_item(
    c: Dict[str, Any], out: List[str], **fmt_opts: Any
) -> None:
    """Format single callee site (direct, async, or indirect dispatch site)."""
    if c["call_type"] == "indirect":
        _format_indirect_callee(c, out, fmt_opts)
        return

    _indent, prefix, tags = _item_prefix_and_tags(c, fmt_opts)
    cs_line = c.get("call_site_line", "?")
    async_str = (
        f" [async via {c['dispatch']}]"
        if c["call_type"] == "async" and c.get("dispatch")
        else ""
    )
    out.append(
        f"{prefix}[Line {cs_line}] {c['callee']}"
        f" ({c['file']}:{c['line']}){async_str}{tags}"
    )
    sub_callees = c.get("callees", [])
    indent_level = fmt_opts.get("indent_level", 1)
    for sub_idx, sub in enumerate(sub_callees):
        _format_callee_item(
            sub,
            out,
            indent_level=indent_level + 1,
            is_last=sub_idx == len(sub_callees) - 1,
            candidate_limit=fmt_opts.get("candidate_limit", 10),
            show_all=fmt_opts.get("show_all", False),
        )


def _format_callers_section(
    callers: List[Dict[str, Any]], out: List[str], **fmt_opts: Any
) -> None:
    """Append incoming callers section to summary report lines."""
    direct_callers = [c for c in callers if c.get("call_type") == "direct"]
    indirect_callers = [c for c in callers if c.get("call_type") == "indirect"]
    async_callers = [c for c in callers if c.get("call_type") == "async"]
    async_hdr = f" | Async: {len(async_callers)}" if async_callers else ""
    out.extend([
        "-" * 72,
        (
            f"INCOMING CALLERS (Total: {len(callers)} |"
            f" Direct: {len(direct_callers)} |"
            f" Indirect: {len(indirect_callers)}{async_hdr}):"
        ),
        "-" * 72,
    ])
    if not callers:
        out.append(
            "  (No callers found in database - possible top-level entry,"
            " syscall root, or dead code)"
        )
        return

    if direct_callers:
        out.append("Direct Callers:")
        for idx, c in enumerate(direct_callers):
            _format_caller_item(
                c,
                out,
                indent_level=1,
                is_last=idx == len(direct_callers) - 1,
                **fmt_opts,
            )

    if indirect_callers:
        if direct_callers:
            out.append("")
        out.append("Indirect Dispatchers (via ops_targets):")
        for idx, c in enumerate(indirect_callers):
            _format_caller_item(
                c,
                out,
                indent_level=1,
                is_last=idx == len(indirect_callers) - 1,
                **fmt_opts,
            )

    if async_callers:
        if direct_callers or indirect_callers:
            out.append("")
        out.append("Async Dispatchers (via async_edges):")
        for idx, c in enumerate(async_callers):
            _format_caller_item(
                c,
                out,
                indent_level=1,
                is_last=idx == len(async_callers) - 1,
                **fmt_opts,
            )


def _format_callees_section(
    callees: List[Dict[str, Any]], out: List[str], **fmt_opts: Any
) -> None:
    """Append outgoing callees section to summary report lines."""
    direct_callees = [c for c in callees if c.get("call_type") == "direct"]
    indirect_callees = [c for c in callees if c.get("call_type") == "indirect"]
    async_callees = [c for c in callees if c.get("call_type") == "async"]
    async_hdr = f" | Async: {len(async_callees)}" if async_callees else ""
    out.extend([
        "-" * 72,
        (
            f"OUTGOING CALLEES (Total Call Sites: {len(callees)} |"
            f" Direct: {len(direct_callees)} |"
            f" Indirect Sites: {len(indirect_callees)}{async_hdr}):"
        ),
        "-" * 72,
    ])
    if not callees:
        out.append("  (No outgoing function calls found within function body)")
        return

    for idx, c in enumerate(callees):
        _format_callee_item(
            c,
            out,
            indent_level=1,
            is_last=idx == len(callees) - 1,
            **fmt_opts,
        )


def _format_ops_registrations_section(
    registrations: List[Dict[str, Any]], out: List[str]
) -> None:
    """Append ops table registrations, acquisition gates, and siblings."""
    if not registrations:
        return
    out.extend([
        "-" * 72,
        f"OPS TABLE REGISTRATIONS & SIBLINGS (Total: {len(registrations)}):",
        "-" * 72,
    ])
    for reg in registrations:
        out.append(
            f"  * {reg['struct']}.{reg['field']}"
            f" [Definition: {reg['definition']}]"
        )
        acq = reg.get("acquisition_gates", [])
        if acq:
            g_str = ", ".join(
                f"{g['cap_str']}" + (f" via {g['via']}" if g.get("via") else "")
                for g in acq
            )
            out.append(f"    Acquisition Gate(s): {g_str}")
        sibs = reg.get("siblings", [])
        if sibs:
            sib_str = ", ".join(f".{s['field']}={s['target']}" for s in sibs)
            out.append(f"    Sibling Callbacks  : {sib_str}")


def format_summary(
    target_info: Dict[str, Any],
    callers: List[Dict[str, Any]],
    callees: List[Dict[str, Any]],
    **options: Any,
) -> str:
    """Format human-readable caller/callee inspection report."""
    s, e = target_info["start_line"], target_info["end_line"]
    out = [
        "=" * 72,
        f"FUNCTION CALL INSPECTION: '{target_info['function']}'",
        "=" * 72,
        f"Location: {target_info['file']}:{s} - {e} (lines {s}-{e})",
    ]
    fmt_opts = {
        "candidate_limit": options.get("candidate_limit", 10),
        "show_all": options.get("show_all", False),
    }
    if options.get("show_callers", True):
        _format_callers_section(callers, out, **fmt_opts)
        _format_ops_registrations_section(
            target_info.get("ops_registrations", []), out
        )
    if options.get("show_callees", True):
        _format_callees_section(callees, out, **fmt_opts)

    out.append("=" * 72)
    return "\n".join(out)


def _emit_flat_callers(
    caller_list: List[Dict[str, Any]],
    target_name: str,
    has_multihop: bool,
    out: List[str],
) -> None:
    """Recursively append flat caller lines to out."""
    for c in caller_list:
        depth = c.get("depth", 1)
        c_type, c_fn, c_file = c["call_type"], c["caller"], c["file"]
        cs = c.get("call_site_line") or c["line"]
        disp = f" via {c['dispatch']}" if c.get("dispatch") else ""
        depth_prefix = f"[hop {depth}] " if has_multihop else ""
        out.append(
            f"CALLER {depth_prefix}[{c_type:<8}] {c_fn:<30}"
            f" ({c_file}:{cs}){disp} -> {target_name}"
        )
        if c.get("callers"):
            _emit_flat_callers(c["callers"], c_fn, has_multihop, out)


def _emit_flat_callees(
    callee_list: List[Dict[str, Any]],
    caller_name: str,
    has_multihop: bool,
    out: List[str],
) -> None:
    """Recursively append flat callee lines to out."""
    for c in callee_list:
        depth = c.get("depth", 1)
        cs = c.get("call_site_line", 0)
        depth_prefix = f"[hop {depth}] " if has_multihop else ""
        if c["call_type"] == "direct":
            callee_fn = c["callee"]
            out.append(
                f"CALLEE {depth_prefix}[direct  ] {caller_name}"
                f" (line {cs}) -> {callee_fn} ({c['file']}:{c['line']})"
            )
            if c.get("callees"):
                _emit_flat_callees(c["callees"], callee_fn, has_multihop, out)
        elif c["call_type"] == "async":
            callee_fn = c["callee"]
            disp = f" via {c['dispatch']}" if c.get("dispatch") else ""
            out.append(
                f"CALLEE {depth_prefix}[async   ] {caller_name}"
                f" (line {cs}) -> {callee_fn} ({c['file']}:{c['line']}){disp}"
            )
            if c.get("callees"):
                _emit_flat_callees(c["callees"], callee_fn, has_multihop, out)
        else:
            disp = c.get("dispatch", "")
            for cand in c.get("candidates", []):
                out.append(
                    f"CALLEE {depth_prefix}[indirect] {caller_name}"
                    f" (line {cs}) -> {disp} -> {cand['target']}"
                    f" ({cand['file']}:{cand['line']})"
                )


def format_list(
    target_info: Dict[str, Any],
    callers: List[Dict[str, Any]],
    callees: List[Dict[str, Any]],
    **options: Any,
) -> str:
    """Format flat list of caller and callee relationships across all depths."""
    out: List[str] = []
    root_fn = target_info["function"]
    has_multihop = (
        options.get("max_depth", 1) > 1
        or any(c.get("callers") for c in callers)
        or any(c.get("callees") for c in callees)
    )
    if options.get("show_callers", True):
        _emit_flat_callers(callers, root_fn, has_multihop, out)
    if options.get("show_callees", True):
        _emit_flat_callees(callees, root_fn, has_multihop, out)
    return "\n".join(out)


def _build_arg_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser for inspect_calls."""
    parser = argparse.ArgumentParser(
        description=(
            "Inspect 1-hop and multi-hop function callers, callees, indirect"
            " ops_targets dispatch tables, and async_edges registrations."
        )
    )
    add_common_cli_args(parser, include_reachability_flags=False)
    parser.add_argument(
        "--struct",
        "-s",
        help="Operations struct name to inspect (e.g. file_operations)",
    )
    parser.add_argument(
        "--field",
        help="Operations struct field/slot name (e.g. read, unlocked_ioctl)",
    )
    parser.add_argument(
        "--no-gates",
        action="store_true",
        help="Skip .open / .proc_open acquisition gate resolution",
    )
    parser.add_argument(
        "--callers",
        action="store_true",
        help="Inspect callers (who calls this function?)",
    )
    parser.add_argument(
        "--callees",
        action="store_true",
        help="Inspect callees (what does this function call?)",
    )
    parser.add_argument(
        "--both",
        action="store_true",
        help="Inspect both callers and callees (default)",
    )
    parser.add_argument(
        "--depth",
        "-d",
        type=int,
        default=1,
        help="Call hierarchy traversal depth (default: 1)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help=(
            "Maximum indirect candidates to display per dispatch site"
            " (default: 10)"
        ),
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Show all indirect candidates without truncation",
    )
    parser.add_argument(
        "--format",
        choices=["summary", "tree", "list", "text", "json"],
        default="summary",
        help="Output format: summary, tree, list, json (default: summary)",
    )
    return parser


def _run_struct_mode(args: argparse.Namespace) -> None:
    """Execute forward ops-struct slot inspection mode."""
    if not verify_db_and_indexes(args):
        return
    try:
        payload = inspect_ops_slot(
            args.db,
            args.struct,
            field_name=args.field,
            file_path=args.file,
            syzkaller_db=args.syzkaller_db,
            include_gates=not args.no_gates,
            limit=0 if args.all else args.limit,
            verbose=args.verbose,
        )
    except (FileNotFoundError, ValueError, sqlite3.Error, OSError) as exc:
        sys.exit(f"Error: {exc}")
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        print(format_ops_text(payload))


def main() -> None:
    """CLI entry point for inspect_calls."""
    parser = _build_arg_parser()
    args = parser.parse_args()
    if args.struct:
        _run_struct_mode(args)
        return
    if args.field:
        sys.exit("Error: --field requires --struct <ops_struct_name>.")

    if (
        handle_common_cli_setup(args, parser, resolve_function_to_line=False)
        is None
    ):
        return

    if not args.function and not (args.file and args.line is not None):
        parser.print_help()
        sys.exit(
            "\nError: Please specify target with --function <name>,"
            " (--file <path> --line <number>), or --struct <ops_struct>."
        )

    show_callers = args.callers
    show_callees = args.callees
    if (not show_callers and not show_callees) or args.both:
        show_callers = True
        show_callees = True

    try:
        target_info, callers, callees = inspect_function_calls(
            args.db,
            function_name=args.function,
            file_path=args.file,
            line_number=args.line,
            syzkaller_db=args.syzkaller_db,
            depth=args.depth,
            show_callers=show_callers,
            show_callees=show_callees,
            allow_ambiguous=getattr(args, "allow_ambiguous", False),
            verbose=args.verbose,
        )
    except (FileNotFoundError, ValueError, sqlite3.Error, OSError) as e:
        sys.exit(f"Error: {e}")

    if args.format in ("summary", "tree", "text"):
        print(
            format_summary(
                target_info,
                callers,
                callees,
                show_callers=show_callers,
                show_callees=show_callees,
                candidate_limit=args.limit,
                show_all=args.all,
            )
        )
    elif args.format == "list":
        print(
            format_list(
                target_info,
                callers,
                callees,
                show_callers=show_callers,
                show_callees=show_callees,
                max_depth=args.depth,
            )
        )
    elif args.format == "json":
        print(
            json.dumps(
                {
                    "target": target_info,
                    "callers": callers,
                    "callees": callees,
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
