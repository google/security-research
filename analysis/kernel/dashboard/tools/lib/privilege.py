#!/usr/bin/env python3
"""Condition-gate, capability-map, entry-precondition, and tunable utilities."""

import sqlite3
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

from tools.lib.callgraph import (
    LOCATION_RE,
    SpanFuncList,
    clean_file_path,
    load_functions_for_files,
    table_exists,
)

GateDict = Dict[str, Any]
GateList = List[GateDict]
CallGateMap = Dict[Tuple[str, int], GateList]
FuncGateMap = Dict[str, GateList]

# Cost model for Dijkstra path finding (favoring unprivileged/ungated paths)
COST_UNGATED = 1
COST_INDIRECT_ENTRY = 500
COST_NS_CAPABLE = 10_000
COST_PHYSICAL = 500_000
COST_CAPABLE = 1_000_000


def format_capability(
    c_type: str, arg: str, cap_map: Optional[Dict[str, str]] = None
) -> str:
    """Format capability check name, e.g. capable(CAP_SYS_ADMIN)."""
    if cap_map and str(arg) in cap_map:
        cap_name = cap_map[str(arg)]
    elif str(arg).isdigit():
        cap_name = f"CAP_{arg}"
    else:
        cap_name = str(arg)
    return f"{c_type}({cap_name})"


def deduplicate_gates(gates: GateList) -> GateList:
    """Deduplicate gates, preferring concrete capability checks over 'cap'."""
    if not gates:
        return []
    has_concrete = any(
        g["type"] == "capable" and g["argument"] not in ("cap", "cap_setid")
        for g in gates
    )
    seen: Dict[Tuple[str, str, str], GateDict] = {}
    for g in gates:
        if (
            has_concrete
            and g["type"] == "ns_capable"
            and g["argument"] in ("cap", "cap_setid")
        ):
            continue
        loc = (
            g.get("condition")
            or g.get("definition")
            or g.get("call_location")
            or ""
        )
        key = (g["type"], g["argument"], loc)
        if key in seen:
            if g.get("ns_scope") and not seen[key].get("ns_scope"):
                seen[key] = dict(seen[key], ns_scope=g["ns_scope"])
            prev_max = seen[key].get("max_controlled_line")
            curr_max = g.get("max_controlled_line")
            if prev_max is not None and curr_max is not None:
                seen[key]["max_controlled_line"] = max(prev_max, curr_max)
        else:
            seen[key] = dict(g)
    return list(seen.values())


def add_call_span(
    span_map: CallGateMap, call_loc: Optional[str], item: GateDict
) -> Optional[Tuple[str, int]]:
    """Register item across all lines in call_loc and return (file, end)."""
    m = LOCATION_RE.match(call_loc) if call_loc else None
    if not m:
        return None
    f_clean = clean_file_path(m.group(1))
    s_idx, e_idx = int(m.group(2)), int(m.group(4))
    for l in range(s_idx, e_idx + 1):
        span_map.setdefault((f_clean, l), []).append(item)
    return f_clean, e_idx


def _load_cap_macro_invocations(
    cur: sqlite3.Cursor,
) -> Dict[Tuple[str, int], List[str]]:
    """Load CAP_* macro invocations indexed by (clean_file_path, line)."""
    cur.execute(
        "SELECT macroinvocation_name, file_path, start_line"
        " FROM macroinvocation_locations"
        " WHERE macroinvocation_name LIKE 'CAP_%'"
    )
    macro_invs: Dict[Tuple[str, int], List[str]] = {}
    for m_name, f_path, s_line in cur.fetchall():
        macro_invs.setdefault((clean_file_path(f_path), s_line), []).append(
            m_name
        )
    return macro_invs


def load_capability_map(conn: sqlite3.Connection) -> Dict[str, str]:
    """Extract capability number-to-name mapping directly from the database."""
    cur = conn.cursor()
    if not table_exists(cur, "macroinvocation_locations"):
        return {}

    try:
        macro_invs = _load_cap_macro_invocations(cur)
        cur.execute(
            "SELECT argument, definition FROM conditions"
            " WHERE type IN ('capable', 'ns_capable')"
            " AND argument NOT IN ('cap', 'cap_setid')"
        )
        counts: Dict[str, Dict[str, int]] = {}
        for arg, def_loc in cur.fetchall():
            m = LOCATION_RE.match(def_loc) if str(arg).isdigit() else None
            if m:
                key = (clean_file_path(m.group(1)), int(m.group(2)))
                for name in macro_invs.get(key, []):
                    counts.setdefault(arg, {}).setdefault(name, 0)
                    counts[arg][name] += 1

        return {
            arg: max(name_counts.items(), key=lambda x: x[1])[0]
            for arg, name_counts in counts.items()
        }
    except sqlite3.Error:
        return {}


def _extract_ns_scope(call_name: Optional[str]) -> Optional[str]:
    """Extract namespace scope tag from synthetic span/genl call markers."""
    if not call_name:
        return None
    for prefix in ("__guarded_span__:", "__genl_ops_gate__:"):
        if call_name.startswith(prefix):
            return call_name[len(prefix) :].strip() or None
    return None


def _compute_controlled_end(
    gate: GateDict,
    def_line: int,
    e_line: int,
    cond_max_line: Dict[Tuple[str, str, str], int],
    has_guarded_spans: bool,
) -> int:
    """Compute maximum line controlled by a function-level capability gate."""
    if (gate.get("call") or "").startswith("__genl_ops_gate__"):
        return e_line
    mc = LOCATION_RE.match(gate["condition"]) if gate.get("condition") else None
    cond_end = int(mc.group(4)) if mc else def_line
    key = (
        gate["type"],
        str(gate["argument"]),
        gate.get("condition") or gate.get("definition") or "",
    )
    max_ctrl = cond_max_line.get(key)
    if has_guarded_spans and max_ctrl is not None:
        return max_ctrl
    if max_ctrl is not None and max_ctrl <= cond_end:
        return cond_end
    return e_line


def _attach_function_gates(
    condition_records: GateList,
    file_funcs: Dict[str, SpanFuncList],
    cond_max_line: Dict[Tuple[str, str, str], int],
    has_guarded_spans: bool,
) -> FuncGateMap:
    """Associate capability condition records with enclosing functions."""
    func_gates: FuncGateMap = {}
    for g in condition_records:
        call_name = g.get("call") or ""
        loc_str = (
            g.get("call_location")
            if call_name.startswith("__genl_ops_gate__")
            else (g.get("definition") or g.get("condition"))
        )
        m = LOCATION_RE.match(loc_str) if loc_str else None
        if not m:
            continue
        f_clean, def_line = clean_file_path(m.group(1)), int(m.group(2))
        for fn_name, s_line, e_line in file_funcs.get(f_clean, []):
            if s_line <= def_line <= e_line:
                fg = dict(
                    g,
                    func_file=f_clean,
                    check_line=def_line,
                    fn_span=(s_line, e_line),
                    max_controlled_line=_compute_controlled_end(
                        g, def_line, e_line, cond_max_line, has_guarded_spans
                    ),
                )
                func_gates.setdefault(fn_name, []).append(fg)

    return {fn: deduplicate_gates(vals) for fn, vals in func_gates.items()}


def _make_condition_gate(
    row: Tuple[str, str, str, str, str, str], cap_map: Optional[Dict[str, str]]
) -> GateDict:
    """Build a condition or tunable gate dictionary from a database row."""
    c_type, arg, call_loc, def_loc, cond_loc, call_name = row
    cap_str = (
        format_capability(c_type, arg, cap_map=cap_map)
        if c_type in ("capable", "ns_capable")
        else f"{c_type}({arg})"
    )
    gate_obj: GateDict = {
        "type": c_type,
        "argument": arg,
        "cap_str": cap_str,
        "call": call_name,
        "call_location": call_loc,
        "definition": def_loc,
        "condition": cond_loc,
    }
    ns_scope = _extract_ns_scope(call_name)
    if ns_scope:
        gate_obj["ns_scope"] = ns_scope
    return gate_obj


def _parse_condition_gate_rows(
    rows: List[Tuple[str, str, str, str, str, str]], cap_map: Dict[str, str]
) -> Tuple[
    CallGateMap, Set[str], GateList, Dict[Tuple[str, str, str], int], bool
]:
    """Parse condition rows into call-site gates and function-gate metadata."""
    call_gates: CallGateMap = {}
    def_files: Set[str] = set()
    records: GateList = []
    cond_max_line: Dict[Tuple[str, str, str], int] = {}
    has_guarded_spans = False

    for row in rows:
        gate_obj = _make_condition_gate(row, cap_map)
        if (gate_obj.get("call") or "").startswith("__guarded_span__"):
            has_guarded_spans = True
        records.append(gate_obj)

        span_res = add_call_span(call_gates, row[2], gate_obj)
        if span_res:
            def_files.add(span_res[0])
            key = (row[0], str(row[1]), row[4] or row[3] or "")
            cond_max_line[key] = max(cond_max_line.get(key, 0), span_res[1])

        for loc_str in (row[3], row[4]):
            m_loc = LOCATION_RE.match(loc_str) if loc_str else None
            if m_loc:
                def_files.add(clean_file_path(m_loc.group(1)))

    call_gates = {k: deduplicate_gates(v) for k, v in call_gates.items()}
    return call_gates, def_files, records, cond_max_line, has_guarded_spans


def load_condition_gates(
    conn: sqlite3.Connection, verbose: bool = False
) -> Tuple[CallGateMap, FuncGateMap, Dict[str, str]]:
    """Load capability condition gates from the DB into lookup structures."""
    cur = conn.cursor()
    if not table_exists(cur, "conditions"):
        return {}, {}, {}

    cap_map = load_capability_map(conn)
    cur.execute(
        "SELECT type, argument, call_location, definition, condition, call"
        " FROM conditions WHERE type IN ('capable', 'ns_capable')"
    )
    call_gates, def_files, records, cond_max_line, has_spans = (
        _parse_condition_gate_rows(cur.fetchall(), cap_map)
    )
    file_funcs = load_functions_for_files(conn, def_files)
    func_gates = _attach_function_gates(
        records, file_funcs, cond_max_line, has_spans
    )

    if verbose:
        print(
            f"Loaded {len(call_gates)} call-site gates and {len(func_gates)}"
            f" function-level gates ({len(cap_map)} capability names mapped).",
            file=sys.stderr,
        )
    return call_gates, func_gates, cap_map


def get_call_site_gates(
    call_gates: CallGateMap,
    func_gates: FuncGateMap,
    file_path: str,
    line_number: Optional[int],
    caller_fn: Optional[str] = None,
) -> GateList:
    """Retrieve capability gates applying to a specific line or call site."""
    if line_number is None:
        return []
    f_clean = clean_file_path(file_path)
    gates = list(call_gates.get((f_clean, line_number), []))
    if caller_fn and caller_fn in func_gates:
        for fg in func_gates[caller_fn]:
            fg_file = fg.get("func_file")
            if fg_file and fg_file != f_clean:
                continue
            check_line = fg.get("check_line", 0)
            max_line = fg.get("max_controlled_line")
            if line_number >= check_line and (
                max_line is None or line_number <= max_line
            ):
                gates.append(fg)
    return deduplicate_gates(gates)


def _parse_tunable_rows(
    rows: List[Tuple[str, str, str, str, str, str]],
) -> Tuple[CallGateMap, Set[str], List[Tuple[GateDict, str, int]]]:
    """Parse sysctl and module_param condition rows into span and file maps."""
    call_tunables: CallGateMap = {}
    cond_files: Set[str] = set()
    records: List[Tuple[GateDict, str, int]] = []
    for row in rows:
        tun_obj = _make_condition_gate(row, None)
        add_call_span(call_tunables, row[2], tun_obj)
        m_cond = LOCATION_RE.match(row[4]) if row[4] else None
        if m_cond:
            f_cond = clean_file_path(m_cond.group(1))
            cond_files.add(f_cond)
            records.append((tun_obj, f_cond, int(m_cond.group(2))))
    return call_tunables, cond_files, records


def load_runtime_tunables(
    conn: sqlite3.Connection,
) -> Tuple[CallGateMap, FuncGateMap]:
    """Load sysctl and module_param guards from conditions table."""
    cur = conn.cursor()
    if not table_exists(cur, "conditions"):
        return {}, {}

    cur.execute(
        "SELECT type, argument, call_location, definition, condition, call"
        " FROM conditions WHERE type IN ('sysctl', 'module_param')"
        " AND argument != '__this_module'"
    )
    call_tunables, cond_files, records = _parse_tunable_rows(cur.fetchall())
    file_funcs = load_functions_for_files(conn, cond_files)
    func_tunables: FuncGateMap = {}
    for tun, f_clean, cond_line in records:
        for fn_name, s_line, e_line in file_funcs.get(f_clean, []):
            if s_line <= cond_line <= e_line:
                ft = dict(
                    tun,
                    func_file=f_clean,
                    check_line=cond_line,
                    fn_span=(s_line, e_line),
                )
                func_tunables.setdefault(fn_name, []).append(ft)

    return (
        {k: deduplicate_gates(v) for k, v in call_tunables.items()},
        {k: deduplicate_gates(v) for k, v in func_tunables.items()},
    )


def _make_baseline_gate(entry_name: str, cap: str, call_desc: str) -> GateDict:
    """Create a synthetic baseline capability gate for a gated entry root."""
    loc = f"entry_baseline:{entry_name}"
    return {
        "type": "capable",
        "argument": cap,
        "cap_str": f"capable({cap})",
        "call": call_desc,
        "call_location": loc,
        "definition": loc,
        "condition": loc,
    }


def get_entry_precondition(
    entry_name: str, entry_kind: str = "syscall"
) -> Dict[str, Any]:
    """Return 2D entry precondition metadata for an entry root."""
    pre: Dict[str, Any] = {
        "entry_kind": entry_kind,
        "attacker_position": "local, unprivileged",
        "trigger_directness": "direct",
        "baseline_cost": 0,
        "baseline_gate": None,
        "entry_note": "",
    }
    if entry_kind == "net_rx":
        if entry_name == "packet_rcv":
            pre.update({
                "attacker_position": "local, CAP_NET_RAW",
                "baseline_cost": COST_CAPABLE,
                "baseline_gate": _make_baseline_gate(
                    "packet_rcv",
                    "CAP_NET_RAW",
                    "packet_create (entry baseline)",
                ),
                "entry_note": (
                    "AF_PACKET RX handler (socket creation gated by"
                    " ns_capable/capable(CAP_NET_RAW))"
                ),
            })
        else:
            pre.update({
                "attacker_position": "remote, unauthenticated",
                "entry_note": (
                    "Network RX handler (remote / unauthenticated packet"
                    " delivery)"
                ),
            })
    elif entry_kind in ("vfs_writeback", "vfs_reclaim"):
        pre.update({
            "trigger_directness": "indirect",
            "baseline_cost": COST_INDIRECT_ENTRY,
            "entry_note": (
                "Indirect kernel-thread trigger (dirty-page writeback or"
                " memory pressure)"
            ),
        })
    elif entry_kind == "bpf_entry":
        pre.update({
            "attacker_position": "local, CAP_BPF (default)",
            "baseline_cost": COST_CAPABLE,
            "baseline_gate": _make_baseline_gate(
                entry_name, "CAP_BPF", "sys_bpf (entry baseline)"
            ),
            "entry_note": (
                "BPF helper/kfunc (requires BPF program load;"
                " CAP_BPF/CAP_SYS_ADMIN when"
                " kernel.unprivileged_bpf_disabled != 0, plus"
                " per-program-type BPF verifier helper/kfunc allowlist)"
            ),
        })
    elif entry_kind == "device_usb":
        pre.update({
            "attacker_position": "physical / malicious-device",
            "baseline_cost": COST_PHYSICAL,
            "entry_note": (
                "USB driver probe/disconnect (requires physical USB / BadUSB /"
                " usbip / gadget access)"
            ),
        })
    return pre


def classify_gates(
    gates: GateList,
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

    root_caps = [
        format_capability(g["type"], g["argument"], cap_map=cap_map)
        for g in gates
        if g["type"] == "capable"
    ]
    if root_caps:
        return f"REACHABLE, BUT ONLY BEHIND {root_caps[0]}"

    return "REACHABLE WITH NO PRIVILEGE (UNGATED)"


def _attacker_position_rank(pos: Optional[str]) -> int:
    """Rank attacker position severity (remote < local < physical)."""
    if not pos:
        return 1
    if pos.startswith("remote"):
        return 0
    if pos.startswith("physical"):
        return 2
    return 1


def verdict_rank(res: Dict[str, Any]) -> Tuple[int, int, int, int]:
    """Rank a path result by privilege tier, position, directness, length."""
    v = res.get("verdict") or ""
    pos_rank = _attacker_position_rank(res.get("attacker_position"))
    direct_rank = 0 if res.get("trigger_directness") != "indirect" else 1
    plen = len(res.get("path", []))
    if v == "REACHABLE WITH NO PRIVILEGE (UNGATED)":
        return (0, pos_rank, direct_rank, plen)
    if v == "REACHABLE BEHIND USER NAMESPACE CAPABILITY":
        return (1, pos_rank, direct_rank, plen)
    if v == "REACHABLE VIA PHYSICAL DEVICE (USB)":
        return (2, pos_rank, direct_rank, plen)
    if v.startswith("REACHABLE, BUT ONLY BEHIND") and "CAP_SYS_ADMIN" not in v:
        return (3, pos_rank, direct_rank, plen)
    if "CAP_SYS_ADMIN" in v:
        return (4, pos_rank, direct_rank, plen)
    return (5, pos_rank, direct_rank, plen)
