# BTF Struct & Field Layout Extractor (`data/btf_data/`)

[`extract_btf.py`](extract_btf.py) extracts ground-truth C struct and union layouts from a compiled Linux kernel `vmlinux` ELF64 image and flattens them into the `types` SQLite table.

---

## 1. End-to-End Processing Pipeline

```text
vmlinux (ELF64)
  │
  ├─► has_btf_section(vmlinux)?
  │     ├── YES (.BTF section present) ────────────────────────┐
  │     └── NO  (DWARF only) ──► pahole --btf_encode_detached ─┤
  │                                                            ▼
  │                                      bpftool btf dump --json file <src>
  │                                                            │
  ▼                                                            ▼
Raw BTF Type Graph (JSON) ──► create_types_table() ──► BtfExpandContext.expand_members()
                                                               │
                                                               ▼
                                                 SQLite `types` Table (btf.db)
```

1. **ELF64 & `.BTF` Inspection (`vmlinux()`, `has_btf_section()`)**:
   - Validates that the input file is an ELF64 executable (`EI_MAG0..3 == \x7fELF`, `EI_CLASS == 2`).
   - Checks ELF section headers via `elftools` for an embedded `.BTF` section (`CONFIG_DEBUG_INFO_BTF=y`).
2. **BTF JSON Extraction (`dump_btf_json()`)**:
   - If `.BTF` is present, runs `bpftool btf dump --json file <vmlinux>` directly.
   - If `.BTF` is absent, first generates detached BTF from DWARF debug info via `pahole --btf_encode_detached <tmp> <vmlinux>` and then dumps JSON via `bpftool`.
3. **Recursive Struct Flattening (`create_types_table()`, `BtfExpandContext`, `get_shallow()`)**:
   - Indexes all BTF nodes by integer `id` (`types_by_id = {t["id"]: t for t in json_data["types"]}`).
   - Iterates over every top-level `STRUCT` node and recursively flattens its `members` into leaf rows.

---

## 2. How BTF Graph Nodes Are Converted to SQLite Rows

In raw `bpftool` JSON, C types are represented as a directed graph of integer `type_id` references rather than flat type strings. [`extract_btf.py`](extract_btf.py) resolves these chains using four rules:

### 2.1 Peeling Type Modifiers & Typedefs (`peel_type_modifiers`, `resolve_typedef`)
BTF represents qualifiers (`const`, `volatile`, `restrict`, and `__rcu`/`__user` `TYPE_TAG` attributes) and `typedef` aliases as intermediate wrapper nodes:
- **`resolve_typedef(types, tid)`**: Follows `TYPEDEF` chains (`atomic_t` $\rightarrow$ `struct { int counter; }`) while collecting the alias name (`typedef atomic_t`).
- **`peel_type_modifiers(types, tid)`**: Walks through `CONST`, `VOLATILE`, `RESTRICT`, and `TYPE_TAG` nodes to reach the underlying target `type_id`, collecting prefix qualifiers (e.g., `const type_tag("__rcu")`).

### 2.2 Recursive Anonymous & Nested Struct/Union Flattening (`process_struct_or_union_type`)
Kernel structs frequently embed anonymous unions/structs (such as `struct callback_head` or `union { ... }`). When `get_shallow()` encounters a `STRUCT` or `UNION` member:
- **Path Qualification**: Appends the member name to `prefix` (`prefix.member_name`) if named, or preserves the current `prefix` if the inner struct/union is anonymous.
- **Parent Hierarchy Tracking**: Appends `::<kind> <name>` to `parent_type` (e.g. `struct sk_buff::union (anon)::struct (anon)`).
- **Bit Offset Accumulation**: Adds the member's `bits_offset` to the enclosing context's `bits_offset` so every flattened leaf field records its exact absolute bit offset from the start of the top-level struct.

### 2.3 Multidimensional Arrays & Flexible Array Members (`process_array_type`)
When a member points to an `ARRAY` BTF node:
- Unwraps nested `ARRAY` nodes to compute the total element count (`total_elems = outer.nr_elems * inner.nr_elems`) and constructs a nested kind string (`ARRAY<INT>`, `ARRAY<PTR>`, `ARRAY<STRUCT>`).
- **Flexible Array Detection (`is_flex`)**: If `total_elems == 0` (corresponding to a trailing `char data[]` or `struct foo items[0]` flexible array member), marks `is_flex = True` and `nr_bits = 0`.
- **Arrays of Structs**: If the array element type is a `STRUCT` or `UNION`, recursively expands the element's fields while overriding each child field's `nr_bits` to span the full array size (`total_elems * elem_type["size"] * 8`).

### 2.4 Pointers & Function Prototypes (`resolve_pointer_target`, `format_func_proto`)
When a member has `kind == "PTR"`:
- Pointers on 64-bit LP64 kernels always have `nr_bits = 64` (`8` bytes).
- If the pointer target is a `FUNC_PROTO` (function pointer field in an operations table or struct), `format_func_proto()` reconstructs the C signature: `func_proto (<ret_type>)(<param1_type> <param1_name>, ...)`.

---

## 3. Concrete Conversion Example

Consider the following kernel C structure:

```c
struct demo_obj {
    unsigned long flags;
    union {
        struct callback_head rcu;   /* contains: struct callback_head *next; void (*func)(struct callback_head *head); */
        u64 cookie;
    };
    char data[];                    /* flexible array member */
};
```

### Input (`bpftool btf dump --json` excerpt)
```json
{
  "types": [
    {"id": 1, "kind": "INT", "name": "unsigned long", "size": 8, "nr_bits": 64},
    {"id": 2, "kind": "INT", "name": "char", "size": 1, "nr_bits": 8},
    {"id": 3, "kind": "ARRAY", "type_id": 2, "nr_elems": 0},
    {"id": 4, "kind": "STRUCT", "name": "callback_head", "size": 16, "members": [
      {"name": "next", "type_id": 5, "bits_offset": 0},
      {"name": "func", "type_id": 6, "bits_offset": 64}
    ]},
    {"id": 7, "kind": "UNION", "name": "(anon)", "size": 16, "members": [
      {"name": "rcu", "type_id": 4, "bits_offset": 0},
      {"name": "cookie", "type_id": 1, "bits_offset": 0}
    ]},
    {"id": 8, "kind": "STRUCT", "name": "demo_obj", "size": 24, "members": [
      {"name": "flags", "type_id": 1, "bits_offset": 0},
      {"name": "", "type_id": 7, "bits_offset": 64},
      {"name": "data", "type_id": 3, "bits_offset": 192}
    ]}
  ]
}
```

### Output (`types` SQLite Table Rows for `struct_name = 'demo_obj'`)

| `struct_name` | `struct_size` | `parent_type` | `kind` | `type` | `name` | `bits_offset` | `nr_bits` | `bits_end` | `is_flex` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `demo_obj` | `24` | `struct demo_obj` | `INT` | `unsigned long` | `flags` | `0` | `64` | `64` | `0` |
| `demo_obj` | `24` | `struct demo_obj::union (anon)::struct callback_head` | `PTR` | `struct callback_head` | `rcu.next` | `64` | `64` | `128` | `0` |
| `demo_obj` | `24` | `struct demo_obj::union (anon)::struct callback_head` | `PTR` | `func_proto (void)(struct callback_head * head)` | `rcu.func` | `128` | `64` | `192` | `0` |
| `demo_obj` | `24` | `struct demo_obj::union (anon)` | `INT` | `unsigned long` | `cookie` | `64` | `64` | `128` | `0` |
| `demo_obj` | `24` | `struct demo_obj` | `ARRAY<INT>` | `char` | `data` | `192` | `0` | `192` | `1` |

---

## 4. Usage & Testing

```bash
# Extract BTF from vmlinux into SQLite (and optionally save raw JSON):
python3 -m data.btf_data.extract_btf /path/to/vmlinux \
  --db_file /path/to/codeql_data.db \
  [--json_file /path/to/btf_dump.json]

# Run unit tests:
pytest data/btf_data/tests -v
```
