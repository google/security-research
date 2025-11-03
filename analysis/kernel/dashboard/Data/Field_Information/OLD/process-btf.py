#!/usr/bin/python3

import json
import math

import sys

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

btf = json.load(open("btf-vmlinux.json"))

types = {}
PTR_SIZE = 64

for type in btf['types']:
    types[type['id']] = type

def get_shallow(struct_name, struct_size, object, parent_type, prefix="", bits_offset=0):
    shallow_types = []
    type = types[object['type_id']]

    while type['kind'] in ["TYPEDEF", "CONST", "VOLATILE"]:
        type = types[type['type_id']]

    if type['kind'] == 'ARRAY' and type['nr_elems'] > 0:
        object_bits_offset = object["bits_offset"] + bits_offset
        for index in range(type['nr_elems']):
            expanded_object = object.copy()
            expanded_object['type_id'] = type['type_id']
            expanded_object['name'] += f"[{index}]"
            deeper_types = get_shallow(struct_name, struct_size, expanded_object, parent_type, prefix, object_bits_offset)
            sorted_deepest = sorted(deeper_types, key=lambda x: x['bits_end'], reverse=True)
            deepest_bits_end = sorted_deepest[0]['bits_end'] if len(sorted_deepest) > 0 else 0
            object_bits_offset = 8 * math.ceil(deepest_bits_end / 8)
            shallow_types += deeper_types
    elif type['kind'] == 'STRUCT' or type['kind'] == 'UNION':
        for idx, member in enumerate(type['members']):
            if type['kind'] == 'UNION':
                new_prefix = prefix + "/*" + str(idx) + ":" + object['name'] + "*/"
            else:
                new_prefix = prefix + object['name'] + "."
            deeper_types = get_shallow(struct_name, struct_size, member, type['name'], new_prefix, bits_offset + object["bits_offset"])
            shallow_types += deeper_types
    else:
        kind = type['kind']
        is_flex = False
        if type['kind'] == "PTR":
            nr_bits = PTR_SIZE
            bits_end = bits_offset + object["bits_offset"] + nr_bits
        elif type['kind'] == "ENUM" or type['kind'] == "ENUM64":
            nr_bits = type['size'] * 8
            bits_end = bits_offset + object["bits_offset"] + nr_bits
        elif type['kind'] == "ARRAY":
            expanded_object = object.copy()
            expanded_object['type_id'] = type['type_id']
            expanded_object['bits_offset'] = 0
            deeper_types = get_shallow(struct_name, struct_size, expanded_object, type['name'], prefix, 0)
            sorted_deepest = sorted(deeper_types, key=lambda x: x['bits_end'], reverse=True)
            nr_bits = sorted_deepest[0]['bits_end']
            while type['kind'] in ["TYPEDEF", "CONST", "VOLATILE", "ARRAY"]:
                type = types[type['type_id']]
            kind = "ARRAY<" + type['kind'] + ">"
            is_flex = True
            bits_end = bits_offset + object["bits_offset"]
        else:
            if "nr_bits" not in type:
                eprint(type)
            nr_bits = type["nr_bits"]
            bits_end = bits_offset + object["bits_offset"] + nr_bits

        shallow_types.append({
            "struct_name": struct_name,
            "struct_size": struct_size,
            "parent_type": parent_type,
            "kind": kind,
            "type": type['name'],
            "name": prefix + object['name'],
            "bits_offset": bits_offset + object["bits_offset"],
            "nr_bits": nr_bits,
            "bits_end": bits_end,
            "is_flex": is_flex,
        })

    return shallow_types

all_structs = []
for type in btf['types']:
    types[type['id']] = type
    if type['kind'] == 'STRUCT':
        for member in type['members']:
            all_structs += get_shallow(type["name"], type["size"], member, type["name"])

print(len(all_structs))

print(json.dumps(all_structs, indent="\t"))
