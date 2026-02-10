from argparse import ArgumentParser

from gateway import Gateway
from tdr_tdcs_metadata import tdr_tdcs_metadata_lookup_entry
from tdvmcs_metadata import tdvmcs_metadata_lookup_entry
from tdvps_metadata import tdvps_metadata_lookup_entry
from tdxtend import TdxErrorCode, TdxStatus, Tdxtend


def print_vm_metadata_field(tinny, version, identifier):

  rc, _next_, contents = tinny.call_tdg_vm_rd_leaf(version, identifier)

  if rc == TdxErrorCode.TDX_SUCCESS.value:
    entry = tdr_tdcs_metadata_lookup_entry(identifier)
    if entry != None:
      print(
          f"identifier: {hex(identifier)}, name: {entry['name']}, "
          f"num_of_fields: {entry['num_of_fields']}, "
          f"num_of_elem: {entry['num_of_elem']}, "
          # f"dbg_wr_mask: {hex(entry['dbg_wr_mask'])}, "
          # f"guest_wr_mask: {hex(entry['guest_wr_mask'])}, "
          # f"migtd_wr_mask: {hex(entry['migtd_wr_mask'])}, "
          # f"import_mask: {hex(entry['import_mask'])}, "
          f"contents: {hex(contents)}"
      )
    else:
      print(f"identifier: {hex(identifier)}, contents: {hex(contents)}")

  return rc, _next_


def print_vp_metadata_field(tinny, version, identifier):

  rc, _next_, contents = tinny.call_tdg_vp_rd_leaf(version, identifier)

  if rc == TdxErrorCode.TDX_SUCCESS.value:

    entry = tdvmcs_metadata_lookup_entry(identifier)
    if entry != None:
      print(
          f"identifier: {hex(identifier)}, name: {entry['name']}, "
          f"num_of_fields: {entry['num_of_fields']}, "
          f"num_of_elem: {entry['num_of_elem']}, "
          # f"dbg_wr_mask: {hex(entry['dbg_wr_mask'])}, "
          # f"guest_wr_mask: {hex(entry['guest_wr_mask'])}, "
          # f"import_mask: {hex(entry['import_mask'])}, "
          f"contents: {hex(contents)}"
      )
    else:
      entry = tdvps_metadata_lookup_entry(identifier)
      if entry != None:
        print(
            f"identifier: {hex(identifier)}, name: {entry['name']}, "
            f"num_of_fields: {entry['num_of_fields']}, "
            f"num_of_elem: {entry['num_of_elem']}, "
            # f"prod_wr_mask: {hex(entry['prod_wr_mask'])}, "
            # f"dbg_wr_mask: {hex(entry['dbg_wr_mask'])}, "
            # f"import_mask: {hex(entry['import_mask'])}, "
            f"contents: {hex(contents)}"
        )
      else:
        print(f"identifier: {hex(identifier)}, contents: {hex(contents)}")

  return rc, _next_


def print_metadata_fields(tinny, _type_, identifier, version, count):

  if _type_ == "vm":
    if version == -1:
      version = 1

    if identifier == -1:
      rc, identifier, _ = tinny.call_tdg_vm_rd_leaf(version, -1)

      if rc != TdxErrorCode.TDX_METADATA_FIRST_FIELD_ID_IN_CONTEXT.value:
        print(f"TDX STATUS: {TdxStatus(rc)}")
        return

    print("vm-scope metadata:")

    for _ in range(count):
      rc, identifier = print_vm_metadata_field(tinny, version, identifier)
      if rc != TdxErrorCode.TDX_SUCCESS.value:
        print(f"TDX STATUS: {TdxStatus(rc)}")
        break

      if identifier == -1:
        break

  elif _type_ == "vp":
    if version == -1:
      version = 0

    if identifier == -1:
      rc, identifier, _ = tinny.call_tdg_vp_rd_leaf(version, -1)

      if rc != TdxErrorCode.TDX_METADATA_FIRST_FIELD_ID_IN_CONTEXT.value:
        print(f"TDX STATUS: {TdxStatus(rc)}")
        return

    print("vp-scope metadata:")

    for _ in range(count):
      rc, identifier = print_vp_metadata_field(tinny, version, identifier)
      if rc != TdxErrorCode.TDX_SUCCESS.value:
        print(f"TDX STATUS: {TdxStatus(rc)}")
        break

      if identifier == -1:
        break


def main():
  parser = ArgumentParser(description="tdg_md_rd")

  parser.add_argument(
      "type",
      choices=["vm", "vp"],
      type=str,
      help="type of metadata to read",
  )

  parser.add_argument(
      "identifier",
      type=lambda x: int(x, 0),
      help="field identifier",
  )

  parser.add_argument(
      "--version",
      default=-1,
      type=lambda x: int(x, 0),
      help="metadata version",
  )

  parser.add_argument(
      "--count",
      default=1,
      type=lambda x: int(x, 0),
      help="number of metadata entries to read",
  )

  args = parser.parse_args()

  gateway = Gateway()
  tinny = Tdxtend(0, gateway)

  print_metadata_fields(
      tinny,
      args.type,
      args.identifier,
      args.version,
      args.count,
  )


if __name__ == "__main__":
  main()
