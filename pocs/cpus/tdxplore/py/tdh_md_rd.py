from argparse import ArgumentParser

from global_sys_metadata import global_sys_metadata_lookup_entry
from tdvmcs_metadata import tdvmcs_metadata_lookup_entry
from tdr_tdcs_metadata import tdr_tdcs_metadata_lookup_entry
from tdvps_metadata import tdvps_metadata_lookup_entry
from tdxamine import State, TdData
from gateway import Gateway
from tdxtend import TdxErrorCode, Tdxtend


def print_global_sys_metadata_field(tdxtend, identifier):

  rc, _next_, contents = tdxtend.call_tdh_sys_rd_leaf(identifier)

  if rc == TdxErrorCode.TDX_SUCCESS.value:
    entry = global_sys_metadata_lookup_entry(identifier)
    if entry != None:
      print(
          f"identifier: {hex(identifier)}, name: {entry['name']}, "
          f"num_of_fields: {entry['num_of_fields']}, "
          f"num_of_elem: {entry['num_of_elem']}, "
          # f"vmm_wr_mask: {hex(entry['vmm_wr_mask'])}, "
          f"contents: {hex(contents)}"
      )
    else:
      print(f"identifier: {hex(identifier)}, contents: {hex(contents)}")

  return rc, _next_


def print_td_metadata_field(tdxtend, version, tdr, identifier):

  rc, _next_, contents = tdxtend.call_tdh_mng_rd_leaf(
      version, tdr, identifier
  )

  if rc == TdxErrorCode.TDX_SUCCESS.value:
    entry = tdr_tdcs_metadata_lookup_entry(identifier)
    if entry != None:
      print(
          f"identifier: {hex(identifier)}, name: {entry['name']}, "
          f"num_of_fields: {entry['num_of_fields']}, "
          f"num_of_elem: {entry['num_of_elem']}, "
          # f"prod_wr_mask: {hex(entry['prod_wr_mask'])}, "
          # f"dbg_wr_mask: {hex(entry['dbg_wr_mask'])}, "
          # f"guest_wr_mask: {hex(entry['guest_wr_mask'])}, "
          # f"migtd_wr_mask: {hex(entry['migtd_wr_mask'])}, "
          # f"import_mask: {hex(entry['import_mask'])}, "
          f"contents: {hex(contents)}"
      )
    else:
      print(f"identifier: {hex(identifier)}, contents: {hex(contents)}")

  return rc, _next_


def print_tdvpr_metadata_field(tdxtend, version, tdvpr, identifier):

  tdxtend.switch_to_associated_tdvpr_cpu(tdvpr)
  rc, _next_, contents = tdxtend.call_tdh_vp_rd_leaf(
      version, tdvpr, identifier
  )

  if rc == TdxErrorCode.TDX_SUCCESS.value:

    entry = tdvmcs_metadata_lookup_entry(identifier)
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


def print_metadata_fields(tdxtend, td, _type_, identifier, version, vcpu, count):

  if _type_ == "global":
    if identifier == -1:
      rc, identifier, _ = tdxtend.call_tdh_sys_rd_leaf(-1)

      if (
          rc
          != TdxErrorCode.TDX_METADATA_FIRST_FIELD_ID_IN_CONTEXT.value
      ):
        print(
            f"{rc}: unable to find next field identifier, this might"
            " be because of an unsupported version"
        )
        return

    print("global-scope metadata:")
    for _ in range(count):
      rc, identifier = print_global_sys_metadata_field(
          tdxtend, identifier
      )
      if rc != TdxErrorCode.TDX_SUCCESS.value:
        break

      if identifier == -1:
        break

  elif _type_ == "td":
    if identifier == -1:
      rc, identifier, _ = tdxtend.call_tdh_mng_rd_leaf(
          version, td.tdr_pa, -1
      )

      if (
          rc
          != TdxErrorCode.TDX_METADATA_FIRST_FIELD_ID_IN_CONTEXT.value
      ):
        print(
            "unable to find next field identifier, this might be because of an"
            " unsupported version"
        )
        return

    print("td-scope metadata:")

    for _ in range(count):
      rc, identifier = print_td_metadata_field(
          tdxtend, version, td.tdr_pa, identifier
      )
      if rc != TdxErrorCode.TDX_SUCCESS.value:
        break

      if identifier == -1:
        break

  elif _type_ == "vp":

    tdxtend.switch_to_associated_tdvpr_cpu(td.tdvpr_pas[vcpu])

    if identifier == -1:
      rc, identifier, _ = tdxtend.call_tdh_vp_rd_leaf(
          1, td.tdvpr_pas[vcpu], -1
      )

      if (
          rc
          != TdxErrorCode.TDX_METADATA_FIRST_FIELD_ID_IN_CONTEXT.value
      ):
        print(
            "unable to find next field identifier, this might be because of an"
            " unsupported version"
        )
        return

    print("tdvpr metadata:")

    for _ in range(count):
      rc, identifier = print_tdvpr_metadata_field(
          tdxtend, version, td.tdvpr_pas[vcpu], identifier
      )
      if rc != TdxErrorCode.TDX_SUCCESS.value:
        break

      if identifier == -1:
        break


def main():
  parser = ArgumentParser(description="tdh_md_rd")

  parser.add_argument(
      "tdr_pa",
      type=lambda x: int(x, 0),
      help="TDR PA of the TD",
  )

  parser.add_argument(
      "type",
      choices=["global", "td", "vp"],
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
      default=1,
      type=lambda x: int(x, 0),
      help="metadata version",
  )

  parser.add_argument(
      "--count",
      default=1,
      type=lambda x: int(x, 0),
      help="number of metadata entries to read",
  )

  parser.add_argument(
      "--vcpu",
      default=0,
      type=lambda x: int(x, 0),
      help="vcpu number",
  )

  parser.add_argument(
      "--state",
      type=str,
      default="state.pickle",
      help="State to load",
  )

  args = parser.parse_args()

  gateway = Gateway()
  state = State(args.state)

  td = state.get_td_by_tdr_pa(args.tdr_pa)
  tdxtend = Tdxtend(0, gateway)

  print_metadata_fields(
      tdxtend,
      td,
      args.type,
      args.identifier,
      args.version,
      args.vcpu,
      args.count,
  )


if __name__ == "__main__":
  main()
