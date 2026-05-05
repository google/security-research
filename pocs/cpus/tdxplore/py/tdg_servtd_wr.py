from argparse import ArgumentParser
from os import SCHED_FIFO, sched_param, sched_setscheduler

from tdr_tdcs_metadata import tdr_tdcs_metadata_lookup_entry
from tdxtend import TdxErrorCode, Tdxtend
from gateway import Gateway


def print_field(tinny, identifier, binding_handle, uuid):

  rc, _next_, contents, _, _, _, _ = tinny.call_tdg_servtd_rd_leaf(
      binding_handle, identifier, uuid
  )

  if rc == TdxErrorCode.TDX_SUCCESS.value:

    entry = tdr_tdcs_metadata_lookup_entry(identifier)
    if entry != None:
      print(
          f"identifier: {hex(identifier)}, name: {entry['name']},"
          f" num_of_fields: {entry['num_of_fields']}, num_of_elem:"
          f" {entry['num_of_elem']}, dbg_wr_mask:"
          f" {hex(entry['dbg_wr_mask'])}, guest_wr_mask:"
          f" {hex(entry['guest_wr_mask'])}, migtd_wr_mask:"
          f" {hex(entry['migtd_wr_mask'])}, import_mask:"
          f" {hex(entry['import_mask'])}, value:"
          f" {hex(contents)}"
      )
    else:
      print(f"identifier: {hex(identifier)}, value: {hex(contents)}")
  return rc, _next_


def print_fields(tinny, identifier, count, binding_handle, uuid):

  tmp = []
  for part in uuid.split("-"):
    tmp.append(int(part, 16))

  uuid = tmp

  if identifier == -1:
    rc, identifier, _, _, _, _, _ = tinny.call_tdg_servtd_rd_leaf(
        binding_handle, -1, uuid
    )

    if rc != TdxErrorCode.TDX_METADATA_FIRST_FIELD_ID_IN_CONTEXT.value:
      print(f"rc: {hex(rc)}")
      print(
          "unable to find next field identifier, this might be because of an"
          " unsupported version"
      )
      return

  for _ in range(count):
    rc, identifier = print_field(
        tinny, identifier, binding_handle, uuid
    )

    if rc != TdxErrorCode.TDX_SUCCESS.value:
      break


def main():
  parser = ArgumentParser(description="tdg_servtd_wr")

  parser.add_argument(
      "binding_handle",
      default=0,
      type=lambda x: int(x, 0),
      help="binding handle",
  )
  parser.add_argument(
      "uuid",
      type=str,
      help="uuid in the format of 0-0-0-0",
  )

  parser.add_argument(
      "identifier",
      type=lambda x: int(x, 0),
      help="field identifier",
  )

  parser.add_argument(
      "value",
      type=lambda x: int(x, 0),
      help="field value",
  )

  parser.add_argument(
      "mask",
      type=lambda x: int(x, 0),
      help="field mask",
  )

  args = parser.parse_args()

  sched_setscheduler(0, SCHED_FIFO, sched_param(99))

  gateway = Gateway()
  tdxtend = Tdxtend(0, gateway)

  uuid = []
  for part in args.uuid.split("-"):
    uuid.append(int(part, 16))

  rc, previous_contents, uuid0, uuid1, uuid2, uuid3 = (
      tdxtend.call_tdg_servtd_wr_leaf(
          args.binding_handle, args.identifier, args.value, args.mask, uuid
      )
  )

  if rc != TdxErrorCode.TDX_SUCCESS.value:
    print(f"rc: {hex(rc)}")
  else:
    print(f"previous_contents: {hex(previous_contents)}")
    print(f"uuid: {uuid0:x}-{uuid1:x}-{uuid2:x}-{uuid3:x}")


if __name__ == "__main__":
  main()
