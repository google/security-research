from argparse import ArgumentParser
from random import randint

from tdxamine import State, TdData
from tdxtend import INVALID_PID, TdxErrorCode, TdxStatus, Tdxtend
from gateway import FOUR_KILOBYTES, Gateway


def main():
  parser = ArgumentParser(description="tdh_vp_create")

  parser.add_argument(
      "tdr_pa",
      type=lambda x: int(x, 0),
      help="TD TDR physical address",
  )

  parser.add_argument(
      "--retries",
      type=int,
      default=4,
      help="Number of times to retry creating a TD",
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
  tdxtend = Tdxtend(INVALID_PID, gateway)

  td = state.get_td_by_tdr_pa(args.tdr_pa)

  free_list = []

  while args.retries > 0:
    tdvpr_ka, tdvpr_pa = gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)

    print(f"tdvpr_pa: {hex(tdvpr_pa)}")
    rc = tdxtend.call_tdh_vp_create_leaf(tdvpr_pa, td.tdr_pa)

    if rc == TdxErrorCode.TDX_SUCCESS.value:
      print(f"tdvpr_ka: {hex(tdvpr_ka)}, tdvpr_pa: {hex(tdvpr_pa)}")

      td.tdvpr_kas.append(tdvpr_ka)
      td.tdvpr_pas.append(tdvpr_pa)
      break
    else:
      print(f"TDX STATUS: {TdxStatus(rc)}")
      free_list.append(tdvpr_ka)
      args.retries -= 1

  for ka in free_list:
    gateway.free_contiguous_buffer(ka, FOUR_KILOBYTES)

  state.save(args.state)


if __name__ == "__main__":
  main()
