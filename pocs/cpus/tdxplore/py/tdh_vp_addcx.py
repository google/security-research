from argparse import ArgumentParser

from tdxamine import State, TdData
from tdxtend import INVALID_PID, MIN_TDVPS_PAGES, TdxErrorCode, TdxStatus, Tdxtend
from gateway import FOUR_KILOBYTES, Gateway


def main():
  parser = ArgumentParser(description="tdh_vp_addcx")

  parser.add_argument(
      "tdr_pa",
      type=lambda x: int(x, 0),
      help="TD TDR physical address",
  )

  parser.add_argument(
      "vcpu",
      type=lambda x: int(x, 0),
      help="VCPU number for the target VCPU",
  )

  parser.add_argument(
      "--count",
      type=int,
      default=MIN_TDVPS_PAGES,
      help="Number of TDCS pages to add to the VP",
  )

  parser.add_argument(
      "--retries",
      type=int,
      default=4,
      help="Number of times to retry creating a tdcs page",
  )

  parser.add_argument(
      "--state",
      type=str,
      default="state.pickle",
      help="State to load",
  )

  parser.add_argument("--verbose", action="store_true", help="Verbose output")

  args = parser.parse_args()

  gateway = Gateway()
  state = State(args.state)
  tdxtend = Tdxtend(INVALID_PID, gateway)

  td = state.get_td_by_tdr_pa(args.tdr_pa)

  free_list = []

  while len(td.tdcx_kas) < args.count:
    tdcx_ka, tdcx_pa = gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)

    rc = tdxtend.call_tdh_vp_addcx(tdcx_pa, td.tdvpr_pas[args.vcpu])

    if rc != TdxErrorCode.TDX_SUCCESS.value:
      print(f"TDX STATUS: {TdxStatus(rc)}")
      free_list.append(tdcx_ka)

      args.retries -= 1
      if args.retries <= 0:
        break

    td.tdcx_kas.append(tdcx_ka)
    td.tdcx_pas.append(tdcx_pa)

  for ka in free_list:
    gateway.free_contiguous_buffer(ka, FOUR_KILOBYTES)

  state.save(args.state)


if __name__ == "__main__":
  main()
