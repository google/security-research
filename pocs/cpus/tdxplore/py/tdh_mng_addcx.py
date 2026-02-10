from argparse import ArgumentParser

from tdxamine import State, TdData
from tdxtend import INVALID_PID, MIN_NUM_TDCS_PAGES, TdxErrorCode, TdxStatus, Tdxtend
from gateway import FOUR_KILOBYTES, Gateway


def main():
  parser = ArgumentParser(description="tdh_mng_addcx")

  parser.add_argument(
      "tdr_pa",
      type=lambda x: int(x, 0),
      help="TD TDR physical address",
  )

  parser.add_argument(
      "--count",
      type=int,
      default=MIN_NUM_TDCS_PAGES,
      help="Number of TDCS pages to add to the TD",
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

  while len(td.tdcs_kas) < args.count:
    tdcs_ka, tdcs_pa = gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)

    rc = tdxtend.call_tdh_mng_addcx(tdcs_pa, td.tdr_pa)

    if rc != TdxErrorCode.TDX_SUCCESS.value:
      print(f"TDX STATUS: {TdxStatus(rc)}")
      free_list.append(tdcs_ka)

      args.retries -= 1
      if args.retries <= 0:
        break

    td.tdcs_kas.append(tdcs_ka)
    td.tdcs_pas.append(tdcs_pa)

    for ka in free_list:
      gateway.free_contiguous_buffer(ka, FOUR_KILOBYTES)

    state.save(args.state)


if __name__ == "__main__":
  main()
