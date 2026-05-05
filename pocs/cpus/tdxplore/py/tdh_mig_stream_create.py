from argparse import ArgumentParser

from tdxamine import State, TdData
from tdxtend import MIN_MIGS, TdxErrorCode, TdxStatus, Tdxtend
from gateway import FOUR_KILOBYTES, Gateway


def main():
  parser = ArgumentParser(description="tdh_mig_stream_create")

  parser.add_argument(
      "tdr_pa",
      type=lambda x: int(x, 0),
      help="TDR PA of the TD",
  )
  
  parser.add_argument(
      "--retries",
      type=int,
      default=4,
      help="Number of times to retry creating a migsc",
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
  tdxtend = Tdxtend(td.pid, gateway)

  free_list = []

  while len(td.migsc_kas) < MIN_MIGS:
    migsc_ka, migsc_pa = gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)
    rc = tdxtend.call_tdh_mig_stream_create_leaf(migsc_pa, td.tdr_pa)

    if rc != TdxErrorCode.TDX_SUCCESS.value:
      print(f"TDX STATUS: {TdxStatus(rc)}")
      free_list.append(migsc_ka)

      args.retries -= 1
      if args.retries <= 0:
        break

    td.migsc_kas.append(migsc_ka)
    td.migsc_pas.append(migsc_pa)

  for ka in free_list:
    gateway.free_contiguous_buffer(ka, FOUR_KILOBYTES)

  state.save(args.state)

  print("migsc:")
  for i in range(MIN_MIGS):
    print(
        f"  ka[{i}] - {hex(td.migsc_kas[i])}, pa[{i}] - {hex(td.migsc_pas[i])}"
    )


if __name__ == "__main__":
  main()
