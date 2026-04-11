from argparse import ArgumentParser

from tdxamine import State, TdData
from tdxtend import INVALID_PID, TdxStatus, Tdxtend
from gateway import FOUR_KILOBYTES, Gateway


def main():
  parser = ArgumentParser(description="tdh_export_abort")

  parser.add_argument(
      "tdr_pa",
      type=lambda x: int(x, 0),
      help="TDR PA of the TD",
  )

  parser.add_argument(
      "--token",
      action="store_true",
      help="token to use",
  )

  parser.add_argument(
      "--migs_index",
      type=lambda x: int(x, 0),
      default=0,
      help="index of the migration state",
  )

  parser.add_argument(
      "--state",
      type=str,
      default="state.pickle",
      help="State to load",
  )

  args = parser.parse_args()

  gateway = Gateway()
  tdxtend = Tdxtend(INVALID_PID, gateway)

  state = State(args.state)
  td = state.get_td_by_tdr_pa(args.tdr_pa)

  if args.token:
    print("post-copy token not supported")
    exit(0)
  else:
    token = 0

  rc = tdxtend.call_tdh_export_abort(td.tdr_pa, token, args.migs_index)

  print(f"TDX STATUS: {TdxStatus(rc)}")

  for ka in td.migsc_kas:
    gateway.free_contiguous_buffer(ka, FOUR_KILOBYTES)

  td.migsc_kas = []
  td.migsc_pas = []

if __name__ == "__main__":
  main()
