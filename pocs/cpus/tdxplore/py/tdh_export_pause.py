from argparse import ArgumentParser

from tdxamine import State, TdData
from tdxtend import INVALID_PID, TdxStatus, Tdxtend
from gateway import FOUR_KILOBYTES, Gateway


def main():
  parser = ArgumentParser(description="tdh_export_pause")

  parser.add_argument(
      "tdr_pa",
      type=lambda x: int(x, 0),
      help="TDR PA of the TD",
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

  rc = tdxtend.call_tdh_export_pause(td.tdr_pa)

  print(f"TDX STATUS: {TdxStatus(rc)}")

if __name__ == "__main__":
  main()
