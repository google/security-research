from argparse import ArgumentParser

from tdxamine import State, TdData
from tdxtend import INVALID_PID, TdxStatus, Tdxtend
from gateway import Gateway


def main():
  parser = ArgumentParser(description="tdh_mem_sept_rd")

  parser.add_argument(
      "tdr_pa",
      type=lambda x: int(x, 0),
      help="TDR PA of the TD",
  )

  parser.add_argument(
      "gpa",
      type=lambda x: int(x, 0),
      help="guest physical address to read",
  )

  parser.add_argument(
      "level",
      type=lambda x: int(x, 0),
      help="level of the secure ept to read",
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

  rc, entry = tdxtend.call_tdh_mem_sept_rd(td.tdr_pa, args.gpa, args.level)

  print(f"TDX STATUS: {TdxStatus(rc)}")
  print(f"entry: {hex(entry)}")

if __name__ == "__main__":
  main()
