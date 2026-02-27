from argparse import ArgumentParser
from random import randint

from tdxamine import State, TdData
from tdxtend import INVALID_PID, TdxErrorCode, TdxStatus, Tdxtend
from gateway import FOUR_KILOBYTES, Gateway


def main():
  parser = ArgumentParser(description="tdh_mng_init")

  parser.add_argument(
      "tdr_pa",
      type=lambda x: int(x, 0),
      help="TD TDR physical address",
  )

  parser.add_argument(
      "params_file",
      type=str,
      help="Name of the params file to use",
  )

  parser.add_argument(
      "--state",
      type=str,
      default="state.pickle",
      help="State to load",
  )

  parser.add_argument("--verbose", action="store_true", help="Verbose output")

  args = parser.parse_args()

  with open(args.params_file, "rb") as f:
    params = f.read()

  gateway = Gateway()
  state = State(args.state)
  tdxtend = Tdxtend(INVALID_PID, gateway)

  td = state.get_td_by_tdr_pa(args.tdr_pa)

  td_params_ka, td_params_pa = gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)

  gateway.write_buffer(params, td_params_ka)

  print(f"td_params_pa: {hex(td_params_pa)}")
  rc = tdxtend.call_tdh_mng_init_leaf(td.tdr_pa, td_params_pa)

  print(f"TDX STATUS: {TdxStatus(rc)}")

  gateway.free_contiguous_buffer(td_params_ka, FOUR_KILOBYTES)


if __name__ == "__main__":
  main()
