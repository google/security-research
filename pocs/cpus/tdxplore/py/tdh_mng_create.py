from argparse import ArgumentParser
from random import randint

from tdxamine import State, TdData
from tdxtend import INVALID_PID, TdxErrorCode, TdxStatus, Tdxtend
from gateway import FOUR_KILOBYTES, Gateway


def main():
  parser = ArgumentParser(description="tdh_mng_create")

  parser.add_argument(
      "name",
      type=str,
      help="name of the TD",
  )

  parser.add_argument(
      "--hkid",
      type=lambda x: int(x, 0),
      help="private hkid to use",
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

  parser.add_argument("--verbose", action="store_true", help="Verbose output")

  args = parser.parse_args()

  if not args.hkid:
    args.hkid = randint(0, 128)

  if args.verbose:
    print(f"hkid: {hex(args.hkid)}")

  gateway = Gateway()
  state = State(args.state)
  tdxtend = Tdxtend(INVALID_PID, gateway)

  free_list = []

  rc = TdxErrorCode.TDX_SUCCESS.value
  while args.retries > 0:
    tdr_ka, tdr_pa = gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)

    print(f"tdr_pa: {hex(tdr_pa)}")
    rc = tdxtend.call_tdh_mng_create_leaf(tdr_pa, args.hkid)

    if rc == TdxErrorCode.TDX_SUCCESS.value:
      print(f"tdr_ka: {hex(tdr_ka)}, tdr_pa: {hex(tdr_pa)}")

      td = TdData(name=args.name, hkid=args.hkid, tdr_ka=tdr_ka, tdr_pa=tdr_pa)
      state.add_td(td)
      break
    else:
      print(f"TDX STATUS: {TdxStatus(rc)}")
      free_list.append(tdr_ka)
      args.retries -= 1

  for ka in free_list:
    gateway.free_contiguous_buffer(ka, FOUR_KILOBYTES)

  state.save(args.state)

  exit(rc)

if __name__ == "__main__":
  main()
