from argparse import ArgumentParser
from threading import get_ident

from tdxtend import TdxStatus, Tdxtend
from gateway import Gateway


def main():
  parser = ArgumentParser(description="tdg_md_wr")

  parser.add_argument(
      "type",
      choices=["vm", "vp"],
      type=str,
      help="type of metadata to read",
  )

  parser.add_argument(
      "identifier",
      type=lambda x: int(x, 0),
      help="field identifier",
  )

  parser.add_argument(
      "value",
      type=lambda x: int(x, 0),
      help="Value",
  )

  parser.add_argument(
      "mask",
      type=lambda x: int(x, 0),
      help="Mask",
  )

  parser.add_argument(
      "--vcpu",
      default=0,
      type=int,
      help="VCPU number for the target VCPU",
  )

  args = parser.parse_args()

  gateway = Gateway()
  tdxtend = Tdxtend(0, gateway)

  if args.type == "vm":
    rc, _ = tdxtend.call_tdg_vm_wr_leaf(
        args.identifier, args.value, args.mask
    )

    print(f"TDX STATUS: {TdxStatus(rc)}")
  elif args.type == "vp":
    gateway.set_thread_affinity(get_ident(), args.vcpu)
    rc, _ = tdxtend.cacll_tdg_vp_wr_leaf(
        args.identifier, args.value, args.mask
    )

    print(f"TDX STATUS: {TdxStatus(rc)}")


if __name__ == "__main__":
  main()
