from argparse import ArgumentParser
from os import kill
from signal import SIGCONT, SIGSTOP
from tdxamine import State, TdData
from tdxtend import TdxErrorCode, Tdxtend, TdxStatus
from gateway import Gateway


def main():
  parser = ArgumentParser(description="tdh_md_wr")

  parser.add_argument(
      "tdr_pa",
      type=lambda x: int(x, 0),
      help="TDR PA of the TD",
  )
  
  parser.add_argument(
      "type",
      choices=["td", "vp"],
      type=str,
      help="type of metadata to write",
  )

  parser.add_argument(
      "identifier",
      type=lambda x: int(x, 0),
      help="Identifier",
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

  print(
      f"identifier: {hex(args.identifier)}, value: {hex(args.value)}, mask:"
      f" {hex(args.mask)}"
  )

  if args.type == "td":
    print("td-scope metadata:")
    tdr = tdxtend.get_tdr_pa(tdxtend.get_vm_fd())
    print(f"tdr: {hex(tdr)}")
    rc, _ = tdxtend.call_tdh_mng_wr_leaf(
        td.tdr_pa, args.identifier, args.value, args.mask
    )

    print(f"rc: {hex(rc)}")

  elif args.type == "vp":
    print("tdvpr metadata:")
    tdvpr = td.tdvpr_pas[args.vcpu]
    print(f"tdvpr: {hex(tdvpr)}")
    tdxtend.switch_to_associated_tdvpr_cpu(tdvpr)
    rc, _ = tdxtend.call_tdh_vp_wr_leaf(
        tdvpr, args.identifier, args.value, args.mask
    )

    print(f"TDX STATUS: {TdxStatus(rc)}")

if __name__ == "__main__":
  main()
