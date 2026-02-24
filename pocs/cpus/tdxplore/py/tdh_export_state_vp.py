from argparse import ArgumentParser

from tdxamine import State, TdData
from tdxtend import INVALID_PID, MBMD_SIZE, MIN_VP_STATE_EXPORT_PAGES, TdxErrorCode, TdxStatus, Tdxtend
from gateway import FOUR_KILOBYTES, Gateway


def main():
  parser = ArgumentParser(description="tdh_export_state_vp")

  parser.add_argument(
      "tdr_pa",
      type=lambda x: int(x, 0),
      help="TDR PA of the TD",
  )

  parser.add_argument(
      "vcpu",
      type=lambda x: int(x, 0),
      help="VCPU number for the target VCPU",
  )

  parser.add_argument(
      "mbmd_file",
      type=str,
      help="mbmd file to use",
  )

  parser.add_argument(
      "vp_file",
      type=str,
      help="vp data file to use",
  )

  parser.add_argument(
      "--migs_index",
      type=lambda x: int(x, 0),
      default=0,
      help="index of the migration state",
  )

  parser.add_argument(
      "--num_in_order_migs",
      type=lambda x: int(x, 0),
      default=0,
      help="number of in-order migrations",
  )

  parser.add_argument(
      "--state",
      type=str,
      default="state.pickle",
      help="State to load",
  )

  parser.add_argument(
      "--verbose",
      action="store_true",
      help="Verbose output",
  )

  args = parser.parse_args()

  gateway = Gateway()
  tdxtend = Tdxtend(INVALID_PID, gateway)

  state = State(args.state)
  td = state.get_td_by_tdr_pa(args.tdr_pa)

  tdxtend.switch_to_associated_tdvpr_cpu(td.tdvpr_pas[args.vcpu])

  plt_ka, plt_pa = gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)

  exp_pg_ka_list = []

  for i in range(MIN_VP_STATE_EXPORT_PAGES):
    exp_pg_ka, exp_pg_pa = gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)
    gateway.write_buffer(b"\x00" * FOUR_KILOBYTES, exp_pg_ka)
    exp_pg_ka_list.append(exp_pg_ka)

    gateway.write_uint64(plt_ka + (i * 8), exp_pg_pa)

  mbmd_ka, mbmd_pa = gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)

  print(f"export state vp")

  try:
    rc, count = tdxtend.call_tdh_export_state_vp(
        td.tdvpr_pas[args.vcpu],
        tdxtend.make_mbmd(mbmd_pa, MBMD_SIZE),
        tdxtend.make_page_list_info(plt_pa, len(exp_pg_ka_list) - 1),
        tdxtend.make_migration_index_and_cmd(
            args.migs_index, args.num_in_order_migs, False
        ),
    )

    print(f"TDX STATUS: {TdxStatus(rc)}")

    if rc != TdxErrorCode.TDX_SUCCESS.value:
      raise ValueError(f"{TdxStatus(rc)}")

    mbmd = gateway.read_buffer(mbmd_ka, MBMD_SIZE)

    with open(args.mbmd_file, "wb") as f:
      f.write(mbmd)

    if args.verbose:
      print("mbmd:")
      gateway.hexdump(mbmd, MBMD_SIZE)

    exp_bf_list = []
    for exp_pg_ka in exp_pg_ka_list[:count]:
      exp_bf_list.append(gateway.read_buffer(exp_pg_ka, FOUR_KILOBYTES))

    with open(args.vp_file, "wb") as f:
      for exp_bf in exp_bf_list:
        f.write(exp_bf)

    if args.verbose:
      print(f"exp_pg(s):")
      for exp_bf in exp_bf_list:
        gateway.hexdump(exp_bf, FOUR_KILOBYTES)

  except Exception:
    pass

  for exp_pg_ka in exp_pg_ka_list:
    gateway.free_contiguous_buffer(exp_pg_ka, FOUR_KILOBYTES)

  gateway.free_contiguous_buffer(mbmd_ka, FOUR_KILOBYTES)
  gateway.free_contiguous_buffer(plt_ka, FOUR_KILOBYTES)


if __name__ == "__main__":
  main()
