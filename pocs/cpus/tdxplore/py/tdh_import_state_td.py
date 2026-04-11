from argparse import ArgumentParser

from tdxamine import State, TdData
from tdxtend import INVALID_PID, MBMD_SIZE, TdxErrorCode, TdxStatus, Tdxtend
from gateway import FOUR_KILOBYTES, Gateway


def chunk_buffer(buffer_data, chunk_size_bytes=FOUR_KILOBYTES) -> [bytes]:

  chunks = []
  for i in range(0, len(buffer_data), chunk_size_bytes):
    chunk = buffer_data[i : i + chunk_size_bytes]
    chunks.append(chunk)
  return chunks


def main():
  parser = ArgumentParser(description="tdh_import_state_td")

  parser.add_argument(
      "tdr_pa",
      type=lambda x: int(x, 0),
      help="TDR PA of the TD",
  )

  parser.add_argument(
      "mbmd_file",
      type=str,
      help="mbmd file to use",
  )

  parser.add_argument(
      "td_file",
      type=str,
      help="td data file to use",
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

  plt_ka, plt_pa = gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)

  imp_pg_ka_list = []

  with open(args.td_file, "rb") as f:
    chunks = chunk_buffer(f.read(), FOUR_KILOBYTES)

  i = 0
  for chunk in chunks:
    imp_pg_ka, imp_pg_pa = gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)
    gateway.write_buffer(chunk, imp_pg_ka)
    imp_pg_ka_list.append(imp_pg_ka)

    gateway.write_uint64(plt_ka + (i * 8), imp_pg_pa)
    i += 1

    if args.verbose:
      print(f"imp_pg(s):")
      for imp_pg_ka in imp_pg_ka_list:
        buffer = gateway.read_buffer(imp_pg_ka, FOUR_KILOBYTES)
        gateway.hexdump(buffer, FOUR_KILOBYTES)

  mbmd_ka, mbmd_pa = gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)

  with open(args.mbmd_file, "rb") as f:
    mbmd = f.read()

  if args.verbose:
    print("mbmd:")
    gateway.hexdump(mbmd, MBMD_SIZE)

  gateway.write_buffer(mbmd, mbmd_ka)

  try:
    rc, eei1, eei2 = tdxtend.call_tdh_import_state_td(
        td.tdr_pa,
        tdxtend.make_mbmd(mbmd_pa, MBMD_SIZE),
        tdxtend.make_page_list_info(plt_pa, len(imp_pg_ka_list) - 1),
        tdxtend.make_migration_index_and_cmd(
            args.migs_index, args.num_in_order_migs, False
        ),
    )

    while rc == TdxErrorCode.TDX_INTERRUPTED_RESUMABLE.value:
      rc, eei1, eei2 = tdxtend.call_tdh_import_state_td(
          td.tdr_pa,
          tdxtend.make_mbmd(mbmd_pa, MBMD_SIZE),
          tdxtend.make_page_list_info(plt_pa, len(imp_pg_ka_list) - 1),
          tdxtend.make_migration_index_and_cmd(
              args.migs_index, args.num_in_order_migs, True
          ),
      )

    print(
        f"return code: {TdxStatus(rc)}, extended error information 1:"
        f" {hex(eei1)}, 2: {hex(eei2)}"
    )

    if rc != TdxErrorCode.TDX_SUCCESS.value:
      raise ValueError(f"{TdxStatus(rc)}")
  except ValueError as e:
    print(e)
    pass

  for imp_pg_ka in imp_pg_ka_list:
    gateway.free_contiguous_buffer(imp_pg_ka, FOUR_KILOBYTES)

  gateway.free_contiguous_buffer(mbmd_ka, FOUR_KILOBYTES)
  gateway.free_contiguous_buffer(plt_ka, FOUR_KILOBYTES)


if __name__ == "__main__":
  main()
