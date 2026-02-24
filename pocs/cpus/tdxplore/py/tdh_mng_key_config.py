from argparse import ArgumentParser
from dataclasses import dataclass
from re import match
from threading import get_ident

from tdxamine import State, TdData
from tdxtend import INVALID_PID, TdxErrorCode, TdxStatus, Tdxtend
from gateway import Gateway


@dataclass
class CpuInfo:
  processor: int
  physical_id: int
  core_id: int
  apic_id: int
  initial_apic_id: int


def get_cpuinfo() -> list[CpuInfo]:

  cpus = []

  processor = -1
  physical_id = -1
  core_id = -1
  apicid = -1
  initial_apicid = -1

  with open("/proc/cpuinfo") as f:
    for line in f.readlines():
      if (
          processor != -1
          and physical_id != -1
          and core_id != -1
          and apicid != -1
          and initial_apicid != -1
      ):
        cpus.append(
            CpuInfo(processor, physical_id, core_id, apicid, initial_apicid)
        )

        processor = -1
        physical_id = -1
        core_id = -1
        apicid = -1
        initial_apicid = -1

      result = match(r"processor\s*: (\d+)", line)
      if result:
        processor = int(result.group(1))
        continue

      result = match(r"physical id\s*: (\d+)", line)
      if result:
        physical_id = int(result.group(1))
        continue

      result = match(r"core id\s*: (\d+)", line)
      if result:
        core_id = int(result.group(1))
        continue

      result = match(r"apicid\s*: (\d+)", line)
      if result:
        apicid = int(result.group(1))
        continue

      result = match(r"initial apicid\s*: (\d+)", line)
      if result:
        initial_apicid = int(result.group(1))
        continue

  return cpus


def main():
  parser = ArgumentParser(description="tdh_mng_key_config")

  parser.add_argument(
      "tdr_pa",
      type=lambda x: int(x, 0),
      help="TD TDR physical address",
  )

  parser.add_argument(
      "--state",
      type=str,
      default="state.pickle",
      help="State to load",
  )

  parser.add_argument("--verbose", action="store_true", help="Verbose output")

  args = parser.parse_args()

  gateway = Gateway()
  state = State(args.state)
  tdxtend = Tdxtend(INVALID_PID, gateway)

  td = state.get_td_by_tdr_pa(args.tdr_pa)

  packages = []
  for cpu in get_cpuinfo():
    if cpu.physical_id not in packages:
      packages.append(cpu.physical_id)

      gateway.set_thread_affinity(get_ident(), cpu.processor)

      rc = tdxtend.call_tdh_mng_key_config(td.tdr_pa)

      if rc == TdxErrorCode.TDX_KEY_CONFIGURED.value:
        continue

      if rc != TdxErrorCode.TDX_SUCCESS.value:
        print(f"TDX STATUS: {TdxStatus(rc)}")
        return


if __name__ == "__main__":
  main()
