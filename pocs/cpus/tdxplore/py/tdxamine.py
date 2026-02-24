from argparse import ArgumentParser
from pickle import dump, load

from tdxtend import INVALID_ADDR, INVALID_HKID, INVALID_PID, Tdxtend
from gateway import FOUR_KILOBYTES, Gateway


class TdData:

  def __init__(
      self,
      name: str = "",
      pid: int = INVALID_PID,
      hkid: int = INVALID_HKID,
      tdr_ka: int = INVALID_ADDR,
      tdr_pa: int = INVALID_ADDR,
      bind_handles: list[int] = [],
      bind_uuids: list[str] = [],
      migsc_kas: list[int] = [],
      migsc_pas: list[int] = [],
      tdcs_kas: list[int] = [],
      tdcs_pas: list[int] = [],
      tdvpr_kas: list[int] = [],
      tdvpr_pas: list[int] = [],
      tdcx_kas: list[int] = [],
      tdcx_pas: list[int] = [],
  ):

    self.name = name
    self.pid = pid
    self.hkid = hkid
    self.tdr_ka = tdr_ka
    self.tdr_pa = tdr_pa
    self.bind_handles = bind_handles
    self.bind_uuids = bind_uuids
    self.migsc_kas = migsc_kas
    self.migsc_pas = migsc_pas
    self.tdcs_kas = tdcs_kas
    self.tdcs_pas = tdcs_pas
    self.tdvpr_kas = tdvpr_kas
    self.tdvpr_pas = tdvpr_pas
    self.tdcx_kas = tdcx_kas
    self.tdcx_pas = tdcx_pas


class State:

  def __init__(self, path: str):

    self.tds = []

    try:
      self.load(path)
    except IOError:
      self.tds = []

  def get_td_by_tdr_pa(self, tdr_pa: int) -> TdData:
    for td in self.tds:
      if td.tdr_pa == tdr_pa:
        return td

    raise ValueError(f"TD {tdr_pa} doesn't exist")

  def get_td_by_pid(self, pid: int) -> TdData:

    for td in self.tds:
      if td.pid == pid:
        return td

    raise ValueError(f"TD {pid} doesn't exist")

  def get_td_by_name(self, name: str) -> TdData:

    for td in self.tds:
      if td.name == name:
        return td

    raise ValueError(f"TD {name} doesn't exist")

  def add_td(self, td: TdData):
    for i in range(len(self.tds)):
      if self.tds[i].tdr_pa == td.tdr_pa:
        raise ValueError(f"TD {td.tdr_pa} already exists")

    self.tds.append(td)

  def remove_td(self, tdr_pa: int):
    for i in range(len(self.tds)):
      if self.tds[i].tdr_pa == tdr_pa:
        self.tds.remove(self.tds[i])
        return

    raise ValueError(f"TD {tdr_pa} doesn't exist")

  def load(self, path: str):
    with open(path, "rb") as f:
      self.tds = load(f)

  def save(self, path: str):
    with open(path, "wb") as f:
      dump(self.tds, f)

  def reset(self, gateway: Gateway):
    for td in self.tds:
      if td.tdr_ka != 0:
        gateway.free_contiguous_buffer(td.tdr_ka, FOUR_KILOBYTES)

      for ka in td.migsc_kas:
        if ka != 0:
          gateway.free_contiguous_buffer(ka, FOUR_KILOBYTES)

      for ka in td.tdcx_kas:
        if ka != 0:
          gateway.free_contiguous_buffer(ka, FOUR_KILOBYTES)

      for ka in td.tdvpr_kas:
        if ka != 0:
          gateway.free_contiguous_buffer(ka, FOUR_KILOBYTES)

      for ka in td.tdcs_kas:
        if ka != 0:
          gateway.free_contiguous_buffer(ka, FOUR_KILOBYTES)

    self.tds = []

  def __str__(self):
    result = ""
    for td in self.tds:
      result += (
          f"td: name - {td.name}, tdr_ka - {hex(td.tdr_ka)}, tdr_pa -"
          f" {hex(td.tdr_pa)}\n"
      )

      result += f"\n hkid - {hex(td.hkid)}\n"

      for index in range(len(td.tdcs_pas)):
        result += f"\n  tdcs {index}: pa -  {hex(td.tdcs_pas[index])}"
        if index < len(td.tdcs_kas) and td.tdcs_kas[index] != 0:
          result += f"    ka - {hex(td.tdcs_kas[index])}"

      for index in range(len(td.tdvpr_pas)):
        result += f"\n  tdvpr {index}: pa -  {hex(td.tdvpr_pas[index])}"
        if index < len(td.tdvpr_kas) and td.tdvpr_kas[index] != 0:
          result += f"    ka - {hex(td.tdvpr_kas[index])}"

      for index in range(len(td.tdcx_pas)):
        result += f"\n  tdcx {index}: pa -  {hex(td.tdcx_pas[index])}"
        if index < len(td.tdcx_kas) and td.tdcx_kas[index] != 0:
          result += f"    ka - {hex(td.tdcx_kas[index])}"

      for index in range(len(td.bind_handles)):
        result += f"\n  bind {index}: handle - {hex(td.bind_handles[index])}"

      for index in range(len(td.bind_uuids)):
        result += f"\n  bind {index}: uuid - {td.bind_uuids[index]}"

      for index in range(len(td.migsc_kas)):
        result += (
            f"\n  migsc {index}: ka - {hex(td.migsc_kas[index])}, pa - "
            f" {hex(td.migsc_pas[index])}"
        )

      result += "\n"

    return result


def cmd_add_td_by_pid(args, state):
  gateway = Gateway()
  tdxtend = Tdxtend(args.pid, gateway)

  try:
    td = TdData(
        name=args.name,
        pid=args.pid,
        tdr_pa=tdxtend.get_tdr_pa(tdxtend.get_vm_fd()),
        tdvpr_pas=[
            tdxtend.get_tdvpr_pa(vcpu_fd) for vcpu_fd in tdxtend.get_vcpu_fds()
        ],
    )
    state.add_td(td)
  except ValueError:
    print(f"Failed to add TD for PID {args.pid}")


def cmd_remove_td_by_name(args, state):

  try:
    state.remove_td(state.get_td_by_name(args.name).tdr_pa)
  except ValueError:
    print(f"Failed to remove TD for Name {args.name}")


def cmd_remove_td_bind_by_index(args, state):

  try:
    td = state.get_td_by_name(args.name)
    td.bind_handles.remove(td.bind_handles[args.index])
    td.bind_uuids.remove(td.bind_uuids[args.index])
  except ValueError:
    print(f"Failed to remove TD bind Index {args.index} from Name {args.name}")


def cmd_print_tdr_pa_from_pid(args, state):
  print(hex(state.get_td_by_pid(args.pid).tdr_pa))


def cmd_print_tdr_pa_from_name(args, state):
  print(hex(state.get_td_by_name(args.name).tdr_pa))


def cmd_print_state(args, state):
  print(state)


def cmd_reset_state(args, state):
  state.reset(Gateway())


if __name__ == "__main__":

  parser = ArgumentParser(description="tdxamine")

  subparsers = parser.add_subparsers(dest="command")

  parser.add_argument(
      "--state",
      type=str,
      default="state.pickle",
      help="State to load",
  )

  add_td_by_pid_parser = subparsers.add_parser(
      "add_td_by_pid", help="Add TD by PID"
  )
  add_td_by_pid_parser.add_argument(
      "pid",
      type=lambda x: int(x, 0),
      help="Process ID (PID) of the process",
  )

  add_td_by_pid_parser.add_argument("name", type=str, help="Name of the TD")
  add_td_by_pid_parser.set_defaults(func=cmd_add_td_by_pid)

  remove_td_by_name_parser = subparsers.add_parser(
      "remove_td_by_name", help="Remove TD by Name"
  )
  remove_td_by_name_parser.add_argument(
      "name",
      type=str,
      help="Name of the TD",
  )
  remove_td_by_name_parser.set_defaults(func=cmd_remove_td_by_name)

  remove_td_bind_by_index_parser = subparsers.add_parser(
      "remove_td_bind_by_index", help="Remove bind by index"
  )
  remove_td_bind_by_index_parser.add_argument(
      "name",
      type=str,
      help="Name of the TD",
  )
  remove_td_bind_by_index_parser.add_argument(
      "index",
      type=lambda x: int(x, 0),
      help="Index of the bind",
  )
  remove_td_bind_by_index_parser.set_defaults(func=cmd_remove_td_bind_by_index)

  print_tdr_pa_from_pid_parser = subparsers.add_parser(
      "print_tdr_pa_from_pid", help="Print TDR from PID"
  )
  print_tdr_pa_from_pid_parser.add_argument(
      "pid",
      type=lambda x: int(x, 0),
      help="Process ID (PID) of the process",
  )
  print_tdr_pa_from_pid_parser.set_defaults(func=cmd_print_tdr_pa_from_pid)

  print_tdr_pa_from_name_parser = subparsers.add_parser(
      "print_tdr_pa_from_name", help="Print TDR from name"
  )
  print_tdr_pa_from_name_parser.add_argument(
      "name",
      type=str,
      help="Name of the TD",
  )
  print_tdr_pa_from_name_parser.set_defaults(func=cmd_print_tdr_pa_from_name)

  print_state_parser = subparsers.add_parser("print_state", help="Print state")
  print_state_parser.set_defaults(func=cmd_print_state)

  reset_state_parser = subparsers.add_parser("reset_state", help="Reset state")
  reset_state_parser.set_defaults(func=cmd_reset_state)

  args = parser.parse_args()

  try:
    state = State(args.state)

    if hasattr(args, "func"):
      args.func(args, state)
      state.save(args.state)
    else:
      parser.print_help()
  except IOError:
    print(f"Failed to load state: {args.tdx_state}")
