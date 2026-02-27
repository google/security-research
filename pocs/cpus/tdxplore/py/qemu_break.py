from argparse import ArgumentParser
from enum import Enum
from os import SCHED_FIFO, kill, sched_param, sched_setscheduler
from signal import SIGCONT, SIGSTOP
from boxy import Boxy, DataType, Endian, genuint32, genuint64
import ptrace.debugger
from ptrace.debugger import (
    Application,
    NewProcessEvent,
    ProcessExecution,
    ProcessExit,
    ProcessSignal,
    PtraceDebugger,
)
import ptrace.signames
import ptrace.syscall
import ptrace.tools
from tdxtend import Tdxtend
from gateway import Gateway

IOCTL_NR = 16

KVMIO = 0xAE
KVM_MEMORY_ENCRYPT_OP = 0xBA
KVM_TDX_CMD_SIZE = 32


class KvmTdxCmdId(Enum):
  KVM_TDX_CAPABILITIES = 0
  KVM_TDX_INIT_VM = 1
  KVM_TDX_INIT_VCPU = 2
  KVM_TDX_EXTEND_MEMORY = 3
  KVM_TDX_FINALIZE_VM = 4


IOC_NRBITS = 8
IOC_TYPEBITS = 8
IOC_SIZEBITS = 14
IOC_DIRBITS = 2

IOC_NRMASK = (1 << IOC_NRBITS) - 1
IOC_TYPEMASK = (1 << IOC_TYPEBITS) - 1
IOC_SIZEMASK = (1 << IOC_SIZEBITS) - 1
IOC_DIRMASK = (1 << IOC_DIRBITS) - 1

IOC_NRSHIFT = 0
IOC_TYPESHIFT = IOC_NRBITS
IOC_SIZESHIFT = IOC_NRBITS + IOC_TYPEBITS
IOC_DIRSHIFT = IOC_NRBITS + IOC_TYPEBITS + IOC_SIZEBITS


def decode_ioctl_request(request: int):

  direction = (request >> IOC_DIRSHIFT) & IOC_DIRMASK
  size = (request >> IOC_SIZESHIFT) & IOC_SIZEMASK
  _type_ = (request >> IOC_TYPESHIFT) & IOC_TYPEMASK
  command = (request >> IOC_NRSHIFT) & IOC_NRMASK

  return {
      "direction": direction,
      "size": size,
      "type": _type_,
      "command": command,
  }


def main():
  parser = ArgumentParser(description="qemu_break")

  parser.add_argument(
      "--command",
      type=lambda x: getattr(KvmTdxCmdId, x, None),
      choices=[
          "KVM_TDX_CAPABILITIES",
          "KVM_TDX_INIT_VM",
          "KVM_TDX_INIT_VCPU",
          "KVM_TDX_EXTEND_MEMORY",
          "KVM_TDX_FINALIZE_VM",
      ],
      default="KVM_TDX_EXTEND_MEMORY",
      help="Operation state to stop at",
  )

  args = parser.parse_args()

  sched_setscheduler(0, SCHED_FIFO, sched_param(99))

  gateway = Gateway()
  tdxtend = Tdxtend(0, gateway)

  kvm_tdx_cmd = Boxy("struct kvm_tdx_cmd", endian=Endian.LITTLE)
  kvm_tdx_cmd.addfield("id", DataType.UINT32, genuint32(value=0))
  kvm_tdx_cmd.addfield("flags", DataType.UINT32, genuint32(value=0))
  kvm_tdx_cmd.addfield("data", DataType.UINT64, genuint64(value=0))
  kvm_tdx_cmd.addfield("error", DataType.UINT64, genuint64(value=0))

  for i in range(2):
    pid = tdxtend.watch_for_process_creation("td")

  debugger = ptrace.debugger.PtraceDebugger()

  process = debugger.addProcess(pid, False)

  tdxtend = Tdxtend(pid, gateway)
  vm_fd = None

  while True:
    process.syscall()

    try:
      process.waitSyscall()
    except NewProcessEvent as event:
      print(f"NewProcessEvent: {event}")
      continue
    except ProcessExit as event:
      print(f"ProcessExit: {event}")
      continue
    except ProcessSignal as event:
      print(f"ProcessSignal: {event}")
      continue

    if vm_fd == None:
      try:
        vm_fd = tdxtend.get_vm_fd()
      except ValueError:
        continue

    regs = process.getregs()

    if regs.orig_rax == IOCTL_NR and regs.rdi == vm_fd:
      request = decode_ioctl_request(regs.rsi)
      if (
          request["type"] == KVMIO
          and request["command"] == KVM_MEMORY_ENCRYPT_OP
      ):
        kvm_tdx_cmd.decode(process.readBytes(regs.rdx, KVM_TDX_CMD_SIZE))

        # print(kvm_tdx_cmd)

        if kvm_tdx_cmd.get("id") == args.command.value:
          print(f"stopping {pid} at {args.command}")
          kill(pid, SIGSTOP)
          break


if __name__ == "__main__":
  main()
