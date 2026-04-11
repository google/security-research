from argparse import ArgumentParser
from os import kill
from signal import SIGSTOP


def main():
  parser = ArgumentParser(description="qemu_stop")

  parser.add_argument("pid", type=int, help="Process ID (PID) for the process")

  args = parser.parse_args()

  kill(args.pid, SIGSTOP)
