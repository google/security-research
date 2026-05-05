from argparse import ArgumentParser
from os import kill
from signal import SIGCONT


def main():
  parser = ArgumentParser(description="qemu_resume")

  parser.add_argument("pid", type=int, help="Process ID (PID) for the process")

  args = parser.parse_args()

  kill(args.pid, SIGCONT)
  
if __name__ == "__main__":
  main()
