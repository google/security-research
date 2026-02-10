from argparse import ArgumentParser
from boxy import SIZEOF_UINT64
from tdxtend import SIZEOF_STRUCT_MD_LIST_HEADER, Tdxtend
from gateway import FOUR_KILOBYTES, Gateway

def main():

  parser = ArgumentParser(description="mig_bundle_parse")

  parser.add_argument(
      "bundle",
      type=str,
      default="bundle.bin",
      help="file for the metadata bundle",
  )

  parser.add_argument(
      "--verbose",
      action="store_true",
      help="Verbose output",
  )

  args = parser.parse_args()

  zylex = Gateway()
  tdxtend = Tdxtend(0, zylex)

  buffers = []
  with open(args.bundle, "rb") as f:
    while True:
      buffer = f.read(FOUR_KILOBYTES)

      if not buffer:
        break

      buffers.append(buffer)

  i = 0
  for buffer in buffers:
    print(f"dumping buffer[{i}]")
    md_list, _ = tdxtend.make_md_list(buffer)
    md_list.decode(buffer)

    if args.verbose:
      print(md_list)

    sequence_index = 0

    for _ in range(md_list.get("num_sequences")):
      position = (sequence_index * SIZEOF_UINT64) + SIZEOF_STRUCT_MD_LIST_HEADER
      md_sequence, _ = tdxtend.make_md_sequence(
          md_list.get(f"sequence {sequence_index}"), buffer[position:]
      )

      if args.verbose:
        print(md_sequence)

      sequence_index += 1
      sequence_index += tdxtend.print_md_sequence(md_sequence)

    i += 1


if __name__ == "__main__":
  main()
