from argparse import ArgumentParser
from os import urandom
from struct import pack
from boxy import Boxy, DataType, Endian
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from devo import genbytes, genuint16, genuint32, genuint64, genuint8


def main():

  parser = ArgumentParser(description="mig_bundle_decrypt")

  parser.add_argument(
      "key",
      type=str,
      default="0-0-0-0",
      help="key to use",
  )

  parser.add_argument(
      "type",
      choices=["immutable", "td", "vp"],
      help="type of migration bundle",
  )

  parser.add_argument(
      "mbmd",
      type=str,
      help="file for the migration bundle metadata",
  )

  parser.add_argument(
      "cyphertext",
      type=str,
      default="cyphertext.bin",
      help="file for the input ciphertext",
  )

  parser.add_argument(
      "plaintext",
      type=str,
      default="plaintext.bin",
      help="file for the output plaintext",
  )

  parser.add_argument(
      "--verbose",
      action="store_true",
      help="Verbose output",
  )

  args = parser.parse_args()

  parts = args.key.split("-")
  if len(parts) != 4:
    raise ValueError("key must be 4 parts")

  tmp = []
  for part in parts:
    tmp.append(int(part, 16))

  key = pack("<QQQQ", *tmp)

  with open(args.cyphertext, "rb") as f:
    ciphertext = f.read()

  mbmd = Boxy("struct mbmd", endian=Endian.LITTLE)

  mbmd.addfield("size", DataType.UINT16, genuint16(value=0))
  mbmd.addfield("mig_version", DataType.UINT16, genuint16(value=0))
  mbmd.addfield("migs_index", DataType.UINT16, genuint16(value=0))
  mbmd.addfield("mb_type", DataType.UINT8, genuint8(value=0))
  mbmd.addfield("reserved_1", DataType.UINT8, genuint8(value=0))
  mbmd.addfield("mb_counter", DataType.UINT32, genuint32(value=0))
  mbmd.addfield("mig_epoch", DataType.UINT32, genuint32(value=0))
  mbmd.addfield("iv_counter", DataType.UINT64, genuint64(value=0))

  if args.type == "immutable":
    mbmd.addfield("num_f_migs", DataType.UINT16, genuint16(value=0))
    mbmd.addfield("reserved_0", DataType.UINT16, genuint16(value=0))
    mbmd.addfield("num_sys_md_pages", DataType.UINT32, genuint32(value=0))
    mbmd.addfield("mac", DataType.BYTES, genbytes(16, value=b"\x00" * 16))
  elif args.type == "td":
    mbmd.addfield("reserved_0", DataType.UINT64, genuint64(value=0))
    mbmd.addfield("mac", DataType.BYTES, genbytes(16, value=b"\x00" * 16))
  elif args.type == "vp":
    mbmd.addfield("vp_index", DataType.UINT64, genuint64(value=0))
    mbmd.addfield("mac", DataType.BYTES, genbytes(16, value=b"\x00" * 16))

  with open(args.mbmd, "rb") as f:
    mbmd.decode(f.read())

  if args.verbose:
    print(mbmd)

  iv = pack("<QHH", mbmd.get("iv_counter"), 0, 0)

  cipher = Cipher(
      algorithms.AES(key),
      modes.GCM(iv, mbmd.get("mac")),
      backend=default_backend(),
  )

  decryptor = cipher.decryptor()

  mbmd.set("iv_counter", 0)
  decryptor.authenticate_additional_data(mbmd.encode()[: -len(mbmd.get("mac"))])

  plaintext = decryptor.update(ciphertext)
  plaintext += decryptor.finalize()

  with open(args.plaintext, "wb") as f:
    f.write(plaintext)


if __name__ == "__main__":
  main()
