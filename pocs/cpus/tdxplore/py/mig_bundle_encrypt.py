from argparse import ArgumentParser
from os import urandom
from shutil import copyfile
from struct import pack
from boxy import Boxy, DataType, Endian
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from devo import genbytes, genuint16, genuint32, genuint64, genuint8


def main():

  parser = ArgumentParser(description="mig_bundle_encrypt")

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
      "plaintext",
      type=str,
      default="plaintext.bin",
      help="file for the input plaintext",
  )

  parser.add_argument(
      "mbmd",
      type=str,
      default="mbmd.bin",
      help="file for the migration bundle metadata",
  )

  parser.add_argument(
      "ciphertext",
      type=str,
      default="ciphertext.bin",
      help="file for the output ciphertext",
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

  with open(args.plaintext, "rb") as f:
    plaintext = f.read()

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
      modes.GCM(iv),
      backend=default_backend(),
  )

  encryptor = cipher.encryptor()

  tmp = mbmd.get("iv_counter")
  mbmd.set("iv_counter", 0)
  encryptor.authenticate_additional_data(mbmd.encode()[: -len(mbmd.get("mac"))])
  mbmd.set("iv_counter", tmp)

  ciphertext = encryptor.update(plaintext)
  ciphertext += encryptor.finalize()

  with open(args.ciphertext, "wb") as f:
    f.write(ciphertext)

  mbmd.set("mac", encryptor.tag)
  with open(args.mbmd, "wb") as f:
    f.write(mbmd.encode())


if __name__ == "__main__":
  main()
