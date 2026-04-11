from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from logging import DEBUG, getLogger
from struct import calcsize, pack, unpack
from typing import Any, Callable, Sequence
from devo import Devo, genasciis, genbytes, genint16, genint32, genint64, genint8, genint8, genuint16, genuint32, genuint64
from pytest import approx


SIZEOF_UINT64 = 8
SIZEOF_UINT32 = 4
SIZEOF_UINT16 = 2
SIZEOF_UINT8 = 1

SIZEOF_INT64 = 8
SIZEOF_INT32 = 4
SIZEOF_INT16 = 2
SIZEOF_INT8 = 1


class Endian(Enum):
  NONE = ''
  NATIVE = '='
  LITTLE = '<'
  BIG = '>'
  NETWORK = '!'


class DataType(Enum):
  CHAR = 'b'  # 1 byte
  UNSIGNED_CHAR = 'B'  # 1 byte
  SHORT = 'h'  # 2 bytes
  UNSIGNED_SHORT = 'H'  # 2 bytes
  INT = 'i'  # 4 bytes
  UNSIGNED_INT = 'I'  # 4 bytes
  LONG_LONG = 'q'  # 8 bytes
  UNSIGNED_LONG_LONG = 'Q'  # 8 bytes
  FLOAT = 'f'  # 4 bytes
  DOUBLE = 'd'  # 8 bytes

  BYTES = 's'
  STRING = 's'
  VOID_POINTER = 'P'

  INT8 = CHAR
  UINT8 = UNSIGNED_CHAR
  INT16 = SHORT
  UINT16 = UNSIGNED_SHORT
  INT32 = INT
  UINT32 = UNSIGNED_INT
  INT64 = LONG_LONG
  UINT64 = UNSIGNED_LONG_LONG


def hexdump(data: bytes):
  def to_printable_ascii(byte):
    return chr(byte) if 32 <= byte <= 126 else '.'

  offset = 0
  while offset < len(data):
    chunk = data[offset : offset + 16]
    hex_values = ' '.join(f'{byte:02x}' for byte in chunk)
    ascii_values = ''.join(to_printable_ascii(byte) for byte in chunk)
    print(f'{offset:08x}  {hex_values:<48}  |{ascii_values}|')
    offset += 16


class Boxy:

  @dataclass
  class Item:
    endian: Endian
    datatype: DataType
    callback: Callable

  def __init__(self, name: str = __name__, endian=Endian.NATIVE):

    self.logger = getLogger(name)
    self.logger.debug('__init__')

    self.endian = endian
    self.items = OrderedDict()

  def encode(self) -> bytes:

    self.logger.debug('encode')

    array = bytearray()

    for key, item in self.items.items():
      if item.datatype == DataType.BYTES:
        tmp = item.callback()
        array.extend(
            pack(f'{self.endian.value}{len(tmp)}{item.datatype.value}', tmp)
        )
      else:
        array.extend(
            pack(self.endian.value + item.datatype.value, item.callback())
        )

    return bytes(array)

  def decode(self, buffer: bytes):

    self.logger.debug('decode')

    offset = 0
    for key, item in self.items.items():
      if item.datatype == DataType.BYTES:
        length = len(item.callback())
        (tmp,) = unpack(
            f'{self.endian.value}{length}{item.datatype.value}',
            buffer[offset : offset + length],
        )
        item.callback = lambda value=tmp: value
      elif item.datatype == DataType.VOID_POINTER:
        length = calcsize(f'{item.datatype.value}')
        (tmp,) = unpack(
            f'{item.datatype.value}',
            buffer[offset : offset + length],
        )
        item.callback = lambda value=tmp: value
      else:
        length = calcsize(f'{self.endian.value}{item.datatype.value}')
        (tmp,) = unpack(
            f'{self.endian.value}{item.datatype.value}',
            buffer[offset : offset + length],
        )
        item.callback = lambda value=tmp: value

      offset += length

  def get(self, name: str) -> Any:
    return self.items[name].callback()

  def set(self, name: str, value: Any):
    self.items[name].callback = lambda value=value: value

  def addfield(
      self,
      name: str,
      type: DataType,
      callback: Callable,
      endian: Endian = Endian.NONE,
  ):

    self.logger.debug('addfield')

    if endian == Endian.NONE:
      endian = self.endian

    self.items[name] = Boxy.Item(endian, type, callback)

  def delfield(self, name: str):

    self.logger.debug('delfield')

    del self.items[name]

  def __str__(self) -> str:

    lines = [
        f'Boxy Object (Name: {self.logger.name}, Endian: {self.endian.name}):'
    ]

    for key, item in self.items.items():
      value = item.callback()
      if item.datatype == DataType.BYTES:
        string = {value.hex()}
      elif item.datatype == DataType.VOID_POINTER:
        string = f'0x{value:0X}' if value is not None else 'None'
      else:
        string = hex(value)

      lines.append(f'  {key}: {item.datatype.name} = {string}')
    return '\n'.join(lines)


def test_addfield():

  boxy = Boxy()

  for i in range(8):
    boxy.addfield(f'field{i}', DataType.INT8, genint8(value=i))

  assert len(boxy.items) == 8

  for i in range(8):
    assert list(boxy.items.keys())[i] == f'field{i}'


def test_delfield():

  boxy = Boxy()

  for i in range(8):
    boxy.addfield(f'field{i}', DataType.INT8, genint8(value=i))

  boxy.delfield('field2')
  assert len(boxy.items) == 7

  for i in range(7):
    assert list(boxy.items.keys())[i] != f'field2'

  assert boxy.encode() == b'\x00\x01\x03\x04\x05\x06\x07'


def test_encode_decode():

  boxy = Boxy()

  boxy.addfield('uint8 field', DataType.UINT8, genint8(value=0))
  boxy.addfield('uint16 field', DataType.UINT16, genint16(value=1))
  boxy.addfield('uint32 field', DataType.UINT32, genint8(value=2))
  boxy.addfield('uint64 field', DataType.UINT64, genint8(value=3))
  boxy.addfield('float field', DataType.FLOAT, genint8(value=0.05))
  boxy.addfield('double field', DataType.DOUBLE, genint8(value=0.10))
  boxy.addfield('int8 field', DataType.INT8, genint8(value=-1))
  boxy.addfield('int16 field', DataType.INT16, genint8(value=-2))
  boxy.addfield('int32 field', DataType.INT32, genint8(value=-3))
  boxy.addfield('int64 field', DataType.INT64, genint8(value=-4))
  boxy.addfield(
      'bytes field', DataType.BYTES, genbytes(16, value=b'Hello World')
  )
  boxy.addfield(
      'string field', DataType.STRING, genasciis(16, value='Goodbye World')
  )

  assert (
      boxy.encode()
      == b"""\x00\x01\x00\x02\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\xcd\xccL=\x9a\x99\x99\x99\x99\x99\xb9?\xff\xfe\xff\xfd\xff\xff\xff\xfc\xff\xff\xff\xff\xff\xff\xffHello WorldGoodbye World"""
  )

  buffer = b"""\xff\x11\x00\x22\x00\x00\x00\x33\x00\x00\x00\x00\x00\x00\x00\xcd\xccL=\x9a\x99\x99\x99\x99\x99\xb9?\xef\xfe\xef\xfd\xef\xff\xff\xfc\xef\xff\xff\xff\xff\xff\xffHello EarthGoodbye Earth"""
  boxy.decode(buffer)

  assert boxy.get('uint8 field') == 255
  assert boxy.get('uint16 field') == 17
  assert boxy.get('uint32 field') == 34
  assert boxy.get('uint64 field') == 51
  assert approx(boxy.get('float field')) == 0.05
  assert approx(boxy.get('double field')) == 0.10
  assert boxy.get('int8 field') == -17
  assert boxy.get('int16 field') == -4098
  assert boxy.get('int32 field') == -4099
  assert boxy.get('int64 field') == -4100
  assert boxy.get('bytes field') == b'Hello Earth'
  assert boxy.get('string field').decode('utf-8') == 'Goodbye Earth'


if __name__ == '__main__':

  test_delfield()

  print('run "pytest boxy.py -v -rP"')
