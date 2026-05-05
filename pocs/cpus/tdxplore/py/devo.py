from enum import Enum
from logging import DEBUG, getLogger
from random import choice, choices, randbytes, randint, seed as randseed
from string import ascii_letters, ascii_lowercase, ascii_uppercase, digits, printable, punctuation
from typing import Any, Callable, Optional, Sequence

maxuchar = 2**8 - 1
minuchar = 0

maxchar = 2**7 - 1
minchar = -maxchar

maxushort = 2**16 - 1
minushort = 0

maxshort = 2**15 - 1
minshort = -maxshort

maxuint = 2**32 - 1
minuint = 0

maxint = 2**31 - 1
minint = -maxint

maxulong = 2**64 - 1
minulong = 0

maxlong = 2**63 - 1
minlong = -maxlong

maxutf8 = 0x10FFFF
minutf8 = 0


class Resize(Enum):
  ADD = 1
  DELETE = 2
  SKIP = 3


class Devo:

  def __init__(
      self,
      seed: int = randint(minlong, maxlong),
      name: str = __name__,
      level: Any = DEBUG,
  ):

    self.name = name

    self.logger = getLogger(name)
    self.logger.debug('__init__')

    self.seed = seed

    randseed(self.seed)

  def reseed(self) -> int:
    self.seed = self.randint()
    randseed(self.seed)

  def randchoice(self, set: list[Any], weights: Sequence[float] = None) -> Any:
    return choices(set, weights)[0]

  def randint(self, start: int = minint, stop: int = maxint) -> int:
    return randint(start, stop)

  def randlong(self, start: int = minlong, stop: int = maxlong) -> int:
    return randint(start, stop)

  def randbyte(self) -> int:
    return randint(0, 0xFF)

  def randbytes(self, size: int) -> bytes:
    return randbytes(size)

  def randascii(self, set: str = printable) -> chr:
    return choice(set)

  def randasciis(self, size: int, set: str = printable) -> str:
    return ''.join(choices(list(set), k=size))

  def randutf8(self) -> chr:
    return chr(randint(minutf8, maxutf8))

  def randutf8s(self, size: int) -> str:

    array = list()

    for i in range(size):
      array.append(self.randutf8())

    return ''.join(array)

  def seqbytes(self, count: int) -> bytes:

    array = list()

    i = 0
    while len(array) < count:
      array.append(i % maxuchar)
      array.append(i % maxuchar)
      array.append(i % maxuchar)
      array.append(i % maxuchar)
      i = i + 1

    return bytes(array[:count])

  def seqasciis(self, count: int) -> str:

    array = list()

    i = 0
    while len(array) < count:
      array.append(ascii_lowercase[i % len(ascii_lowercase)])
      array.append(ascii_uppercase[i % len(ascii_uppercase)])
      array.append(ascii_lowercase[i % len(ascii_lowercase)])
      array.append(ascii_uppercase[i % len(ascii_uppercase)])
      i = i + 1

    return ''.join(array[:count])

  def mutasciis(
      self,
      string: str,
      count: int,
      resize: dict = {Resize.ADD: 0.1, Resize.DELETE: 0.1, Resize.SKIP: 0.8},
  ) -> str:

    array = list(string)

    for i in range(count):
      index = self.randint(0, len(array) - 1)

      tmp = self.randchoice(list(resize.keys()), list(resize.values()))
      if tmp == Resize.ADD:
        array.insert(index, self.randascii())
      elif tmp == Resize.DELETE:
        del array[index]
      else:
        array[index] = self.randascii()

    return ''.join(array)

  def mututf8s(
      self,
      string: str,
      count: int,
      resize: dict = {Resize.ADD: 0.1, Resize.DELETE: 0.1, Resize.SKIP: 0.8},
  ) -> bytes:

    array = list(string)
    for i in range(count):
      index = self.randint(0, len(array) - 1)

      tmp = self.randchoice(list(resize.keys()), list(resize.values()))
      if tmp == Resize.ADD:
        array.insert(index, self.randutf8())
      elif tmp == Resize.DELETE:
        del array[index]
      else:
        array[index] = self.randutf8()

    return ''.join(array)

  def mutbytes(
      self,
      buffer: bytes,
      count: int,
      resize: dict = {Resize.ADD: 0.1, Resize.DELETE: 0.1, Resize.SKIP: 0.8},
  ) -> bytes:

    array = bytearray(buffer)
    for i in range(count):
      index = self.randint(0, len(array) - 1)

      tmp = self.randchoice(list(resize.keys()), list(resize.values()))
      if tmp == Resize.ADD:
        array.insert(index, self.randbyte())
      elif tmp == Resize.DELETE:
        del array[index]
      else:
        array[index] = self.randbyte()

    return bytes(array)


def genint8(
    devo: Optional[Devo] = None, value: Optional[int] = None
) -> Callable:
  return lambda: devo.randint(minchar, maxchar) if value is None else value


def genuint8(
    devo: Optional[Devo] = None, value: Optional[int] = None
) -> Callable:
  return lambda: devo.randint(minuchar, maxuchar) if value is None else value


def genint16(
    devo: Optional[Devo] = None, value: Optional[int] = None
) -> Callable:
  return lambda: devo.randint(minshort, maxshort) if value is None else value


def genuint16(
    devo: Optional[Devo] = None, value: Optional[int] = None
) -> Callable:
  return lambda: devo.randint(minushort, maxushort) if value is None else value


def genint32(
    devo: Optional[Devo] = None, value: Optional[int] = None
) -> Callable:
  return lambda: devo.randint(minint, maxint) if value is None else value


def genuint32(
    devo: Optional[Devo] = None, value: Optional[int] = None
) -> Callable:
  return lambda: devo.randint(minuint, maxuint) if value is None else value


def genint64(
    devo: Optional[Devo] = None, value: Optional[int] = None
) -> Callable:
  return lambda: devo.randint(minlong, maxlong) if value is None else value


def genuint64(
    devo: Optional[Devo] = None, value: Optional[int] = None
) -> Callable:
  return lambda: devo.randint(minulong, maxulong) if value is None else value


def genbytes(
    size: int, devo: Optional[Devo] = None, value: Optional[bytes] = None
) -> Callable:
  return lambda: devo.randbytes(size) if value is None else value[:size]


def genasciis(
    size: int, devo: Optional[Devo] = None, value: Optional[str] = None
) -> Callable:
  return (
      lambda: devo.randasciis(size).encode('utf-8')
      if value is None
      else value[:size].encode('utf-8')
  )


def test_gens():

  mins = [
      minchar,
      minuchar,
      minshort,
      minushort,
      minint,
      minuint,
      minlong,
      minulong,
  ]
  maxs = [
      maxchar,
      maxuchar,
      maxshort,
      maxushort,
      maxint,
      maxuint,
      maxlong,
      maxulong,
  ]
  gens = [
      genint8,
      genuint8,
      genint16,
      genuint16,
      genint32,
      genuint32,
      genint64,
      genuint64,
  ]

  assert len(mins) == len(maxs) == len(gens)

  for i in range(len(gens)):
    generator = gens[i](devo=Devo(0))
    value = generator()
    assert value >= mins[i]
    assert value <= maxs[i]

    generator = gens[i](value=i)
    value = generator()
    assert value == i

  generator = genbytes(16, Devo(0))
  value = generator()
  assert len(value) == 16

  generator = genasciis(16, Devo(0))
  value = generator()
  assert len(value) == 16


def test_seqbytes():

  tmp = Devo(0).seqbytes(16)

  assert len(tmp) == 16
  assert (
      tmp == b'\x00\x00\x00\x00\x01\x01\x01\x01\x02\x02\x02\x02\x03\x03\x03\x03'
  )


def test_seqasciis():

  string = Devo(0).seqasciis(16)

  assert len(string) == 16
  assert string == 'aAaAbBbBcCcCdDdD'


def test_mutbytes():

  original = b'\x00\xff\xaa\xbb\xcc\xdd\xee\xff'
  mutated = Devo(0).mutbytes(original, 64)

  assert original != mutated


def test_mututf8s():

  original = (
      '∮ E⋅da = Q,  n → ∞, ∑ f(i) = ∏ g(i), ∀x∈: ⌈x⌉ = ⌊x⌋, ∧ ¬β = ¬(¬α β)'
  )
  mutated = Devo(0).mututf8s(original, 32)

  assert original != mutated


def test_mutasciis():

  original = 'The quick brown fox jumps over the lazy dog.'
  mutated = Devo(0).mutasciis(original, 32)

  assert original != mutated


def test_randutf8s():

  string = Devo(0).randutf8s(512)
  assert len(string) == 512

  for char in string:
    assert ord(char) >= minutf8 and ord(char) <= maxutf8


def test_randasciis():

  string = Devo(0).randasciis(8)
  assert len(string) == 8

  for char in string:
    assert char in (ascii_letters + digits + punctuation)


def test_randbytes():

  tmp = Devo(0).randbytes(16)
  assert len(tmp) == 16


def test_utf8():

  tmp = Devo(0).randutf8()

  assert ord(tmp) >= minutf8 and ord(tmp) <= maxutf8


def test_ascii():

  tmp = Devo(0).randascii()

  assert tmp in printable


def test_byte():

  tmp = Devo(0).randbyte()

  assert tmp > 0 and tmp < 0xFF


def test_randint():

  value = Devo(0).randint()
  assert value >= minint and value <= maxint

  value = Devo(0).randint(0, 128)
  assert value >= 0 and value <= 128

  value = Devo(0).randint(-128, 0)
  assert value >= -128 and value <= 0


def test_randlong():

  value = Devo(0).randlong()
  assert value >= minlong and value <= maxlong

  value = Devo(0).randlong(0, 256)
  assert value > 0 and value < 256

  value = Devo(0).randint(-256, 0)
  assert value >= -256 and value <= 0


def test_randchoice():

  options = ['hello', 'goodbye', 'world']

  tmp = Devo(0).randchoice(options)

  assert tmp in options


if __name__ == '__main__':

  test_seqbytes()

  print('run "pytest devo.py -v -rP"')
