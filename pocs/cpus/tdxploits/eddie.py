""""""

from argparse import ArgumentParser
from subprocess import CalledProcessError, run

from boxy import Boxy, DataType, Endian, SIZEOF_UINT64
from devo import genbytes, genuint16, genuint32, genuint64, genuint8
from tdxamine import State, TdData
from tdxtend import CLASS_CODE_SHIFT, CONTEXT_CODE_SHIFT, ELEMENT_SIZE_CODE_SHIFT, IGNORED_SHIFT, INC_SIZE_SHIFT, LAST_ELEMENT_IN_FIELD_SHIFT, LAST_FIELD_IN_SEQUENCE_SHIFT, SIZEOF_STRUCT_MD_LIST_HEADER, TdxContextCode, TdxMigrationBundleType, Tdxtend, WRITE_MASK_VALID_SHIFT
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


def cmd_build(args):

  md_lists = []
  sequences = []

  field_id = 0x1C200000001  # PKG_FMS
  elements = [0x806F8, 0x806F8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x800004200000000  # VENDOR_ID
  elements = [0x8086, 0x134DA10]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x8800010100000002  # BUILD_NUM
  elements = [0x32D, 0x5, 0x1, 0x9, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0xA00000200000000  # SYS_ATTRIBUTES
  elements = [0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0xA00000000000001  # NUM_TDX_FEATURES
  elements = [0x1]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0xA00000300000008  # TDX_FEATURES0
  elements = [0x26F1F0FBF]
  sequences.append(make_md_sequence(field_id, elements))

  md_list = make_md_list(0, len(sequences) - 1, sequences)
  md_list.set("list_buff_size", len(md_list.encode()))
  md_lists.append(md_list)

  sequences = []

  field_id = 0x8010000F00000020  # TD_UUID
  elements = [0xDE7EC7ED, 0xBAD0C0FE, 0xDE7EC7ED, 0xBAD0C0FE]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9010000200000001  # NUM_VCPUS
  elements = [0x10]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9010000100000005  # NUM_L2_VMS
  elements = [0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x1110004300000000  # ATTRIBUTES
  elements = [0x30000000, 0x602E7]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x1110000200000002  # MAX_VCPUS
  elements = [0x10]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x1110000000000003  # GPAW
  elements = [0x1]
  sequences.append(make_md_sequence(field_id, elements))

  elements = [0x0, 0xDE7EC7ED]
  field_id = make_field_identifier(
      context_code=TdxContextCode.MD_CTX_TD.value,
      class_code=17,
      field_code=4,
      element_size_code=3,
      last_field_in_sequence=0,
      last_element_in_field=0,
      write_mask_valid=1,
      inc_size=0,
      ignored=0,
  )  # EPTP

  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x111000010000000C  # TSC_FREQUENCY
  elements = [0x58]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x911000010000000E  # NUM_CPUID_VALUES
  elements = [0x4F]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x911000020000000F  # XBUFF_SIZE
  elements = [0x2A00]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9110000300000016  # CONFIG_FLAGS
  elements = [0x1]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9110004000000019  # TOPOLOGY_ENUM_CONFIGURED
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9110000300000021  # CPUID_FIXED0_BITMAP
  elements = [0x380000508CFD308]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x911000CE00000200  # CPUID4_NATIVE_VALUES
  elements = [
      0xFC004121,
      0x2C0003F,
      0x3F,
      0x0,
      0xFC004122,
      0x1C0003F,
      0x3F,
      0x0,
      0xFC004143,
      0x3C0003F,
      0x7FF,
      0x0,
      0xFC1FC163,
      0x380003F,
      0x1BFFF,
      0x4,
  ]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x1310001700000000  # MRTD
  elements = [
      0x0011223344556677,
      0x8899AABBCCDDEEFF,
      0x7766554433221100,
      0xFFEEDDCCBBAA9988,
      0x0000000000000000,
      0x1111111111111111,
  ]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x1310001700000010  # MRCONFIGID
  elements = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x1310001700000018  # MROWNER
  elements = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x1310001700000020  # MROWNERCONFIG
  elements = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x94100007000003FE  # CPUID_VALUES
  elements = [0x100800000806F8, 0x3FA9FBFFF7FAB217]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700000800  # CPUID_VALUES
  elements = [0x1C0003F3C000121, 0x10000003F]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700000802  # CPUID_VALUES
  elements = [0x1C0003F3C000122, 0x10000003F]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700000804  # CPUID_VALUES
  elements = [0x3C0003F3C000143, 0x100000FFF]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700000806  # CPUID_VALUES
  elements = [0x3C0003F3C03C163, 0x600003FFF]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700000E00  # CPUID_VALUES
  elements = [0xF1BF2FF900000002, 0xFFC144101B415F6E]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700000E02  # CPUID_VALUES
  elements = [0x1C30, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x94100007000015FE  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x94100007000039FE  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x94100007000111FE  # CPUID_VALUES
  elements = [0x20000003934, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x94100007000001FE  # CPUID_VALUES
  elements = [0x756E654700000023, 0x49656E696C65746E]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x94100007000007FE  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700000808  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700000DFE  # CPUID_VALUES
  elements = [0x4, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700000E04  # CPUID_VALUES
  elements = [0x0, 0x1700000000]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x94100007000011FE  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A00  # CPUID_VALUES
  elements = [0x602E7, 0x2B00]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A02  # CPUID_VALUES
  elements = [0x1F, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A04  # CPUID_VALUES
  elements = [0x24000000100, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A06  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A08  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A0A  # CPUID_VALUES
  elements = [0x44000000040, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A0C  # CPUID_VALUES
  elements = [0x48000000200, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A0E  # CPUID_VALUES
  elements = [0x68000000400, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A10  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A12  # CPUID_VALUES
  elements = [0xA8000000008, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A14  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A16  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A18  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A1A  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A1C  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A1E  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A20  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A22  # CPUID_VALUES
  elements = [0xAC000000040, 0x2]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001A24  # CPUID_VALUES
  elements = [0xB0000002000, 0x6]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001DFE  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x94100007000023FE  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x94100007000025FE  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x94100007000027FE  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700002800  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700002802  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700002BFE  # CPUID_VALUES
  elements = [0x5800000001, 0x17D7840]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x94100007000033FE  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700003A00  # CPUID_VALUES
  elements = [0x1, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700003A02  # CPUID_VALUES
  elements = [0x8004004002000, 0x10]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700003DFE  # CPUID_VALUES
  elements = [0x401000000000, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700003E00  # CPUID_VALUES
  elements = [0x200000001, 0x100]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700003E02  # CPUID_VALUES
  elements = [0x7000000007, 0x201]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700003E04  # CPUID_VALUES
  elements = [0x0, 0x2]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700003E06  # CPUID_VALUES
  elements = [0x0, 0x3]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700003E08  # CPUID_VALUES
  elements = [0x0, 0x4]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700003E0A  # CPUID_VALUES
  elements = [0x0, 0x5]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x94100007000041FE  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700004200  # CPUID_VALUES
  elements = [0x65746E4900000000, 0x5844546C20202020]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x94100007000101FE  # CPUID_VALUES
  elements = [0x80000008, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x94100007000103FE  # CPUID_VALUES
  elements = [0x0, 0x2C10000000000121]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700010DFE  # CPUID_VALUES
  elements = [0x0, 0x8007040]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700010FFE  # CPUID_VALUES
  elements = [0x0, 0x10000000000]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x94100007000045FE  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700004600  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700004602  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700004604  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700004606  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700000BFE  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001600  # CPUID_VALUES
  elements = [0x200000001, 0x100]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001602  # CPUID_VALUES
  elements = [0x7000000007, 0x201]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700001604  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x94100007000035FE  # CPUID_VALUES
  elements = [0x0, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700003000  # CPUID_VALUES
  elements = [0x8, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700003002  # CPUID_VALUES
  elements = [0x8000100000000, 0x2200000020]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700003004  # CPUID_VALUES
  elements = [0x8000600000000, 0x2200000004]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700003006  # CPUID_VALUES
  elements = [0x10000F00000000, 0x12500000001]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x94100007000005FE  # CPUID_VALUES
  elements = [0xFEFF01, 0x0]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700003008  # CPUID_VALUES
  elements = [0x4000100000000, 0x2400000010]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x941000070000300A  # CPUID_VALUES
  elements = [0x4000600000000, 0x2400000008]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x941000070000300C  # CPUID_VALUES
  elements = [0x8000800000000, 0x12400000001]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x941000070000300E  # CPUID_VALUES
  elements = [0x8000700000000, 0x4300000080]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9410000700003010  # CPUID_VALUES
  elements = [0x8000900000000, 0x4300000080]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x94100007000105FE  # CPUID_VALUES
  elements = [0x5820445465746E49, 0x6C202020]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x961000030000010A  # VIRTUAL_IA32_ARCH_CAPABILITIES
  elements = [0x28F1EB]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9610000300000480  # VIRTUAL_IA32_VMX_BASIC
  elements = [0x1C0000000000000]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9610010300000485  # VIRTUAL_IA32_VMX_MISC
  elements = [0x600440E0, 0x20, 0x8005003F, 0x2040, 0x773FFF]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x961002030000048B  # VIRTUAL_IA32_VMX_PROCBASED_CTLS2
  elements = [
      0x779BFFE032881F2,
      0x1000000430001,
      0x3F0000003F,
      0xFDFBFFFEB5226DFA,
      0x1F3FEFFF1F3FEFFF,
      0x3ED3FF003ED1FF,
      0x0,
      0xE,
      0x0,
  ]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9810000200000002  # EXPORT_COUNT
  elements = [0x1]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9910001700000000  # SERVTD_HASH
  elements = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6]
  sequences.append(make_md_sequence(field_id, elements))

  field_id = 0x9910000100000006  # SERVTD_NUM # CHECK THIS
  elements = [0x1]
  sequences.append(make_md_sequence(field_id, elements))

  elements = [0] * 120
  field_id = make_field_identifier(
      context_code=TdxContextCode.MD_CTX_TD.value,
      class_code=28,
      field_code=0,
      element_size_code=2,
      last_field_in_sequence=len(elements) - 1,
      last_element_in_field=0,
      write_mask_valid=0,
      inc_size=0,
      ignored=1,
  )  # X2APIC_IDS

  sequences.append(make_md_sequence(field_id, elements))

  md_list = make_md_list(0, len(sequences) - 1, sequences)
  md_list.set("list_buff_size", len(md_list.encode()))
  md_lists.append(md_list)

  sequences = []

  elements = [0] * 456
  field_id = make_field_identifier(
      context_code=TdxContextCode.MD_CTX_TD.value,
      class_code=28,
      field_code=120,
      element_size_code=2,
      last_field_in_sequence=len(elements) - 1,
      last_element_in_field=0,
      write_mask_valid=0,
      inc_size=0,
      ignored=1,
  )  # X2APIC_IDS
  sequences.append(make_md_sequence(field_id, elements))

  md_list = make_md_list(0, len(sequences), sequences)
  md_list.set("list_buff_size", len(md_list.encode()))
  md_lists.append(md_list)

  with open(args.immutable_data, "wb") as f:
    for md_list in md_lists:
      encoded = md_list.encode()
      padding = FOUR_KILOBYTES - len(encoded)

      print(f"md_list size: {len(encoded)}, padding: {padding}")

      f.write(encoded)
      f.write(b"\0" * padding)

  mbmd = Boxy("struct mbmd", endian=Endian.LITTLE)

  mbmd.addfield("size", DataType.UINT16, genuint16(value=48))
  mbmd.addfield("mig_version", DataType.UINT16, genuint16(value=0))
  mbmd.addfield("migs_index", DataType.UINT16, genuint16(value=0))
  mbmd.addfield(
      "mb_type",
      DataType.UINT8,
      genuint8(value=TdxMigrationBundleType.MB_TYPE_IMMUTABLE_TD_STATE.value),
  )
  mbmd.addfield("reserved_1", DataType.UINT8, genuint8(value=0))
  mbmd.addfield("mb_counter", DataType.UINT32, genuint32(value=0))
  mbmd.addfield("mig_epoch", DataType.UINT32, genuint32(value=0))
  mbmd.addfield("iv_counter", DataType.UINT64, genuint64(value=1))
  mbmd.addfield("num_f_migs", DataType.UINT16, genuint16(value=1))
  mbmd.addfield("reserved_2", DataType.UINT16, genuint16(value=0))
  mbmd.addfield("num_sys_md_pages", DataType.UINT32, genuint32(value=1))
  mbmd.addfield("mac", DataType.BYTES, genbytes(16, value=b"\x00" * 16))

  with open(args.immutable_mbmd, "wb") as f:
    f.write(mbmd.encode())


def main():

  parser = ArgumentParser(
      prog="eddie",
      description=(
          "Malfunctioning Eddie: Pleased to meet you. Actually we’ve met once"
          " before. WHAT?!"
      ),
  )

  parser.add_argument(
      "--state",
      type=str,
      default="state.pickle",
      help="State to load",
  )

  subparsers = parser.add_subparsers(dest="command")

  build_parser = subparsers.add_parser(
      "build", help="Build TD Immutable MD list"
  )
  build_parser.add_argument("immutable_data", type=str, help="Output data file")
  build_parser.add_argument(
      "immutable_mbmd",
      type=str,
      help="Output mbmd file",
  )
  build_parser.set_defaults(func=cmd_build)

  args = parser.parse_args()

  if hasattr(args, "func"):
    args.func(args)
  else:
    parser.print_help()


if __name__ == "__main__":
  main()
