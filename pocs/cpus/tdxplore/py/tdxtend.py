from argparse import ArgumentParser
from enum import Enum
from os import cpu_count, listdir, path, readlink
from platform import release
from sys import stderr
from threading import get_ident
from boxy import Boxy, DataType, Endian, SIZEOF_UINT64
from devo import genbytes, genuint16, genuint32, genuint64, genuint8
from global_sys_metadata import global_sys_metadata_lookup_entry
from psutil import AccessDenied, NoSuchProcess, Process, pids
from tdr_tdcs_metadata import TdrTdcsMetadataClassCode, tdr_tdcs_metadata_lookup_entry
from tdvmcs_metadata import tdvmcs_metadata_lookup_entry
from tdvps_metadata import tdvps_metadata_lookup_entry
from gateway import FOUR_KILOBYTES, Gateway

SERVTD_TYPE_MIGTD = 0
MIN_MIGS = 2
MBMD_SIZE = 128

MIN_TD_IMMUTABLE_STATE_EXPORT_PAGES = 4
MIN_TD_IMMUTABLE_STATE_IMPORT_PAGES = 1

MIN_TD_STATE_IMPORT_PAGES = 1
MIN_TD_STATE_EXPORT_PAGES = 2

MIN_VP_STATE_IMPORT_PAGES = 4
MIN_VP_STATE_EXPORT_PAGES = 9

FIELD_CODE_MASK = 0xFFFFFF

IGNORED_SHIFT = 63
IGNORED_MASK = 0x1 << IGNORED_SHIFT

INC_SIZE_SHIFT = 50
INC_SIZE_MASK = 0x1 << INC_SIZE_SHIFT

WRITE_MASK_VALID_SHIFT = 51
WRITE_MASK_VALID_MASK = 0x1 << WRITE_MASK_VALID_SHIFT

CLASS_CODE_SHIFT = 56
CLASS_CODE_MASK = 0x3F << CLASS_CODE_SHIFT

CONTEXT_CODE_SHIFT = 52
CONTEXT_CODE_MASK = 0x3 << CONTEXT_CODE_SHIFT

ELEMENT_SIZE_CODE_SHIFT = 32
ELEMENT_SIZE_CODE_MASK = 0x3 << ELEMENT_SIZE_CODE_SHIFT

LAST_FIELD_IN_SEQUENCE_SHIFT = 38
LAST_FIELD_IN_SEQUENCE_MASK = 0x1FF << LAST_FIELD_IN_SEQUENCE_SHIFT

LAST_ELEMENT_IN_FIELD_SHIFT = 34
LAST_ELEMENT_IN_FIELD_MASK = 0xF << LAST_ELEMENT_IN_FIELD_SHIFT

SIZEOF_STRUCT_MD_LIST_HEADER = 8
SIZEOF_STRUCT_MD_SEQUENCE_HEADER = 8

TDX_OPERAND_CODE_MASK = 0xFF
TDX_ERROR_CODE_MASK = ~0xFF
TDX_FATAL_FLAG_MASK = 1 << 61
TDX_NON_RECOVERABLE_FLAG_MASK = 1 << 62
TDX_ERROR_FLAG_MASK = 1 << 63

MIN_NUM_TDCS_PAGES = 6
MAX_NUM_TDCS_PAGES = 9

MIN_TDVPS_PAGES = 6
MAX_TDVPS_PAGES = 15


class TdxMigrationBundleType(Enum):
  MB_TYPE_IMMUTABLE_TD_STATE = 0
  MB_TYPE_MUTABLE_TD_STATE = 1
  MB_TYPE_MUTABLE_VCPU_STATE = 2
  MB_TYPE_MEM = 16
  MB_TYPE_EPOCH_TOKEN = 32
  MB_TYPE_ABORT_TOKEN = 33


class TdxContextCode(Enum):
  MD_CTX_SYS = 0
  MD_CTX_TD = 1
  MD_CTX_VP = 2


class TdxErrorCode(Enum):
  TDX_SUCCESS = 0x0000000000000000
  TDX_NON_RECOVERABLE_VCPU = 0x4000000100000000
  TDX_NON_RECOVERABLE_TD = 0x6000000200000000
  TDX_INTERRUPTED_RESUMABLE = 0x8000000300000000
  TDX_INTERRUPTED_RESTARTABLE = 0x8000000400000000
  TDX_NON_RECOVERABLE_TD_NON_ACCESSIBLE = 0x6000000500000000
  TDX_INVALID_RESUMPTION = 0xC000000600000000
  TDX_NON_RECOVERABLE_TD_WRONG_APIC_MODE = 0xE000000700000000
  TDX_CROSS_TD_FAULT = 0x8000000800000000
  TDX_CROSS_TD_TRAP = 0x9000000900000000
  TDX_NON_RECOVERABLE_TD_CORRUPTED_MD = 0x6000000A00000000
  TDX_OPERAND_INVALID = 0xC000010000000000
  TDX_OPERAND_ADDR_RANGE_ERROR = 0xC000010100000000
  TDX_EVENT_FILTER_INVALID = 0xC000010200000000
  TDX_EVENT_FILTER_ORDER_INVALID = 0xC000010300000000
  TDX_OPERAND_BUSY = 0x8000020000000000
  TDX_PREVIOUS_TLB_EPOCH_BUSY = 0x8000020100000000
  TDX_SYS_BUSY = 0x8000020200000000
  TDX_RND_NO_ENTROPY = 0x8000020300000000
  TDX_OPERAND_BUSY_HOST_PRIORITY = 0x8000020400000000
  TDX_HOST_PRIORITY_BUSY_TIMEOUT = 0x9000020500000000
  TDX_PAGE_METADATA_INCORRECT = 0xC000030000000000
  TDX_PAGE_ALREADY_FREE = 0x0000030100000000
  TDX_PAGE_NOT_OWNED_BY_TD = 0xC000030200000000
  TDX_PAGE_NOT_FREE = 0xC000030300000000
  TDX_TD_ASSOCIATED_PAGES_EXIST = 0xC000040000000000
  TDX_SYS_INIT_NOT_PENDING = 0xC000050000000000
  TDX_SYS_LP_INIT_NOT_DONE = 0xC000050200000000
  TDX_SYS_LP_INIT_DONE = 0xC000050300000000
  TDX_SYS_NOT_READY = 0xC000050500000000
  TDX_SYS_SHUTDOWN = 0xC000050600000000
  TDX_SYS_KEY_CONFIG_NOT_PENDING = 0xC000050700000000
  TDX_SYS_STATE_INCORRECT = 0xC000050800000000
  TDX_SYS_INVALID_HANDOFF = 0xC000050900000000
  TDX_SYS_INCOMPATIBLE_SIGSTRUCT = 0xC000050A00000000
  TDX_SYS_LP_INIT_NOT_PENDING = 0xC000050B00000000
  TDX_SYS_CONFIG_NOT_PENDING = 0xC000050C00000000
  TDX_INCOMPATIBLE_SEAM_CAPABILITIES = 0xC000050D00000000
  TDX_CRYPTO_SELF_TEST_FAILED = 0xC000051100000000
  TDX_TD_FATAL = 0xE000060400000000
  TDX_TD_NON_DEBUG = 0xC000060500000000
  TDX_TDCS_NOT_ALLOCATED = 0xC000060600000000
  TDX_LIFECYCLE_STATE_INCORRECT = 0xC000060700000000
  TDX_OP_STATE_INCORRECT = 0xC000060800000000
  TDX_NO_VCPUS = 0xC000060900000000
  TDX_TDCX_NUM_INCORRECT = 0xC000061000000000
  TDX_X2APIC_ID_NOT_UNIQUE = 0xC000062100000000
  TDX_VCPU_STATE_INCORRECT = 0xC000070000000000
  TDX_VCPU_ASSOCIATED = 0x8000070100000000
  TDX_VCPU_NOT_ASSOCIATED = 0x8000070200000000
  TDX_NO_VALID_VE_INFO = 0xC000070400000000
  TDX_MAX_VCPUS_EXCEEDED = 0xC000070500000000
  TDX_TSC_ROLLBACK = 0xC000070600000000
  TDX_INTERRUPTIBILITY_BLOCKED = 0xC000070700000000
  TDX_TD_VMCS_FIELD_NOT_INITIALIZED = 0xC000073000000000
  TD_VMCS_FIELD_ERROR = 0xC000073100000000
  TDX_KEY_GENERATION_FAILED = 0x8000080000000000
  TDX_TD_KEYS_NOT_CONFIGURED = 0x8000081000000000
  TDX_KEY_STATE_INCORRECT = 0xC000081100000000
  TDX_KEY_CONFIGURED = 0x0000081500000000
  TDX_WBCACHE_NOT_COMPLETE = 0x8000081700000000
  TDX_HKID_NOT_FREE = 0xC000082000000000
  TDX_NO_HKID_READY_TO_WBCACHE = 0x0000082100000000
  TDX_WBCACHE_RESUME_ERROR = 0xC000082300000000
  TDX_FLUSHVP_NOT_DONE = 0x8000082400000000
  TDX_NUM_ACTIVATED_HKIDS_NOT_SUPPORTED = 0xC000082500000000
  TDX_INCORRECT_CPUID_VALUE = 0xC000090000000000
  TDX_LIMIT_CPUID_MAXVAL_SET = 0xC000090100000000
  TDX_INCONSISTENT_CPUID_FIELD = 0xC000090200000000
  TDX_CPUID_MAX_SUBLEAVES_UNRECOGNIZED = 0xC000090300000000
  TDX_CPUID_LEAF_1F_FORMAT_UNRECOGNIZED = 0xC000090400000000
  TDX_INVALID_WBINVD_SCOPE = 0xC000090500000000
  TDX_INVALID_PKG_ID = 0xC000090600000000
  TDX_ENABLE_MONITOR_FSM_NOT_SET = 0xC000090700000000
  TDX_CPUID_LEAF_NOT_SUPPORTED = 0xC000090800000000
  TDX_SMRR_NOT_LOCKED = 0xC000091000000000
  TDX_INVALID_SMRR_CONFIGURATION = 0xC000091100000000
  TDX_SMRR_OVERLAPS_CMR = 0xC000091200000000
  TDX_SMRR_LOCK_NOT_SUPPORTED = 0xC000091300000000
  TDX_SMRR_NOT_SUPPORTED = 0xC000091400000000
  TDX_INCONSISTENT_MSR = 0xC000092000000000
  TDX_INCORRECT_MSR_VALUE = 0xC000092100000000
  TDX_SEAMREPORT_NOT_AVAILABLE = 0xC000093000000000
  TDX_SEAMDB_GETREF_NOT_AVAILABLE = 0xC000093100000000
  TDX_SEAMDB_REPORT_NOT_AVAILABLE = 0xC000093200000000
  TDX_SEAMVERIFYREPORT_NOT_AVAILABLE = 0xC000093300000000
  TDX_INVALID_TDMR = 0xC0000A0000000000
  TDX_NON_ORDERED_TDMR = 0xC0000A0100000000
  TDX_TDMR_OUTSIDE_CMRS = 0xC0000A0200000000
  TDX_TDMR_ALREADY_INITIALIZED = 0x00000A0300000000
  TDX_INVALID_PAMT = 0xC0000A1000000000
  TDX_PAMT_OUTSIDE_CMRS = 0xC0000A1100000000
  TDX_PAMT_OVERLAP = 0xC0000A1200000000
  TDX_INVALID_RESERVED_IN_TDMR = 0xC0000A2000000000
  TDX_NON_ORDERED_RESERVED_IN_TDMR = 0xC0000A2100000000
  TDX_CMR_LIST_INVALID = 0xC0000A2200000000
  TDX_EPT_WALK_FAILED = 0xC0000B0000000000
  TDX_EPT_ENTRY_FREE = 0xC0000B0100000000
  TDX_EPT_ENTRY_NOT_FREE = 0xC0000B0200000000
  TDX_EPT_ENTRY_NOT_PRESENT = 0xC0000B0300000000
  TDX_EPT_ENTRY_NOT_LEAF = 0xC0000B0400000000
  TDX_EPT_ENTRY_LEAF = 0xC0000B0500000000
  TDX_GPA_RANGE_NOT_BLOCKED = 0xC0000B0600000000
  TDX_GPA_RANGE_ALREADY_BLOCKED = 0x00000B0700000000
  TDX_TLB_TRACKING_NOT_DONE = 0xC0000B0800000000
  TDX_EPT_INVALID_PROMOTE_CONDITIONS = 0xC0000B0900000000
  TDX_PAGE_ALREADY_ACCEPTED = 0x00000B0A00000000
  TDX_PAGE_SIZE_MISMATCH = 0xC0000B0B00000000
  TDX_GPA_RANGE_BLOCKED = 0xC0000B0C00000000
  TDX_EPT_ENTRY_STATE_INCORRECT = 0xC0000B0D00000000
  TDX_EPT_PAGE_NOT_FREE = 0xC0000B0E00000000
  TDX_L2_SEPT_WALK_FAILED = 0xC0000B0F00000000
  TDX_L2_SEPT_ENTRY_NOT_FREE = 0xC0000B1000000000
  TDX_PAGE_ATTR_INVALID = 0xC0000B1100000000
  TDX_L2_SEPT_PAGE_NOT_PROVIDED = 0xC0000B1200000000
  TDX_METADATA_FIELD_ID_INCORRECT = 0xC0000C0000000000
  TDX_METADATA_FIELD_NOT_WRITABLE = 0xC0000C0100000000
  TDX_METADATA_FIELD_NOT_READABLE = 0xC0000C0200000000
  TDX_METADATA_FIELD_VALUE_NOT_VALID = 0xC0000C0300000000
  TDX_METADATA_LIST_OVERFLOW = 0xC0000C0400000000
  TDX_INVALID_METADATA_LIST_HEADER = 0xC0000C0500000000
  TDX_REQUIRED_METADATA_FIELD_MISSING = 0xC0000C0600000000
  TDX_METADATA_ELEMENT_SIZE_INCORRECT = 0xC0000C0700000000
  TDX_METADATA_LAST_ELEMENT_INCORRECT = 0xC0000C0800000000
  TDX_METADATA_FIELD_CURRENTLY_NOT_WRITABLE = 0xC0000C0900000000
  TDX_METADATA_WR_MASK_NOT_VALID = 0xC0000C0A00000000
  TDX_METADATA_FIRST_FIELD_ID_IN_CONTEXT = 0x00000C0B00000000
  TDX_METADATA_FIELD_SKIP = 0x00000C0C00000000
  TDX_VIRTUAL_MSR_VALUE_NOT_VALID = 0xC0000C0D00000000
  TDX_METADATA_FIELD_NOT_ALLOCATED = 0xC0000C0E00000000
  TDX_SERVTD_ALREADY_BOUND_FOR_TYPE = 0xC0000D0000000000
  TDX_SERVTD_TYPE_MISMATCH = 0xC0000D0100000000
  TDX_SERVTD_ATTR_MISMATCH = 0xC0000D0200000000
  TDX_SERVTD_INFO_HASH_MISMATCH = 0xC0000D0300000000
  TDX_SERVTD_UUID_MISMATCH = 0xC0000D0400000000
  TDX_SERVTD_NOT_BOUND = 0xC0000D0500000000
  TDX_SERVTD_BOUND = 0xC0000D0600000000
  TDX_TARGET_UUID_MISMATCH = 0xC0000D0700000000
  TDX_TARGET_UUID_UPDATED = 0xC0000D0800000000
  TDX_INVALID_MBMD = 0xC0000E0000000000
  TDX_INCORRECT_MBMD_MAC = 0xC0000E0100000000
  TDX_NOT_WRITE_BLOCKED = 0xC0000E0200000000
  TDX_ALREADY_WRITE_BLOCKED = 0x00000E0300000000
  TDX_NOT_EXPORTED = 0xC0000E0400000000
  TDX_MIGRATION_STREAM_STATE_INCORRECT = 0xC0000E0500000000
  TDX_MAX_MIGS_NUM_EXCEEDED = 0xC0000E0600000000
  TDX_EXPORTED_DIRTY_PAGES_REMAIN = 0xC0000E0700000000
  TDX_MIGRATION_DECRYPTION_KEY_NOT_SET = 0xC0000E0800000000
  TDX_TD_NOT_MIGRATABLE = 0xC0000E0900000000
  TDX_PREVIOUS_EXPORT_CLEANUP_INCOMPLETE = 0xC0000E0A00000000
  TDX_NUM_MIGS_HIGHER_THAN_CREATED = 0xC0000E0B00000000
  TDX_IMPORT_MISMATCH = 0xC0000E0C00000000
  TDX_MIGRATION_EPOCH_OVERFLOW = 0xC0000E0D00000000
  TDX_MAX_EXPORTS_EXCEEDED = 0xC0000E0E00000000
  TDX_INVALID_PAGE_MAC = 0xC0000E0F00000000
  TDX_MIGRATED_IN_CURRENT_EPOCH = 0xC0000E1000000000
  TDX_DISALLOWED_IMPORT_OVER_REMOVED = 0xC0000E1100000000
  TDX_SOME_VCPUS_NOT_MIGRATED = 0xC0000E1200000000
  TDX_ALL_VCPUS_IMPORTED = 0xC0000E1300000000
  TDX_MIN_MIGS_NOT_CREATED = 0xC0000E1400000000
  TDX_VCPU_ALREADY_EXPORTED = 0xC0000E1500000000
  TDX_INVALID_MIGRATION_DECRYPTION_KEY = 0xC0000E1600000000
  TDX_INVALID_CPUSVN = 0xC000100000000000
  TDX_INVALID_REPORTMACSTRUCT = 0xC000100100000000
  TDX_L2_EXIT_HOST_ROUTED_ASYNC = 0x0000110000000000
  TDX_L2_EXIT_HOST_ROUTED_TDVMCALL = 0x0000110100000000
  TDX_L2_EXIT_PENDING_INTERRUPT = 0x0000110200000000
  TDX_L2_VM_ENTRY_FAILED = 0x8000110300000000
  TDX_PENDING_INTERRUPT = 0x0000112000000000
  TDX_TD_EXIT_BEFORE_L2_ENTRY = 0x0000114000000000
  TDX_TD_EXIT_ON_L2_VM_EXIT = 0x0000114100000000
  TDX_TD_EXIT_ON_L2_TO_L1 = 0x0000114200000000
  TDX_GLA_NOT_CANONICAL = 0xC000116000000000
  UNINITIALIZE_ERROR = 0xFFFFFFFFFFFFFFFF


class TdxOperandCode(Enum):
  OPERAND_ID_RAX = 0
  OPERAND_ID_RCX = 1
  OPERAND_ID_RDX = 2
  OPERAND_ID_RBX = 3
  OPERAND_ID_RBP = 5
  OPERAND_ID_RSI = 6
  OPERAND_ID_RDI = 7
  OPERAND_ID_R8 = 8
  OPERAND_ID_R9 = 9
  OPERAND_ID_R10 = 10
  OPERAND_ID_R11 = 11
  OPERAND_ID_R12 = 12
  OPERAND_ID_R13 = 13
  OPERAND_ID_R14 = 14
  OPERAND_ID_R15 = 15
  OPERAND_ID_ATTRIBUTES = 64
  OPERAND_ID_XFAM = 65
  OPERAND_ID_EXEC_CONTROLS = 66
  OPERAND_ID_EPTP_CONTROLS = 67
  OPERAND_ID_MAX_VCPUS = 68
  OPERAND_ID_CPUID_CONFIG = 69
  OPERAND_ID_TSC_FREQUENCY = 70
  OPERAND_ID_NUM_L2_VMS = 71
  OPERAND_ID_IA32_ARCH_CAPABILITIES_CONFIG = 72
  OPERAND_ID_PAGE = 95
  OPERAND_ID_TDMR_INFO_PA = 96
  OPERAND_ID_GPA_LIST_ENTRY = 97
  OPERAND_ID_MIG_BUFF_LIST_ENTRY = 98
  OPERAND_ID_NEW_PAGE_LIST_ENTRY = 99
  OPERAND_ID_tdr_pa = 128
  OPERAND_ID_TDCX = 129
  OPERAND_ID_TDVPR = 130
  OPERAND_ID_REG_PAGE = 132
  OPERAND_ID_TDCS = 144
  OPERAND_ID_TDVPS = 145
  OPERAND_ID_SEPT_TREE = 146
  OPERAND_ID_SEPT_ENTRY = 147
  OPERAND_ID_RTMR = 168
  OPERAND_ID_TD_EPOCH = 169
  OPERAND_ID_L2_VAPIC_GPA = 170
  OPERAND_ID_MIGSC = 171
  OPERAND_ID_OP_STATE = 172
  OPERAND_ID_MIG = 173
  OPERAND_ID_SERVTD_BINDINGS = 174
  OPERAND_ID_METADATA_FIELD = 176
  OPERAND_ID_NUM_VCPUS = 177
  OPERAND_ID_CPUID_FIXED0_BITMAP = 178
  OPERAND_ID_SYS = 184
  OPERAND_ID_TDMR = 185
  OPERAND_ID_KOT = 186
  OPERAND_ID_KET = 187
  OPERAND_ID_WBCACHE = 188


class TdCallLeafOpcode(Enum):
  TDG_VP_VMCALL_LEAF = 0
  TDG_VP_INFO_LEAF = 1
  TDG_MR_RTMR_EXTEND_LEAF = 2
  TDG_VP_VEINFO_GET_LEAF = 3
  TDG_MR_REPORT_LEAF = 4
  TDG_VP_CPUIDVE_SET_LEAF = 5
  TDG_MEM_PAGE_ACCEPT_LEAF = 6
  TDG_VM_RD_LEAF = 7
  TDG_VM_WR_LEAF = 8
  TDG_VP_RD_LEAF = 9
  TDG_VP_WR_LEAF = 10
  TDG_SYS_RD_LEAF = 11
  TDG_SYS_RDALL_LEAF = 12
  TDG_SERVTD_RD_LEAF = 18
  TDG_SERVTD_WR_LEAF = 20
  TDG_MR_VERIFYREPORT_LEAF = 22
  TDG_MEM_PAGE_ATTR_RD_LEAF = 23
  TDG_MEM_PAGE_ATTR_WR_LEAF = 24
  TDG_VP_ENTER_LEAF = 25
  TDG_VP_INVEPT_LEAF = 26
  TDG_VP_INVVPID_LEAF = 27


class SeamCallLeafOpcode(Enum):
  TDH_VP_ENTER_LEAF = 0
  TDH_MNG_ADDCX_LEAF = 1
  TDH_MEM_PAGE_ADD_LEAF = 2
  TDH_MEM_SEPT_ADD_LEAF = 3
  TDH_VP_ADDCX_LEAF = 4
  TDH_MEM_PAGE_RELOCATE = 5
  TDH_MEM_PAGE_AUG_LEAF = 6
  TDH_MEM_RANGE_BLOCK_LEAF = 7
  TDH_MNG_KEY_CONFIG_LEAF = 8
  TDH_MNG_CREATE_LEAF = 9
  TDH_VP_CREATE_LEAF = 10
  TDH_MNG_RD_LEAF = 11
  TDH_MEM_RD_LEAF = 12
  TDH_MNG_WR_LEAF = 13
  TDH_MEM_WR_LEAF = 14
  TDH_MEM_PAGE_DEMOTE_LEAF = 15
  TDH_MR_EXTEND_LEAF = 16
  TDH_MR_FINALIZE_LEAF = 17
  TDH_VP_FLUSH_LEAF = 18
  TDH_MNG_VPFLUSHDONE_LEAF = 19
  TDH_MNG_KEY_FREEID_LEAF = 20
  TDH_MNG_INIT_LEAF = 21
  TDH_VP_INIT_LEAF = 22
  TDH_MEM_PAGE_PROMOTE_LEAF = 23
  TDH_PHYMEM_PAGE_RDMD_LEAF = 24
  TDH_MEM_SEPT_RD_LEAF = 25
  TDH_VP_RD_LEAF = 26
  TDH_MNG_KEY_RECLAIMID_LEAF = 27
  TDH_PHYMEM_PAGE_RECLAIM_LEAF = 28
  TDH_MEM_PAGE_REMOVE_LEAF = 29
  TDH_MEM_SEPT_REMOVE_LEAF = 30
  TDH_SYS_KEY_CONFIG_LEAF = 31
  TDH_SYS_INFO_LEAF = 32
  TDH_SYS_INIT_LEAF = 33
  TDH_SYS_RD_LEAF = 34
  TDH_SYS_LP_INIT_LEAF = 35
  TDH_SYS_TDMR_INIT_LEAF = 36
  TDH_SYS_RDALL_LEAF = 37
  TDH_MEM_TRACK_LEAF = 38
  TDH_MEM_RANGE_UNBLOCK_LEAF = 39
  TDH_PHYMEM_CACHE_WB_LEAF = 40
  TDH_PHYMEM_PAGE_WBINVD_LEAF = 41
  TDH_MEM_SEPT_WR_LEAF = 42
  TDH_VP_WR_LEAF = 43
  TDH_SYS_LP_SHUTDOWN_LEAF = 44
  TDH_SYS_CONFIG_LEAF = 45
  TDH_SYS_SHUTDOWN_LEAF = 52
  TDH_SYS_UPDATE_LEAF = 53
  TDH_SERVTD_BIND_LEAF = 48
  TDH_SERVTD_PREBIND_LEAF = 49
  TDH_EXPORT_ABORT_LEAF = 64
  TDH_EXPORT_BLOCKW_LEAF = 65
  TDH_EXPORT_RESTORE_LEAF = 66
  TDH_EXPORT_MEM_LEAF = 68
  TDH_EXPORT_PAUSE_LEAF = 70
  TDH_EXPORT_TRACK_LEAF = 71
  TDH_EXPORT_STATE_IMMUTABLE_LEAF = 72
  TDH_EXPORT_STATE_TD_LEAF = 73
  TDH_EXPORT_STATE_VP_LEAF = 74
  TDH_EXPORT_UNBLOCKW_LEAF = 75
  TDH_IMPORT_ABORT_LEAF = 80
  TDH_IMPORT_END_LEAF = 81
  TDH_IMPORT_COMMIT_LEAF = 82
  TDH_IMPORT_MEM_LEAF = 83
  TDH_IMPORT_TRACK_LEAF = 84
  TDH_IMPORT_STATE_IMMUTABLE_LEAF = 85
  TDH_IMPORT_STATE_TD_LEAF = 86
  TDH_IMPORT_STATE_VP_LEAF = 87
  TDH_MIG_STREAM_CREATE_LEAF = 96
  SEAMLDR_INFO_LEAF = 0x8000000000000000
  SEAMLDR_INSTALL_LEAF = 0x8000000000000001
  SEAMLDR_SHUTDOWN_LEAF = 0x8000000000000002
  SEAMLDR_SEAMINFO_LEAF = 0x8000000000000003
  SEAMLDR_CLEANUP_LEAF = 0x8000000000000004


SIZEOF_STRUCT_KVM_INDEX = 0
SIZEOF_STRUCT_KVM_TDX_INDEX = 1
SIZEOF_STRUCT_KVM_VCPU_INDEX = 2
SIZEOF_STRUCT_VCPU_TDX_INDEX = 3
SIZEOF_VCPU_TDX_RESERVED_0_INDEX = 4

versions = {
    "6.8.12+": [39832, 39944, 6712, 6912, 88],
    "6.11.11+": [39824, 39936, 6520, 6784, 88],
}

# added sizeof(struct kvm) to kmod init
# added sizeof(struct kvm_vcpu) to kmod init

# added to arch/x86/kvm/vmx/tdx.h
# char (*__sizeof__)[sizeof(struct kvm_tdx)] = 1;
# error: initialization of ‘char (*)[39936]’

# added to arch/x86/kvm/vmx/tdx.h
# char (*__sizeof__)[sizeof(struct vcpu_tdx)] = 1;
# error: initialization of ‘char (*)[6784]’

SIZEOF_SEAMLDR_INFO_STRUCT_RESERVED_2 = 80
SIZEOF_SEAMLDR_INFO_STRUCT_SEAMEXTEND = 136

SIZEOF_TDSYSINFO_STRUCT_RESERVED_0 = 13
SIZEOF_TDSYSINFO_STRUCT_RESERVED_1 = 10
SIZEOF_TDSYSINFO_STRUCT_RESERVED_3 = 10
SIZEOF_TDSYSINFO_STRUCT_RESERVED_4 = 32
SIZEOF_TDSYSINFO_STRUCT_CPUID_CONFIG_ENTRY = 24

SIZEOF_TD_PARAMS_STRUCT_RESERVED_0 = 4
SIZEOF_TD_PARAMS_STRUCT_RESERVED_1 = 38
SIZEOF_TD_PARAMS_STRUCT_RESERVED_2 = 24
SIZEOF_TD_PARAMS_STRUCT_RESERVED_3 = 320

SIZEOF_MEASUREMENT = 48

MAX_NUM_CPUID_CONFIG = 28

MAX_TDSYSINFO_STRUCT_CPUID_CONFIG_ENTRIES = 8
MAX_CMR_INFO_STRUCT_ENTRIES = 32


class TdxStatus:

  def __init__(self, code: int):
    self.code = code

  def __str__(self) -> str:
    try:
      status = TdxErrorCode(
          self.code & (~TDX_FATAL_FLAG_MASK & TDX_ERROR_CODE_MASK)
      )
      operand = TdxOperandCode(self.code & TDX_OPERAND_CODE_MASK)
      return f"{hex(self.code)} - {status.name} : {operand.name}"
    except ValueError:
      return f"{hex(self.code)}"


INVALID_HKID = 0xFFFFFFFFFFFFFFFF
INVALID_ADDR = 0xFFFFFFFFFFFFFFFF
INVALID_PID = 0


class Tdxtend:

  def __init__(self, pid: int, gateway: Gateway):
    self.pid = pid
    self.gateway = gateway

    boxy = Boxy("seamldr_info_struct", endian=Endian.LITTLE)
    boxy.addfield("version", DataType.UINT32, genuint64(value=0))
    boxy.addfield("attributes", DataType.UINT32, genuint64(value=0))
    boxy.addfield("vendor_id", DataType.UINT32, genuint64(value=0))
    boxy.addfield("build_date", DataType.UINT32, genuint64(value=0))
    boxy.addfield("build_num", DataType.UINT16, genuint64(value=0))
    boxy.addfield("minor", DataType.UINT16, genuint64(value=0))
    boxy.addfield("major", DataType.UINT16, genuint64(value=0))
    boxy.addfield("reserved_0", DataType.UINT16, genuint64(value=0))
    boxy.addfield("acm_x2apic", DataType.UINT32, genuint64(value=0))
    boxy.addfield("num_remaining_updates", DataType.UINT32, genuint64(value=0))
    boxy.addfield(
        "seamextend",
        DataType.BYTES,
        genbytes(
            SIZEOF_SEAMLDR_INFO_STRUCT_SEAMEXTEND,
            value=b"\x00" * SIZEOF_SEAMLDR_INFO_STRUCT_SEAMEXTEND,
        ),
    )
    boxy.addfield("features0", DataType.UINT64, genuint64(value=0))
    boxy.addfield(
        "reserved_2",
        DataType.BYTES,
        genbytes(
            SIZEOF_SEAMLDR_INFO_STRUCT_RESERVED_2,
            value=b"\x00" * SIZEOF_SEAMLDR_INFO_STRUCT_RESERVED_2,
        ),
    )
    self.seamldr_info_struct = boxy

    boxy = Boxy("tdsysinfo_struct", endian=Endian.LITTLE)
    boxy.addfield("attributes", DataType.UINT32, genuint32(value=0))
    boxy.addfield("vendor_id", DataType.UINT32, genuint32(value=0))
    boxy.addfield("build_date", DataType.UINT32, genuint32(value=0))
    boxy.addfield("build_num", DataType.UINT16, genuint16(value=0))
    boxy.addfield("minor_version", DataType.UINT16, genuint16(value=0))
    boxy.addfield("major_version", DataType.UINT16, genuint16(value=0))
    boxy.addfield("sys_rd", DataType.UINT8, genuint8(value=0))
    boxy.addfield(
        "reserved 0",
        DataType.BYTES,
        genbytes(
            SIZEOF_TDSYSINFO_STRUCT_RESERVED_0,
            value=b"\x00" * SIZEOF_TDSYSINFO_STRUCT_RESERVED_0,
        ),
    )
    boxy.addfield("max_tdmrs", DataType.UINT16, genuint16(value=0))
    boxy.addfield("max_reserved_per_tdmr", DataType.UINT16, genuint16(value=0))
    boxy.addfield("pamt_entry_size", DataType.UINT16, genuint16(value=0))
    boxy.addfield(
        "reserved 1",
        DataType.BYTES,
        genbytes(
            SIZEOF_TDSYSINFO_STRUCT_RESERVED_1,
            value=b"\x00" * SIZEOF_TDSYSINFO_STRUCT_RESERVED_1,
        ),
    )
    boxy.addfield("tdcs_base_size", DataType.UINT16, genuint16(value=0))
    boxy.addfield("reserved 2", DataType.UINT16, genuint16(value=0))
    boxy.addfield("tdvps_base_size", DataType.UINT16, genuint16(value=0))
    boxy.addfield(
        "reserved 3",
        DataType.BYTES,
        genbytes(
            SIZEOF_TDSYSINFO_STRUCT_RESERVED_3,
            value=b"\x00" * SIZEOF_TDSYSINFO_STRUCT_RESERVED_3,
        ),
    )
    boxy.addfield("attributes_fixed0", DataType.UINT64, genuint64(value=0))
    boxy.addfield("attributes_fixed1", DataType.UINT64, genuint64(value=0))
    boxy.addfield("xfam_fixed0", DataType.UINT64, genuint64(value=0))
    boxy.addfield("xfam_fixed1", DataType.UINT64, genuint64(value=0))
    boxy.addfield(
        "reserved 4",
        DataType.BYTES,
        genbytes(
            SIZEOF_TDSYSINFO_STRUCT_RESERVED_4,
            value=b"\x00" * SIZEOF_TDSYSINFO_STRUCT_RESERVED_4,
        ),
    )
    boxy.addfield("num_cpuid_config", DataType.UINT32, genuint32(value=0))

    for i in range(MAX_TDSYSINFO_STRUCT_CPUID_CONFIG_ENTRIES):
      boxy.addfield(
          f"cpuid_config {i}",
          DataType.BYTES,
          genbytes(
              SIZEOF_TDSYSINFO_STRUCT_CPUID_CONFIG_ENTRY,
              value=b"\x00" * SIZEOF_TDSYSINFO_STRUCT_CPUID_CONFIG_ENTRY,
          ),
      )
    self.tdsysinfo_struct = boxy

    boxy = Boxy("cmr_info_struct", endian=Endian.LITTLE)
    for i in range(MAX_CMR_INFO_STRUCT_ENTRIES):
      boxy.addfield(f"cmr_base {i}", DataType.UINT64, genuint64(value=0))
      boxy.addfield(f"cmr_size {i}", DataType.UINT64, genuint64(value=0))
    self.cmr_info_struct = boxy

    boxy = Boxy("td_params_struct", endian=Endian.LITTLE)
    boxy.addfield("attributes", DataType.UINT64, genuint64(value=0))
    boxy.addfield("xfam", DataType.UINT64, genuint64(value=0))
    boxy.addfield("max_vcpus", DataType.UINT16, genuint16(value=0))
    boxy.addfield("num_l2_vms", DataType.UINT8, genuint8(value=0))
    boxy.addfield("msr_config_ctls", DataType.UINT8, genuint8(value=0))
    boxy.addfield(
        "reserved 0",
        DataType.BYTES,
        genbytes(
            SIZEOF_TD_PARAMS_STRUCT_RESERVED_0,
            value=b"\x00" * SIZEOF_TD_PARAMS_STRUCT_RESERVED_0,
        ),
    )
    boxy.addfield("eptp_controls", DataType.UINT64, genuint64(value=0))
    boxy.addfield("config_flags", DataType.UINT64, genuint64(value=0))
    boxy.addfield("tsc_frequency", DataType.UINT16, genuint16(value=0))
    boxy.addfield(
        "reserved 1",
        DataType.BYTES,
        genbytes(
            SIZEOF_TD_PARAMS_STRUCT_RESERVED_1,
            value=b"\x00" * SIZEOF_TD_PARAMS_STRUCT_RESERVED_1,
        ),
    )
    boxy.addfield(
        "mr_config_id",
        DataType.BYTES,
        genbytes(
            SIZEOF_MEASUREMENT,
            value=b"\x00" * SIZEOF_MEASUREMENT,
        ),
    )
    boxy.addfield(
        "mr_owner",
        DataType.BYTES,
        genbytes(
            SIZEOF_MEASUREMENT,
            value=b"\x00" * SIZEOF_MEASUREMENT,
        ),
    )
    boxy.addfield(
        "mr_owner_config",
        DataType.BYTES,
        genbytes(
            SIZEOF_MEASUREMENT,
            value=b"\x00" * SIZEOF_MEASUREMENT,
        ),
    )
    boxy.addfield(
        "ia32_arch_capabilities_config", DataType.UINT64, genuint64(value=0)
    )
    boxy.addfield(
        "reserved 2",
        DataType.BYTES,
        genbytes(
            SIZEOF_TD_PARAMS_STRUCT_RESERVED_2,
            value=b"\x00" * SIZEOF_TD_PARAMS_STRUCT_RESERVED_2,
        ),
    )
    self.td_params_struct = boxy

    if pid == INVALID_PID:
      return

    self.release = release()
    if release() not in versions:
      raise ValueError(f"Unsupported kernel version: {release()}")

    self.version = versions[release()]

    boxy = Boxy("struct_kvm", endian=Endian.LITTLE)
    boxy.addfield(
        "struct kvm",
        DataType.BYTES,
        genbytes(
            self.version[SIZEOF_STRUCT_KVM_INDEX],
            value=b"\x00" * self.version[SIZEOF_STRUCT_KVM_INDEX],
        ),
    )
    boxy.addfield("tdr_pa", DataType.VOID_POINTER, genuint64(value=0))
    boxy.addfield("tdcs_pa *", DataType.VOID_POINTER, genuint64(value=0))
    self.struct_kvm_tdx = boxy

    boxy = Boxy("struct_kvm_vcpu", endian=Endian.LITTLE)
    boxy.addfield(
        "struct kvm_vcpu",
        DataType.BYTES,
        genbytes(
            self.version[SIZEOF_STRUCT_KVM_VCPU_INDEX],
            value=b"\x00" * self.version[SIZEOF_STRUCT_KVM_VCPU_INDEX],
        ),
    )
    boxy.addfield(
        "reserved 0",
        DataType.BYTES,
        genbytes(
            self.version[SIZEOF_VCPU_TDX_RESERVED_0_INDEX],
            value=b"\x00" * self.version[SIZEOF_VCPU_TDX_RESERVED_0_INDEX],
        ),
    )
    boxy.addfield("tdvpr_pa", DataType.VOID_POINTER, genuint64(value=0))
    self.struct_vcpu_tdx = boxy

  def get_fd(self, location: str) -> int:
    """Finds file descriptors (FDs) for process ID (PID) where the FD's symlink target path contains the specified string.

    Args:
        location (str): The string to search for within the FD's target path.
          This can be a full path, a device name, or part of a socket string.

    Returns:
        list[int]: A list of file descriptors associated with paths containing
                the target string for the given PID. Returns an empty list
                if no such FDs are found, or if the process does not exist
                or is inaccessible.
    """

    if self.pid == 0:
      raise ValueError(f"Process with PID {self.pid} isn't supported.")

    fd_dir = f"/proc/{self.pid}/fd"

    # Check if the /proc/<pid>/fd directory exists and is accessible
    if not path.isdir(fd_dir):
      if path.exists(f"/proc/{self.pid}"):
        print(
            f"Warning: Access denied to {fd_dir}. Check permissions.",
            file=stderr,
        )
      else:
        print(
            f"Error: Process with PID {self.pid} does not exist.", file=stderr
        )
      return []

    try:
      for fd_name in listdir(fd_dir):
        fd_path = path.join(fd_dir, fd_name)
        try:
          symlink_path = readlink(fd_path)
          if location in symlink_path:
            return int(fd_name)
        except OSError:
          pass

    except OSError as e:
      print(f"Error listing directory {fd_dir}: {e}", file=stderr)

    raise ValueError(f"No FD found for {location} in PID {self.pid}")

  def get_kvm_fd(self) -> int:
    """Finds file descriptors (FDs) for process ID (PID) where the FD's symlink target path contains the /dev/kvm string."""
    return self.get_fd("/dev/kvm")

  def get_vm_fd(self) -> int:
    """Finds file descriptors (FDs) for process ID (PID) where the FD's symlink target path contains the anon_inode:kvm-vm string."""
    return self.get_fd("anon_inode:kvm-vm")

  def get_vcpu_fds(self) -> [int]:
    """Finds file descriptors (FDs) for process ID (PID) where the FD's symlink target path contains the anon_inode:kvm-vcpu:<index> string."""

    fds = []

    i = 0
    while True:
      try:
        fds.append(self.get_fd(f"anon_inode:kvm-vcpu:{i}"))
        i += 1
      except ValueError:
        break

    return fds

  def get_vcpu_stats_fds(self) -> [int]:
    """Finds file descriptors (FDs) for process ID (PID) where the FD's symlink target path contains the anon_inode:kvm-vcpu-stats:<index> string."""

    fds = []

    i = 0
    while True:
      try:
        fds.append(self.get_fd(f"anon_inode:kvm-vcpu-stats:{i}"))
        i += 1
      except ValueError:
        break

    return fds

  def get_tdr_pa(self, vm_fd: int) -> int:
    """Returns the tdr_pa PA for the target process."""

    (f, f_mode_offset, private_data_offset) = self.gateway.fdget(self.pid, vm_fd)

    private_data = self.gateway.read_uint64(f + private_data_offset)

    buffer = self.gateway.read_buffer(
        private_data, self.version[SIZEOF_STRUCT_KVM_TDX_INDEX]
    )

    self.gateway.fdput(f)

    self.struct_kvm_tdx.decode(buffer)

    return self.struct_kvm_tdx.get("tdr_pa")

  def get_tdcs_pa(self, vm_fd: int) -> int:
    """Returns the TDCS PA for the target process."""

    (f, f_mode_offset, private_data_offset) = self.gateway.fdget(self.pid, vm_fd)

    private_data = self.gateway.read_uint64(f + private_data_offset)

    buffer = self.gateway.read_buffer(
        private_data, self.version[SIZEOF_STRUCT_KVM_TDX_INDEX]
    )

    self.gateway.fdput(f)

    self.struct_kvm_tdx.decode(buffer)

    return self.gateway.read_uint64(self.struct_kvm_tdx.get("tdcs_pa *"))

  def get_tdvpr_pa(self, vcpu_fd: int) -> tuple[int, Boxy, Boxy]:
    """Returns the TDVPR PA for the target process."""

    (f, f_mode_offset, private_data_offset) = self.gateway.fdget(
        self.pid, vcpu_fd
    )

    private_data = self.gateway.read_uint64(f + private_data_offset)

    buffer = self.gateway.read_buffer(
        private_data, self.version[SIZEOF_STRUCT_VCPU_TDX_INDEX]
    )

    self.gateway.fdput(f)

    self.struct_vcpu_tdx.decode(buffer)

    return self.struct_vcpu_tdx.get("tdvpr_pa")

  def call_seamldr_info_leaf(self) -> Boxy:
    """Returns the Seamldr Info struct."""

    (seamldr_info_struct_ka, seamldr_info_struct_pa) = (
        self.gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)
    )

    (rax, _, _, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.SEAMLDR_INFO_LEAF.value,
        seamldr_info_struct_pa,
        0,
        0,
        64,
        0,
        0,
        0,
        0,
    )

    buffer = self.gateway.read_buffer(seamldr_info_struct_ka, FOUR_KILOBYTES)
    self.seamldr_info_struct.decode(buffer)

    return rax, self.seamldr_info_struct

  def call_tdh_sys_info_leaf(self) -> Boxy:
    """Returns the TD SysInfo struct."""

    (tdsysinfo_struct_ka, tdsysinfo_struct_pa) = (
        self.gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)
    )

    (cmr_info_struct_ka, cmr_info_struct_pa) = (
        self.gateway.alloc_contiguous_buffer(FOUR_KILOBYTES)
    )

    (rax, _, _, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_SYS_INFO_LEAF.value,
        tdsysinfo_struct_pa,
        FOUR_KILOBYTES,
        cmr_info_struct_pa,
        64,
        0,
        0,
        0,
        0,
    )

    buffer = self.gateway.read_buffer(tdsysinfo_struct_ka, FOUR_KILOBYTES)
    self.tdsysinfo_struct.decode(buffer)

    buffer = self.gateway.read_buffer(cmr_info_struct_ka, FOUR_KILOBYTES)
    self.cmr_info_struct.decode(buffer)

    self.gateway.free_contiguous_buffer(cmr_info_struct_ka, FOUR_KILOBYTES)
    self.gateway.free_contiguous_buffer(tdsysinfo_struct_ka, FOUR_KILOBYTES)

    return rax, self.tdsysinfo_struct, self.cmr_info_struct

  def call_tdh_sys_rd_leaf(self, identifier: int) -> tuple[int, int, int]:
    """Read a TDX Module global-sclope metadata field."""

    (rax, _, rdx, r8, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_SYS_RD_LEAF.value,
        0,
        identifier,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    return rax, rdx, r8

  def call_tdg_sys_rd_leaf(self, identifier: int) -> tuple[int, int, int]:
    """Read a TDX Module global-sclope metadata field."""

    (rax, _, rdx, r8, _, _, _, _, _) = self.gateway.issue_tdcall(
        TdCallLeafOpcode.TDG_SYS_RD_LEAF.value,
        0,
        identifier,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    return rax, rdx, r8

  def call_tdh_mng_create_leaf(self, tdr_pa: int, hkid: int) -> [int, int]:
    """Create a TD."""

    (rax, _, _, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_MNG_CREATE_LEAF.value,
        tdr_pa,
        hkid,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    return rax

  def call_tdh_mng_key_config(self, tdr_pa: int) -> [int, int]:
    """Create a TD."""

    (rax, _, _, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_MNG_KEY_CONFIG_LEAF.value,
        tdr_pa,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    return rax

  def call_tdh_mng_addcx(self, tdcs_pa: int, tdr_pa: int) -> int:
    """Add a TDCS page to a TD."""

    (rax, _, _, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_MNG_ADDCX_LEAF.value,
        tdcs_pa,
        tdr_pa,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    return rax

  def call_tdh_mng_init_leaf(self, tdr_pa: int, params_pa: int) -> [int, int]:
    """Initialize a TD."""

    (rax, _, _, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_MNG_INIT_LEAF.value,
        tdr_pa,
        params_pa,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    return rax

  def call_tdh_vp_create_leaf(self, tdvpr_pa: int, tdr_pa: int) -> [int, int]:
    """Create a TD VP."""

    (rax, _, _, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_VP_CREATE_LEAF.value,
        tdvpr_pa,
        tdr_pa,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    return rax

  def call_tdh_vp_addcx(self, tdcx_pa: int, tdvpr_pa: int) -> int:
    """Add a TDCV page to a TD VP."""

    (rax, _, _, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_VP_ADDCX_LEAF.value,
        tdcx_pa,
        tdvpr_pa,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    return rax

  def call_tdh_mng_rd_leaf(
      self, version, tdr_pa, identifier: int
  ) -> tuple[int, int, int]:
    """Read a TD-scope metadata field (control structure field) of a TD."""

    (rax, _, rdx, r8, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_MNG_RD_LEAF.value | (version << 16),
        tdr_pa,
        identifier,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    return rax, rdx, r8

  def call_tdg_vm_rd_leaf(
      self, version, identifier: int
  ) -> tuple[int, int, int]:
    """Read a TD-scope metadata field (control structure field) of a TD."""

    (rax, _, rdx, r8, _, _, _, _, _) = self.gateway.issue_tdcall(
        TdCallLeafOpcode.TDG_VM_RD_LEAF.value | (version << 16),
        0,
        identifier,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    return rax, rdx, r8

  def call_tdh_vp_rd_leaf(
      self, version, tdvps, identifier: int
  ) -> tuple[int, int, int]:
    """Read a TD-scope metadata field (control structure field) of a TD."""

    (rax, _, rdx, r8, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_VP_RD_LEAF.value | (version << 16),
        tdvps,
        identifier,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    return rax, rdx, r8

  def call_tdg_vp_rd_leaf(
      self, version, identifier: int
  ) -> tuple[int, int, int]:
    """Read a TD-scope metadata field (control structure field) of a TD."""

    (rax, _, rdx, r8, _, _, _, _, _) = self.gateway.issue_tdcall(
        TdCallLeafOpcode.TDG_VP_RD_LEAF.value | (version << 16),
        0,
        identifier,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    return rax, rdx, r8

  def call_tdh_mng_wr_leaf(
      self, tdr_pa, identifier: int, value: int, mask: int
  ) -> [int, int]:
    """Write a TD-scope metadata field (control structure field) of a TD."""

    (rax, _, _, r8, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_VP_WR_LEAF.value,
        tdr_pa,
        identifier,
        value,
        mask,
        0,
        0,
        0,
        0,
    )

    return rax, r8

  def call_tdg_vm_wr_leaf(
      self, identifier: int, value: int, mask: int
  ) -> [int, int]:
    """Write a TD-scope metadata field (control structure field) of a TD."""

    (rax, _, _, r8, _, _, _, _, _) = self.gateway.issue_tdcall(
        TdCallLeafOpcode.TDG_VM_WR_LEAF.value,
        0,
        identifier,
        value,
        mask,
        0,
        0,
        0,
        0,
    )

    return rax, r8

  def call_tdh_vp_wr_leaf(
      self, tdvpr, identifier: int, value: int, mask: int
  ) -> [int, int]:
    """Write a TD-scope metadata field (control structure field) of a TD."""
    (rax, _, _, r8, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_VP_WR_LEAF.value,
        tdvpr,
        identifier,
        value,
        mask,
        0,
        0,
        0,
        0,
    )

    return rax, r8

  def call_tdg_vp_wr_leaf(
      self, identifier: int, value: int, mask: int
  ) -> [int, int]:
    """Write a TD-scope metadata field (control structure field) of a TD."""

    (rax, _, _, r8, _, _, _, _, _) = self.gateway.issue_tdcall(
        TdCallLeafOpcode.TDG_VP_WR_LEAF.value,
        0,
        identifier,
        value,
        mask,
        0,
        0,
        0,
        0,
    )

    return rax, r8

  def call_tdh_servtd_prebind_leaf(
      self,
      tgt_tdr_pa: int,
      info_hash: bytes,
      index: int,
      type: int,
      attributes: int,
  ) -> [int, int]:
    """Bind a servce TD to a target TD."""

    (rax, _, _, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_SERVTD_PREBIND_LEAF.value,
        tgt_tdr_pa,
        info_hash,
        index,
        type,
        attributes,
        0,
        0,
        0,
    )

    return rax

  def call_tdh_servtd_bind_leaf(
      self,
      tgt_tdr_pa: int,
      serv_tdr_pa: int,
      index: int,
      type: int,
      attributes: int,
  ) -> [int, int, int, int, int, int]:
    """Bind a servce TD to a target TD."""

    (rax, rcx, _, _, _, r10, r11, r12, r13) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_SERVTD_BIND_LEAF.value,
        tgt_tdr_pa,
        serv_tdr_pa,
        index,
        type,
        attributes,
        0,
        0,
        0,
    )

    return rax, rcx, r10, r11, r12, r13

  def call_tdg_servtd_rd_leaf(
      self, binding_handle: int, identifier: int, uuid: list[int]
  ) -> [int, int, int, int, int, int]:
    """Bind a servce TD to a target TD."""

    (rax, _, rdx, r8, _, r10, r11, r12, r13) = self.gateway.issue_tdcall(
        TdCallLeafOpcode.TDG_SERVTD_RD_LEAF.value,
        binding_handle,
        identifier,
        0,
        0,
        uuid[0],
        uuid[1],
        uuid[2],
        uuid[3],
    )

    return rax, rdx, r8, r10, r11, r12, r13

  def call_tdg_servtd_wr_leaf(
      self,
      binding_handle: int,
      identifier: int,
      value: int,
      mask: int,
      uuid: list[int],
  ) -> [int, int]:
    """Write a service TD metadata field."""

    (rax, _, _, r8, _, r10, r11, r12, r13) = self.gateway.issue_tdcall(
        TdCallLeafOpcode.TDG_SERVTD_WR_LEAF.value,
        binding_handle,
        identifier,
        value,
        mask,
        uuid[0],
        uuid[1],
        uuid[2],
        uuid[3],
    )

    return rax, r8, r10, r11, r12, r13

  def call_tdh_mig_stream_create_leaf(self, migsc: int, tdr_pa: int) -> [int]:
    """Create a migration stream."""

    (rax, _, _, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_MIG_STREAM_CREATE_LEAF.value,
        migsc,
        tdr_pa,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    return rax

  def call_tdh_import_state_immutable(
      self, tdr_pa: int, mbmd: int, page_list_info: int, state: int
  ) -> [int, int, int]:
    """Import immutable state."""

    (rax, rcx, rdx, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_IMPORT_STATE_IMMUTABLE_LEAF.value,
        tdr_pa,
        0,
        mbmd,
        page_list_info,
        state,
        0,
        0,
        0,
    )

    return rax, rcx, rdx

  def call_tdh_import_state_td(
      self, tdr_pa: int, mbmd: int, page_list_info: int, state: int
  ) -> [int, int, int]:
    """Import TD state."""

    (rax, rcx, rdx, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_IMPORT_STATE_TD_LEAF.value,
        tdr_pa,
        0,
        mbmd,
        page_list_info,
        state,
        0,
        0,
        0,
    )

    return rax, rcx, rdx

  def call_tdh_import_state_vp(
      self, tdvpr_pa: int, mbmd: int, page_list_info: int, state: int
  ) -> [int, int, int]:
    """Import VP state."""

    (rax, rcx, rdx, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_IMPORT_STATE_VP_LEAF.value,
        tdvpr_pa,
        0,
        mbmd,
        page_list_info,
        state,
        0,
        0,
        0,
    )

    return rax, rcx, rdx

  def call_tdh_export_state_immutable(
      self, tdr_pa: int, mbmd: int, page_list_info: int, state: int
  ) -> [int, int]:
    """Export immutable state."""

    (rax, _, rdx, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_EXPORT_STATE_IMMUTABLE_LEAF.value,
        tdr_pa,
        0,
        mbmd,
        page_list_info,
        state,
        0,
        0,
        0,
    )

    return rax, rdx

  def call_tdh_export_state_td(
      self, tdr_pa: int, mbmd: int, page_list_info: int, state: int
  ) -> [int, int]:
    """Export TD state."""

    (rax, _, rdx, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_EXPORT_STATE_TD_LEAF.value,
        tdr_pa,
        0,
        mbmd,
        page_list_info,
        state,
        0,
        0,
        0,
    )

    return rax, rdx

  def call_tdh_export_state_vp(
      self, tdvpr_pa: int, mbmd: int, page_list_info: int, state: int
  ) -> [int, int]:
    """Export TD VP state."""

    (rax, _, rdx, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_EXPORT_STATE_VP_LEAF.value,
        tdvpr_pa,
        0,
        mbmd,
        page_list_info,
        state,
        0,
        0,
        0,
    )

    return rax, rdx

  def call_tdh_export_pause(self, tdr_pa: int) -> [int]:
    """Export abort."""

    (rax, _, _, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_EXPORT_PAUSE_LEAF.value,
        tdr_pa,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    return rax

  def call_tdh_export_abort(
      self, tdr_pa: int, token: int, migs_index: int
  ) -> [int]:
    """Export abort."""

    (rax, _, _, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_EXPORT_ABORT_LEAF.value,
        tdr_pa,
        0,
        token,
        0,
        migs_index,
        0,
        0,
        0,
    )

    return rax

  def call_tdh_mem_sept_rd(
      self, tdr_pa: int, gpa: int, level: int
  ) -> [int, int]:
    """Read a Secure EPT entry."""

    (rax, rcx, _, _, _, _, _, _, _) = self.gateway.issue_seamcall(
        SeamCallLeafOpcode.TDH_MEM_SEPT_RD_LEAF.value,
        (gpa | level),
        tdr_pa,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    return rax, rcx

  def switch_to_associated_tdvpr_cpu(self, tdvpr: int) -> int:
    """Finds the CPU associated with the given TDVPR PA."""

    for i in range(cpu_count()):
      self.gateway.set_thread_affinity(get_ident(), i)
      rc, _, _ = self.call_tdh_vp_rd_leaf(1, tdvpr, -1)
      if rc == TdxErrorCode.TDX_METADATA_FIRST_FIELD_ID_IN_CONTEXT.value:
        return i

    return -1

  def watch_for_process_creation(self, name: str) -> int:
    """Waits for a process to be created."""

    old_pids = set(pids())

    while True:
      current_pids = set(pids())

      new_pids = current_pids - old_pids

      for pid in new_pids:
        try:
          p = Process(pid)
          print(
              f"New process created: PID={p.pid}, Name='{p.name()}' (Cmdline:"
              f" {' '.join(p.cmdline())})"
          )
          if name == p.name():
            print(f"PID {pid} returned.")
            return p.pid

        except (NoSuchProcess, AccessDenied):
          pass
        except Exception as e:
          print(f"Error getting info for new PID {pid}: {e}")

      old_pids = current_pids

  def make_page_list_info(self, hpa: int, last: int) -> int:

    if last >= 512:
      return 0

    if hpa & 0xFFF:
      return 0

    return hpa | (last << 55)

  def make_migration_index_and_cmd(
      self, migs_index: int, num_in_order_migs: int, command: bool
  ) -> int:
    return migs_index | (num_in_order_migs << 16) | (command << 63)

  def make_mbmd(self, hpa: int, size: int) -> int:
    return hpa | (size << 52)

  def make_md_list(self, buffer: bytes) -> tuple[Boxy, int]:
    boxy = Boxy("struct md_list", endian=Endian.LITTLE)

    boxy.addfield("list_buff_size", DataType.UINT16, genuint16(value=0))
    boxy.addfield("num_sequences", DataType.UINT16, genuint16(value=0))
    boxy.addfield("reserved", DataType.UINT32, genuint32(value=0))

    num_fields = (len(buffer) - SIZEOF_STRUCT_MD_LIST_HEADER) // SIZEOF_UINT64

    for i in range(num_fields):
      boxy.addfield(f"sequence {i}", DataType.UINT64, genuint64(value=0))

    boxy.decode(buffer)

    return boxy, num_fields

  def make_md_sequence(self, sequence: int, buffer: bytes) -> tuple[Boxy, int]:

    (
        write_mask_valid,
        inc_size,
        field_code,
        class_code,
        context_code,
        element_size_code,
        last_field_in_sequence,
        last_element_in_field,
        ignored,
    ) = self.extract_field_identifier(sequence)

    print(
        f"field_code: {field_code}, class_code: {class_code}, context_code:"
        f" {context_code}, element_size_code: {element_size_code},"
        f" last_field_in_sequence: {last_field_in_sequence},"
        f" last_element_in_field: {last_element_in_field}"
        f" write_mask_valid: {write_mask_valid}"
        f" ignored: {ignored}"
    )

    boxy = Boxy("struct md_sequence", endian=Endian.LITTLE)
    boxy.addfield("sequence_header", DataType.UINT64, genuint64(value=sequence))

    num_fields = last_field_in_sequence + 1

    for i in range(
        (len(buffer) - SIZEOF_STRUCT_MD_SEQUENCE_HEADER) // SIZEOF_UINT64
    ):
      boxy.addfield(f"element {i}", DataType.UINT64, genuint64(value=0))

      boxy.decode(buffer)

    return boxy, num_fields

  def extract_field_identifier(
      self, field_id: int
  ) -> tuple[int, int, int, int, int, int, int, int, int]:

    write_mask_valid = (
        field_id & WRITE_MASK_VALID_MASK
    ) >> WRITE_MASK_VALID_SHIFT
    ignored = (field_id & IGNORED_MASK) >> IGNORED_SHIFT
    inc_size = (field_id & INC_SIZE_MASK) >> INC_SIZE_SHIFT
    field_code = field_id & FIELD_CODE_MASK
    class_code = (field_id & CLASS_CODE_MASK) >> CLASS_CODE_SHIFT
    context_code = (field_id & CONTEXT_CODE_MASK) >> CONTEXT_CODE_SHIFT

    element_size_code = (
        field_id & ELEMENT_SIZE_CODE_MASK
    ) >> ELEMENT_SIZE_CODE_SHIFT

    last_field_in_sequence = (
        field_id & LAST_FIELD_IN_SEQUENCE_MASK
    ) >> LAST_FIELD_IN_SEQUENCE_SHIFT
    last_element_in_field = (
        field_id & LAST_ELEMENT_IN_FIELD_MASK
    ) >> LAST_ELEMENT_IN_FIELD_SHIFT

    return (
        write_mask_valid,
        inc_size,
        field_code,
        class_code,
        context_code,
        element_size_code,
        last_field_in_sequence,
        last_element_in_field,
        ignored,
    )

  def print_md_sequence(self, md_sequence: Boxy) -> int:

    field_id = md_sequence.get("sequence_header")

    print(f"sequence_header: {hex(field_id)}")

    (
        write_mask_valid,
        inc_size,
        field_code,
        class_code,
        context_code,
        element_size_code,
        last_field_in_sequence,
        last_element_in_field,
        ignored,
    ) = self.extract_field_identifier(field_id)

    lookup_code = (
        (class_code << CLASS_CODE_SHIFT)
        | (inc_size << INC_SIZE_SHIFT)
        | (context_code << CONTEXT_CODE_SHIFT)
        | (element_size_code << ELEMENT_SIZE_CODE_SHIFT)
        | field_code
        | (ignored << IGNORED_SHIFT)
    )

    print(
        f"class_code: {class_code}, context_code: {context_code},"
        f" element_size_code: {element_size_code}, last_field_in_sequence:"
        f" {last_field_in_sequence}, last_element_in_field:"
        f" {last_element_in_field}, field_code: {field_code}, ignored:"
        f" {ignored}, lookup_code: {hex(lookup_code)}"
    )

    if context_code == TdxContextCode.MD_CTX_SYS.value:
      entry = global_sys_metadata_lookup_entry(lookup_code)
    elif context_code == TdxContextCode.MD_CTX_TD.value:
      if (
          class_code
          == TdrTdcsMetadataClassCode.MD_TDCS_X2APIC_IDS_CLASS_CODE.value
      ) or (
          class_code == TdrTdcsMetadataClassCode.MD_TDCS_CPUID_CLASS_CODE.value
      ):
        lookup_code = lookup_code & ~FIELD_CODE_MASK
      entry = tdr_tdcs_metadata_lookup_entry(lookup_code)
    elif context_code == TdxContextCode.MD_CTX_VP.value:
      entry = tdvps_metadata_lookup_entry(lookup_code)
      if entry is None:
        entry = tdvmcs_metadata_lookup_entry(lookup_code)
    else:
      raise ValueError(
          f"class_code: {class_code} for lookup_code {hex(lookup_code)} not"
          " found"
      )

    if entry is None:
      raise ValueError(f"lookup_code: {hex(lookup_code)} not found")

    print(f"identifier: {hex(entry['field_id'])}, name: {entry['name']}")

    total = 0

    if write_mask_valid:
      print(f"  write_mask_valid: {hex(md_sequence.get(f"element {total}"))}")
      total += 1

    for _ in range(last_field_in_sequence + 1):
      for _ in range(last_element_in_field + 1):
        print(f"  element {total}: {hex(md_sequence.get(f'element {total}'))}")
        total += 1

    return total


if __name__ == "__main__":

  parser = ArgumentParser(description="tdxtend")
  parser.add_argument(
      "pid", type=int, help="Process ID (PID) for the target process"
  )

  args = parser.parse_args()

  gateway = Gateway()
  tdxtend = Tdxtend(args.pid, gateway)

  kvm_fd = tdxtend.get_kvm_fd()
  vm_fd = tdxtend.get_vm_fd()
  vcpu_fds = tdxtend.get_vcpu_fds()
  vcpu_stats_fds = tdxtend.get_vcpu_stats_fds()

  print(f"kvm_fd: {kvm_fd}")
  print(f"vm_fd: {vm_fd}")
  print(f"vcpu_fds: {vcpu_fds}")
  print(f"vcpu_stats_fds: {vcpu_stats_fds}")

  print(f"tdr_pa: {hex(tdxtend.get_tdr_pa(vm_fd))}")
  print(f"tdcs_pa: {hex(tdxtend.get_tdcs_pa(vm_fd))}")

  for vcpu_fd in vcpu_fds:
    print(f"tdvpr_pa: {hex(tdxtend.get_tdvpr_pa(vcpu_fd))}")
