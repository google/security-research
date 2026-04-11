import ctypes
from enum import Enum
import sys

FOUR_KILOBYTES = 4 * 1024
ONE_MEGABYTE = 1024 * 1024
TWO_MEGABYTES = 2 * ONE_MEGABYTE
ONE_GIGABYTE = 1024 * ONE_MEGABYTE

byte_t = ctypes.c_ubyte
phys_addr_t = ctypes.c_uint64
virt_addr_t = ctypes.c_uint64
kern_addr_t = ctypes.c_uint64
size_t = ctypes.c_size_t
pthread_t = ctypes.c_ulong


class MTRRType(Enum):
  Uncacheable = 0
  WriteCombining = 1
  WriteThrough = 4
  WriteProtected = 5
  WriteBack = 6


class MSRNumber(Enum):
  IA32MTRRCap = 0xFE
  IA32MTRRPhysBase0 = 0x200
  IA32MTRRPhysMask0 = 0x201
  IA32MTRRPhysBase1 = 0x202
  IA32MTRRPhysMask1 = 0x203
  IA32MTRRPhysBase2 = 0x204
  IA32MTRRPhysMask2 = 0x205
  IA32MTRRPhysBase3 = 0x206
  IA32MTRRPhysMask3 = 0x207
  IA32MTRRPhysBase4 = 0x208
  IA32MTRRPhysMask4 = 0x209
  IA32MTRRPhysBase5 = 0x20A
  IA32MTRRPhysMask5 = 0x20B
  IA32MTRRPhysBase6 = 0x20C
  IA32MTRRPhysMask6 = 0x20D
  IA32MTRRPhysBase7 = 0x20E
  IA32MTRRPhysMask7 = 0x20F
  IA32MTRRPhysBase8 = 0x210
  IA32MTRRPhysMask8 = 0x211
  IA32MTRRPhysBase9 = 0x212
  IA32MTRRPhysMask9 = 0x213
  IA32MTRRFix64K00000 = 0x250
  IA32MTRRFix16K80000 = 0x258
  IA32MTRRFix16KA0000 = 0x259
  IA32MTRRFix4KC0000 = 0x268
  IA32MTRRFix4KC8000 = 0x269
  IA32MTRRFix4KD0000 = 0x26A
  IA32MTRRFix4KD8000 = 0x26B
  IA32MTRRFix4KE0000 = 0x26C
  IA32MTRRFix4KE8000 = 0x26D
  IA32MTRRFix4KF0000 = 0x26E
  IA32MTRRFix4KF8000 = 0x26F
  IA32PAT = 0x277
  IA32MTRRDefType = 0x2FF
  IA32_VMX_BASIC = 0x480
  IA32_SEAMRR_BASE = 0x1400
  IA32_SEAMRR_MASK = 0x1401
  IA32_SEAMEXTEND = 0x1402


class VMCSField(Enum):
  Control16BitVirtualProcessorIdentifier = 0x00000000
  Control16BitPostedInterruptNotificationVector = 0x00000002
  Control16BitEPTPIndex = 0x00000004
  Guest16BitESSelector = 0x00000800
  Guest16BitCSSelector = 0x00000802
  Guest16BitSSSelector = 0x00000804
  Guest16BitDSSelector = 0x00000806
  Guest16BitFSSelector = 0x00000808
  Guest16BitGSSelector = 0x0000080A
  Guest16BitLDTRSelector = 0x0000080C
  Guest16BitTRSelector = 0x0000080E
  Guest16BitInterruptStatus = 0x00000810
  Host16BitESSelector = 0x00000C00
  Host16BitCSSelector = 0x00000C02
  Host16BitSSSelector = 0x00000C04
  Host16BitDSSelector = 0x00000C06
  Host16BitFSSelector = 0x00000C08
  Host16BitGSSelector = 0x00000C0A
  Host16BitTRSelector = 0x00000C0C
  Control64BitAddressIOBitmapA = 0x00002000
  Control64BitAddressIOBitmapB = 0x00002002
  Control64BitAddressMSRBitmaps = 0x00002004
  Control64BitVMExitMSRStoreAddress = 0x00002006
  Control64BitVMExitMSRLoadAddress = 0x00002008
  Control64BitVMEntryMSRLoadAddress = 0x0000200A
  Control64BitExecutiveVMCSPointer = 0x0000200C
  Control64BitTSCOffset = 0x00002010
  Control64BitVirtualAPICAddress = 0x00002012
  Control64BitAPICAccessAddress = 0x00002014
  Control64BitPostedInterruptDescriptorAddress = 0x00002016
  Control64BitVMFunctionControls = 0x00002018
  Control64BitEPTPointer = 0x0000201A
  Control64BitEOIExitBitmap0 = 0x0000201C
  Control64BitEOIExitBitmap1 = 0x0000201E
  Control64BitEOIExitBitmap2 = 0x00002020
  Control64BitEOIExitBitmap3 = 0x00002022
  Control64BitEPTPListAddress = 0x00002024
  Control64BitVMReadBitmapAddress = 0x00002026
  Control64BitVMWriteBitmapAddress = 0x00002028
  Control64BitVirtualizationExceptionInformationAddress = 0x0000202A
  ReadOnly64BitGuestPhysicalAddress = 0x00002400
  Guest64BitVMCSLinkPointer = 0x00002800
  Guest64BitIA32DebugCtl = 0x00002802
  Guest64BitIA32PAT = 0x00002804
  Guest64BitIA32EFER = 0x00002806
  Guest64BitIA32PerfGlobalCtrl = 0x00002808
  Guest64BitPDPT0 = 0x0000280A
  Guest64BitPDPT1 = 0x0000280C
  Guest64BitPDPT2 = 0x0000280E
  Guest64BitPDPT3 = 0x00002810
  Host64BitIA32PAT = 0x00002C00
  Host64BitIA32EFER = 0x00002C02
  Host64BitIA32PerfGlobalCtrl = 0x00002C04
  Control32BitPinBasedVMExecution = 0x00004000
  Control32BitPrimaryProcessorBasedVMExecution = 0x00004002
  Control32BitExceptionBitmap = 0x00004004
  Control32BitPageFaultErrorCodeMask = 0x00004006
  Control32BitPageFaultErrorCodeMatch = 0x00004008
  Control32BitCR3TargetCount = 0x0000400A
  Control32BitVMExit = 0x0000400C
  Control32BitVMExitMSRStoreCount = 0x0000400E
  Control32BitVMExitMSRLoadCount = 0x00004010
  Control32BitVMEntry = 0x00004012
  Control32BitVMEntryMSRLoadCount = 0x00004014
  Control32BitVMEntryInterruptionInformation = 0x00004016
  Control32BitVMEntryExceptionErrorCode = 0x00004018
  Control32BitVMEntryInstructionLength = 0x0000401A
  Control32BitTPRThreshold = 0x0000401C
  Control32BitSecondaryProcessorBasedVMExecution = 0x0000401E
  Control32BitPLEGap = 0x00004020
  Control32BitPLEWindow = 0x00004022
  ReadOnly32BitVMInstructionError = 0x00004400
  ReadOnly32BitExitReason = 0x00004402
  ReadOnly32BitVMExitInterruptionInformation = 0x00004404
  ReadOnly32BitVMExitInterruptionErrorCode = 0x00004406
  ReadOnly32BitIDTVectoringInformation = 0x00004408
  ReadOnly32BitIDTVectoringErrorCode = 0x0000440A
  ReadOnly32BitVMExitInstructionLength = 0x0000440C
  ReadOnly32BitVMExitInstructionInformation = 0x0000440E
  Guest32BitESLimit = 0x00004800
  Guest32BitCSLimit = 0x00004802
  Guest32BitSSLimit = 0x00004804
  Guest32BitDSLimit = 0x00004806
  Guest32BitFSLimit = 0x00004808
  Guest32BitGSLimit = 0x0000480A
  Guest32BitLDTRLimit = 0x0000480C
  Guest32BitTRLimit = 0x0000480E
  Guest32BitGDTRLimit = 0x00004810
  Guest32BitIDTRLimit = 0x00004812
  Guest32BitESAccessRights = 0x00004814
  Guest32BitCSAccessRights = 0x00004816
  Guest32BitSSAccessRights = 0x00004818
  Guest32BitDSAccessRights = 0x0000481A
  Guest32BitFSAccessRights = 0x0000481C
  Guest32BitGSAccessRights = 0x0000481E
  Guest32BitLDTRAccessRights = 0x00004820
  Guest32BitTRAccessRights = 0x00004822
  Guest32BitInterruptibilityState = 0x00004824
  Guest32BitActivityState = 0x00004826
  Guest32BitSMBase = 0x00004828
  Guest32BitIA32SysEnterCS = 0x0000482A
  Guest32BitVMXPreemptionTimerValue = 0x0000482E
  Host32BitIA32SysEnterCS = 0x00004C00
  ControlNaturalWidthCR0GuestHostMask = 0x00006000
  ControlNaturalWidthCR4GuestHostMask = 0x00006002
  ControlNaturalWidthCR0ReadShadow = 0x00006004
  ControlNaturalWidthCR4ReadShadow = 0x00006006
  ControlNaturalWidthCR3TargetValue0 = 0x00006008
  ControlNaturalWidthCR3TargetValue1 = 0x0000600A
  ControlNaturalWidthCR3TargetValue2 = 0x0000600C
  ControlNaturalWidthCR3TargetValue3 = 0x0000600E
  ReadOnlyNaturalWidthExitQualification = 0x00006400
  ReadOnlyNaturalWidthIORCX = 0x00006402
  ReadOnlyNaturalWidthIORSI = 0x00006404
  ReadOnlyNaturalWidthIORDI = 0x00006406
  ReadOnlyNaturalWidthIORIP = 0x00006408
  ReadOnlyNaturalWidthLinearAddress = 0x0000640A
  GuestNaturalWidthCR0 = 0x00006800
  GuestNaturalWidthCR3 = 0x00006802
  GuestNaturalWidthCR4 = 0x00006804
  GuestNaturalWidthESBase = 0x00006806
  GuestNaturalWidthCSBase = 0x00006808
  GuestNaturalWidthSSBase = 0x0000680A
  GuestNaturalWidthDSBase = 0x0000680C
  GuestNaturalWidthFSBase = 0x0000680E
  GuestNaturalWidthGSBase = 0x00006810
  GuestNaturalWidthLDTRBase = 0x00006812
  GuestNaturalWidthTRBase = 0x00006814
  GuestNaturalWidthGDTRBase = 0x00006816
  GuestNaturalWidthIDTRBase = 0x00006818
  GuestNaturalWidthDR7 = 0x0000681A
  GuestNaturalWidthRSP = 0x0000681C
  GuestNaturalWidthRIP = 0x0000681E
  GuestNaturalWidthRFlags = 0x00006820
  GuestNaturalWidthPendingDebugException = 0x00006822
  GuestNaturalWidthIA32SysEnterESP = 0x00006824
  GuestNaturalWidthIA32SysEnterEIP = 0x00006826
  HostNaturalWidthCR0 = 0x00006C00
  HostNaturalWidthCR3 = 0x00006C02
  HostNaturalWidthCR4 = 0x00006C04
  HostNaturalWidthFSBase = 0x00006C06
  HostNaturalWidthGSBase = 0x00006C08
  HostNaturalWidthTRBase = 0x00006C0A
  HostNaturalWidthGDTRBase = 0x00006C0C
  HostNaturalWidthIDTRBase = 0x00006C0E
  HostNaturalWidthIA32SysEnterESP = 0x00006C10
  HostNaturalWidthIA32SysEnterEIP = 0x00006C12
  HostNaturalWidthRSP = 0x00006C14
  HostNaturalWidthRIP = 0x00006C16


class GatewayError(Exception):
  """Custom exception for Gateway library errors."""

  pass


class Gateway:
  """A Python wrapper for the Gateway shared library."""

  _lib = None
  _lib_load_lock = False

  def __new__(cls, *args, **kwargs):
    """Ensures the shared library is loaded only once for the entire process."""
    if cls._lib is None and not cls._lib_load_lock:
      cls._lib_load_lock = True
      library_path = kwargs.get("library_path", "./libgateway.so")
      try:
        cls._lib = ctypes.CDLL(library_path)
        cls._configure_functions(cls._lib)
      except OSError as e:
        cls._lib_load_lock = False
        raise GatewayError(
            f"Failed to load Gateway shared library at '{library_path}': {e}"
        )
      cls._lib_load_lock = False
    return super(Gateway, cls).__new__(cls)

  def __init__(
      self,
      device_path: str = "/dev/gateway",
      library_path: str = "./libgateway.so",
  ):
    """Constructor for the Gateway class.

    Opens the specified device path and stores the file descriptor.

    Args:
        device_path (str): The path to the Gateway device (e.g.,
          "/dev/gateway_device").
        library_path (str): Path to the shared library (defaults to
          "./libgateway.so"). Used only on the first instance creation to load
          the library.
    """
    self._device_path = device_path
    self._device_fd = -1

    self._device_fd = Gateway._lib.gateway_open(device_path.encode("utf-8"))
    if self._device_fd < 0:
      raise GatewayError(
          f"Failed to open Gateway device '{device_path}' with error code"
          f" {self._device_fd}."
      )

    self._has_portio = hasattr(Gateway._lib, "gateway_issue_inb")
    self._has_mrs_msr = hasattr(Gateway._lib, "gateway_issue_mrs")
    self._has_seamcall = hasattr(Gateway._lib, "gateway_issue_seamcall")
    self._has_tdcall = hasattr(Gateway._lib, "gateway_issue_tdcall")
    self._has_rdmsr_wrmsr = hasattr(Gateway._lib, "gateway_issue_rdmsr")
    self._has_spectre = hasattr(Gateway._lib, "gateway_spectre")

  def __del__(self):
    """Destructor for the Gateway class.

    Ensures the device file descriptor is closed when the object is garbage
    collected.
    """
    if self._device_fd != -1:
      try:
        Gateway._lib.gateway_close(self._device_fd)
        # print(f"Gateway device {self._device_path} (fd: {self._device_fd}) closed successfully.")
      except Exception as e:
        sys.stderr.write(
            f"Error closing Gateway device {self._device_path} (fd:"
            f" {self._device_fd}): {e}\n"
        )
      finally:
        self._device_fd = -1  # Mark as closed

  @classmethod
  def _configure_functions(cls, lib):
    """Configures the argument types (argtypes) and return types (restype)

    for each function exposed by the shared library.
    This is crucial for ctypes to correctly handle data marshalling.
    This is now a class method called only once.
    """
    lib.gateway_open.argtypes = [ctypes.c_char_p]
    lib.gateway_open.restype = ctypes.c_int

    lib.gateway_close.argtypes = [ctypes.c_int]
    lib.gateway_close.restype = None

    lib.gateway_mmap.argtypes = [ctypes.c_int, phys_addr_t, size_t]
    lib.gateway_mmap.restype = ctypes.c_void_p

    lib.gateway_munmap.argtypes = [ctypes.c_int, ctypes.c_void_p, size_t]
    lib.gateway_munmap.restype = ctypes.c_int

    lib.gateway_memset.argtypes = [ctypes.c_void_p, ctypes.c_int, size_t]
    lib.gateway_memset.restype = None

    lib.gateway_memcpy.argtypes = [ctypes.c_void_p, ctypes.c_void_p, size_t]
    lib.gateway_memcpy.restype = None

    lib.gateway_read_uint64.argtypes = [
        ctypes.c_int,
        kern_addr_t,
        ctypes.POINTER(ctypes.c_uint64),
    ]
    lib.gateway_read_uint64.restype = ctypes.c_int

    lib.gateway_read_buffer.argtypes = [
        ctypes.c_int,
        ctypes.c_void_p,
        kern_addr_t,
        size_t,
    ]
    lib.gateway_read_buffer.restype = ctypes.c_int

    lib.gateway_write_uint64.argtypes = [
        ctypes.c_int,
        kern_addr_t,
        ctypes.c_uint64,
    ]
    lib.gateway_write_uint64.restype = ctypes.c_int

    lib.gateway_write_buffer.argtypes = [
        ctypes.c_int,
        ctypes.c_void_p,
        kern_addr_t,
        size_t,
    ]
    lib.gateway_write_buffer.restype = ctypes.c_int

    lib.gateway_alloc_contiguous_buffer.argtypes = [
        ctypes.c_int,
        size_t,
        ctypes.POINTER(kern_addr_t),
        ctypes.POINTER(phys_addr_t),
    ]
    lib.gateway_alloc_contiguous_buffer.restype = ctypes.c_int

    lib.gateway_free_contiguous_buffer.argtypes = [
        ctypes.c_int,
        kern_addr_t,
        size_t,
    ]
    lib.gateway_free_contiguous_buffer.restype = ctypes.c_int

    lib.gateway_fdget.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(kern_addr_t),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    lib.gateway_fdget.restype = ctypes.c_int

    lib.gateway_fdput.argtypes = [ctypes.c_int, kern_addr_t]
    lib.gateway_fdput.restype = ctypes.c_int

    lib.gateway_set_thread_affinity.argtypes = [pthread_t, ctypes.c_uint32]
    lib.gateway_set_thread_affinity.restype = ctypes.c_int

    lib.gateway_set_process_priority.argtypes = [ctypes.c_int, ctypes.c_int]
    lib.gateway_set_process_priority.restype = ctypes.c_int

    lib.gateway_load_file.argtypes = [ctypes.c_char_p, ctypes.POINTER(size_t)]
    lib.gateway_load_file.restype = ctypes.c_void_p

    lib.gateway_hexdump.argtypes = [ctypes.POINTER(byte_t), size_t]
    lib.gateway_hexdump.restype = None

    if hasattr(lib, "gateway_issue_outb"):
      lib.gateway_issue_outb.argtypes = [
          ctypes.c_int,
          ctypes.c_uint16,
          ctypes.c_uint8,
      ]
      lib.gateway_issue_outb.restype = ctypes.c_int
    if hasattr(lib, "gateway_issue_inb"):
      lib.gateway_issue_inb.argtypes = [
          ctypes.c_int,
          ctypes.c_uint16,
          ctypes.POINTER(ctypes.c_uint8),
      ]
      lib.gateway_issue_inb.restype = ctypes.c_int
    if hasattr(lib, "gateway_issue_outl"):
      lib.gateway_issue_outl.argtypes = [
          ctypes.c_int,
          ctypes.c_uint16,
          ctypes.c_uint32,
      ]
      lib.gateway_issue_outl.restype = ctypes.c_int
    if hasattr(lib, "gateway_issue_inl"):
      lib.gateway_issue_inl.argtypes = [
          ctypes.c_int,
          ctypes.c_uint16,
          ctypes.POINTER(ctypes.c_uint32),
      ]
      lib.gateway_issue_inl.restype = ctypes.c_int

    if hasattr(lib, "gateway_issue_seamcall"):
      lib.gateway_issue_seamcall.argtypes = [
          ctypes.c_int,
          ctypes.POINTER(ctypes.c_uint64),
          ctypes.POINTER(ctypes.c_uint64),
          ctypes.POINTER(ctypes.c_uint64),
          ctypes.POINTER(ctypes.c_uint64),
          ctypes.POINTER(ctypes.c_uint64),
          ctypes.POINTER(ctypes.c_uint64),
          ctypes.POINTER(ctypes.c_uint64),
          ctypes.POINTER(ctypes.c_uint64),
          ctypes.POINTER(ctypes.c_uint64),
      ]
      lib.gateway_issue_seamcall.restype = ctypes.c_int
    if hasattr(lib, "gateway_issue_tdcall"):
      lib.gateway_issue_tdcall.argtypes = [
          ctypes.c_int,
          ctypes.POINTER(ctypes.c_uint64),
          ctypes.POINTER(ctypes.c_uint64),
          ctypes.POINTER(ctypes.c_uint64),
          ctypes.POINTER(ctypes.c_uint64),
          ctypes.POINTER(ctypes.c_uint64),
          ctypes.POINTER(ctypes.c_uint64),
          ctypes.POINTER(ctypes.c_uint64),
          ctypes.POINTER(ctypes.c_uint64),
          ctypes.POINTER(ctypes.c_uint64),
      ]
      lib.gateway_issue_tdcall.restype = ctypes.c_int

    if hasattr(lib, "gateway_issue_rdmsr"):
      lib.gateway_issue_rdmsr.argtypes = [
          ctypes.c_int,
          ctypes.c_uint32,
          ctypes.POINTER(ctypes.c_uint64),
      ]
      lib.gateway_issue_rdmsr.restype = ctypes.c_int
    if hasattr(lib, "gateway_issue_wrmsr"):
      lib.gateway_issue_wrmsr.argtypes = [
          ctypes.c_int,
          ctypes.c_uint32,
          ctypes.c_uint64,
      ]
      lib.gateway_issue_wrmsr.restype = ctypes.c_int

    if hasattr(lib, "gateway_issue_vmclear"):
      lib.gateway_issue_vmclear.argtypes = [
          ctypes.c_int,
          ctypes.c_uint64,
      ]
      lib.gateway_issue_vmclear.restype = ctypes.c_int

    if hasattr(lib, "gateway_issue_vmlaunch"):
      lib.gateway_issue_vmlaunch.argtypes = [
          ctypes.c_int,
      ]
      lib.gateway_issue_vmlaunch.restype = ctypes.c_int

    if hasattr(lib, "gateway_issue_vmresume"):
      lib.gateway_issue_vmresume.argtypes = [
          ctypes.c_int,
      ]
      lib.gateway_issue_vmresume.restype = ctypes.c_int

    if hasattr(lib, "gateway_issue_vmxoff"):
      lib.gateway_issue_vmxoff.argtypes = [
          ctypes.c_int,
      ]
      lib.gateway_issue_vmxoff.restype = ctypes.c_int

    if hasattr(lib, "gateway_issue_vmxon"):
      lib.gateway_issue_vmxon.argtypes = [
          ctypes.c_int,
          ctypes.c_uint64,
      ]
      lib.gateway_issue_vmxon.restype = ctypes.c_int

    if hasattr(lib, "gateway_issue_vmread"):
      lib.gateway_issue_vmread.argtypes = [
          ctypes.c_int,
          ctypes.c_uint64,
          ctypes.POINTER(ctypes.c_uint64),
      ]
      lib.gateway_issue_vmread.restype = ctypes.c_int

    if hasattr(lib, "gateway_issue_vmwrite"):
      lib.gateway_issue_vmwrite.argtypes = [
          ctypes.c_int,
          ctypes.c_uint64,
          ctypes.c_uint64,
      ]
      lib.gateway_issue_vmwrite.restype = ctypes.c_int

    if hasattr(lib, "gateway_issue_vmptrld"):
      lib.gateway_issue_vmptrld.argtypes = [
          ctypes.c_int,
          ctypes.c_uint64,
      ]
      lib.gateway_issue_vmptrld.restype = ctypes.c_int

    if hasattr(lib, "gateway_issue_vmptrst"):
      lib.gateway_issue_vmptrst.argtypes = [
          ctypes.c_int,
          ctypes.POINTER(ctypes.c_uint64),
      ]
      lib.gateway_issue_vmptrst.restype = ctypes.c_int

    lib.gateway_reschedule.argtypes = [
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    lib.gateway_reschedule.restype = ctypes.c_int

    if hasattr(lib, "gateway_ipi_flood"):
      lib.gateway_ipi_flood.argtypes = [
          ctypes.c_int,
          ctypes.c_uint32,
          ctypes.c_uint32,
          ctypes.c_uint32,
      ]
      lib.gateway_ipi_flood.restype = ctypes.c_int

  def mmap(self, address: int, size: int) -> ctypes.c_void_p:
    """Maps a physical address range into the process's virtual address space.

    Returns a ctypes void pointer to the mapped memory.
    """
    mapped_ptr = Gateway._lib.gateway_mmap(
        self._device_fd, phys_addr_t(address), size_t(size)
    )
    if mapped_ptr is None:
      raise GatewayError(
          f"gateway_mmap failed for fd {self._device_fd}, address"
          f" {hex(address)}, size {size}."
      )
    return mapped_ptr

  def munmap(self, buffer: ctypes.c_void_p, size: int) -> None:
    """Unmaps a previously mapped memory region."""
    ret = Gateway._lib.gateway_munmap(self._device_fd, buffer, size_t(size))
    if ret != 0:
      raise GatewayError(
          f"gateway_munmap failed for fd {self._device_fd}, buffer {buffer},"
          f" size {size} with error code {ret}."
      )

  def memset(self, buffer: ctypes.c_void_p, value: int, size: int) -> None:
    """Sets a memory region to zero."""
    Gateway._lib.gateway_memset(buffer, value, size_t(size))

  def memcpy(
      self, dst: ctypes.c_void_p, src: ctypes.c_void_p, size: int
  ) -> None:
    """Copies a memory region from one location to another."""
    Gateway._lib.gateway_memcpy(dst, src, size_t(size))

  def read_uint64(self, kernel_address: int) -> int:
    """Reads a 64-bit unsigned integer from a kernel address."""
    value = ctypes.c_uint64()
    ret = Gateway._lib.gateway_read_uint64(
        self._device_fd, kern_addr_t(kernel_address), ctypes.byref(value)
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_read_uint64 failed for fd {self._device_fd}, address"
          f" {hex(kernel_address)} with error code {ret}."
      )
    return value.value

  def read_buffer(self, kernel_address: int, size: int) -> bytes:
    """Reads a buffer of bytes from a kernel address."""
    buffer = (ctypes.c_ubyte * size)()
    ret = Gateway._lib.gateway_read_buffer(
        self._device_fd,
        ctypes.cast(buffer, ctypes.c_void_p),
        kern_addr_t(kernel_address),
        size_t(size),
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_read_buffer failed for fd {self._device_fd}, address"
          f" {hex(kernel_address)}, size {size} with error code {ret}."
      )
    return bytes(buffer)

  def write_uint64(self, kernel_address: int, value: int) -> None:
    """Writes a 64-bit unsigned integer to a kernel address."""
    ret = Gateway._lib.gateway_write_uint64(
        self._device_fd, kern_addr_t(kernel_address), ctypes.c_uint64(value)
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_write_uint64 failed for fd {self._device_fd}, address"
          f" {hex(kernel_address)}, value {hex(value)} with error code {ret}."
      )

  def write_buffer(self, data: bytes, kernel_address: int) -> None:
    """Writes a buffer of bytes to a kernel address."""
    size = len(data)
    buffer = (ctypes.c_ubyte * size)(
        *data
    )  # Create a C array from Python bytes
    ret = Gateway._lib.gateway_write_buffer(
        self._device_fd,
        ctypes.cast(buffer, ctypes.c_void_p),
        kern_addr_t(kernel_address),
        size_t(size),
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_write_buffer failed for fd {self._device_fd}, address"
          f" {hex(kernel_address)}, size {size} with error code {ret}."
      )

  def issue_smc(
      self,
      arg0: int,
      arg1: int,
      arg2: int,
      arg3: int,
      arg4: int,
      arg5: int,
      arg6: int,
      arg7: int,
  ) -> tuple[int, int, int, int]:
    """Issues a System Management Call (SMC).

    Returns a tuple of (res0, res1, res2, res3).
    """
    res0 = ctypes.c_uint64()
    res1 = ctypes.c_uint64()
    res2 = ctypes.c_uint64()
    res3 = ctypes.c_uint64()
    ret = Gateway._lib.gateway_issue_smc(
        self._device_fd,
        ctypes.c_uint64(arg0),
        ctypes.c_uint64(arg1),
        ctypes.c_uint64(arg2),
        ctypes.c_uint64(arg3),
        ctypes.c_uint64(arg4),
        ctypes.c_uint64(arg5),
        ctypes.c_uint64(arg6),
        ctypes.c_uint64(arg7),
        ctypes.byref(res0),
        ctypes.byref(res1),
        ctypes.byref(res2),
        ctypes.byref(res3),
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_issue_smc failed for fd {self._device_fd} with error code"
          f" {ret}."
      )
    return res0.value, res1.value, res2.value, res3.value

  def alloc_contiguous_buffer(self, size: int) -> tuple[int, int]:
    """Allocates a contiguous buffer in kernel space.

    Returns a tuple of (kernel_address, physical_address).
    """
    ka = kern_addr_t()
    pa = phys_addr_t()
    ret = Gateway._lib.gateway_alloc_contiguous_buffer(
        self._device_fd, size_t(size), ctypes.byref(ka), ctypes.byref(pa)
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_alloc_contiguous_buffer failed for fd {self._device_fd},"
          f" size {size} with error code {ret}."
      )
    return ka.value, pa.value

  def free_contiguous_buffer(self, kernel_address: int, size: int) -> None:
    """Frees a previously allocated contiguous buffer."""
    ret = Gateway._lib.gateway_free_contiguous_buffer(
        self._device_fd, kern_addr_t(kernel_address), size_t(size)
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_free_contiguous_buffer failed for fd {self._device_fd},"
          f" address {hex(kernel_address)}, size {size} with error code {ret}."
      )

  def fdget(self, pid: int, tgt: int) -> tuple[int, int, int]:
    """Retrieves file descriptor information for a given PID.

    Returns a tuple of (file_kernel_address, f_mode_offset,
    private_data_offset).
    """
    f = kern_addr_t()
    f_mode_offset = ctypes.c_uint32()
    private_data_offset = ctypes.c_uint32()
    ret = Gateway._lib.gateway_fdget(
        self._device_fd,
        pid,
        tgt,
        ctypes.byref(f),
        ctypes.byref(f_mode_offset),
        ctypes.byref(private_data_offset),
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_fdget failed for fd {self._device_fd}, pid {pid} with error"
          f" code {ret}."
      )
    return f.value, f_mode_offset.value, private_data_offset.value

  def fdput(self, kernel_address: int) -> None:
    """Puts (releases) a file descriptor's kernel address."""
    ret = Gateway._lib.gateway_fdput(
        self._device_fd, kern_addr_t(kernel_address)
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_fdput failed for fd {self._device_fd}, address"
          f" {hex(kernel_address)} with error code {ret}."
      )

  def issue_vmclear(self, pa: int) -> None:
    """Issues a VMCLEAR instruction."""
    ret = Gateway._lib.gateway_issue_vmclear(self._device_fd, phys_addr_t(pa))
    if ret != 0:
      raise GatewayError(
          f"gateway_issue_vmclear failed for fd {self._device_fd}, address"
          f" {hex(pa)} with error code {ret}."
      )

  def issue_vmlaunch(self) -> None:
    """Issues a VMLAUNCH instruction."""
    ret = Gateway._lib.gateway_issue_vmlaunch(self._device_fd)
    if ret != 0:
      raise GatewayError(
          f"gateway_issue_vmlaunch failed for fd {self._device_fd} with error"
          f" code {ret}."
      )

  def issue_vmresume(self) -> None:
    """Issues a VMRESUME instruction."""
    ret = Gateway._lib.gateway_issue_vmresume(self._device_fd)
    if ret != 0:
      raise GatewayError(
          f"gateway_issue_vmresume failed for fd {self._device_fd} with error"
          f" code {ret}."
      )

  def issue_vmxoff(self) -> None:
    """Issues a VMXOFF instruction."""
    ret = Gateway._lib.gateway_issue_vmxoff(self._device_fd)
    if ret != 0:
      raise GatewayError(
          f"gateway_issue_vmxoff failed for fd {self._device_fd} with error"
          f" code {ret}."
      )

  def issue_vmxon(self, pa: int) -> None:
    """Issues a VMXON instruction."""
    ret = Gateway._lib.gateway_issue_vmxon(self._device_fd, phys_addr_t(pa))
    if ret != 0:
      raise GatewayError(
          f"gateway_issue_vmxon failed for fd {self._device_fd}, address"
          f" {hex(pa)} with error code {ret}."
      )

  def issue_vmread(self, identifier: int) -> int:
    """Issues a VMREAD instruction."""
    value = ctypes.c_uint64()
    ret = Gateway._lib.gateway_issue_vmread(
        self._device_fd, ctypes.c_uint64(identifier), ctypes.byref(value)
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_issue_vmread failed for fd {self._device_fd}, identifier"
          f" {identifier} with error code {ret}."
      )
    return value.value

  def issue_vmwrite(self, identifier: int, value: int) -> None:
    """Issues a VMWRITE instruction."""
    ret = Gateway._lib.gateway_issue_vmwrite(
        self._device_fd, ctypes.c_uint64(identifier), ctypes.c_uint64(value)
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_issue_vmwrite failed for fd {self._device_fd}, identifier"
          f" {identifier}, value {hex(value)} with error code {ret}."
      )

  def issue_vmptrld(self, pa: int) -> None:
    """Issues a VMPTRLD instruction."""
    ret = Gateway._lib.gateway_issue_vmptrld(self._device_fd, phys_addr_t(pa))
    if ret != 0:
      raise GatewayError(
          f"gateway_issue_vmptrld failed for fd {self._device_fd}, address"
          f" {hex(pa)} with error code {ret}."
      )

  def issue_vmptrst(self, pa: int) -> int:
    """Issues a VMPTRST instruction."""
    value = ctypes.c_uint64()
    ret = Gateway._lib.gateway_issue_vmptrst(self._device_fd, ctypes.byref(pa))
    if ret != 0:
      raise GatewayError(
          f"gateway_issue_vmptrst failed for fd {self._device_fd} with error"
          f" code {ret}."
      )
    return value.value

  def issue_reschedule(self, cpu: int, count: int, delay: int) -> None:
    """Issues a RESCHEDULE instruction."""
    ret = Gateway._lib.gateway_reschedule(self._device_fd, cpu, count, delay)
    if ret != 0:
      raise GatewayError(
          f"gateway_reschedule failed for fd {self._device_fd}, cpu"
          f" {cpu} with error code {ret}."
      )

  def set_thread_affinity(self, thread_id: int, core: int) -> None:
    """Sets the CPU affinity for a specific thread."""
    ret = Gateway._lib.gateway_set_thread_affinity(
        pthread_t(thread_id), ctypes.c_uint32(core)
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_set_thread_affinity failed for thread {thread_id}, core"
          f" {core} with error code {ret}."
      )

  def set_process_priority(self, policy: int, priority: int) -> None:
    """Sets the scheduling policy and priority for the current process."""
    ret = Gateway._lib.gateway_set_process_priority(
        ctypes.c_int(policy), ctypes.c_int(priority)
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_set_process_priority failed for policy {policy}, priority"
          f" {priority} with error code {ret}."
      )

  def load_file(self, filename: str) -> tuple[ctypes.c_void_p, int]:
    """Loads a file into memory via the library function.

    Returns a tuple of (buffer_pointer, size_of_file).
    """
    size = size_t()
    # Ensure filename is bytes
    buf_ptr = Gateway._lib.gateway_load_file(
        filename.encode("utf-8"), ctypes.byref(size)
    )
    if buf_ptr is None or buf_ptr.value is None:
      raise GatewayError(f"gateway_load_file failed for file '{filename}'.")
    return buf_ptr, size.value

  def hexdump(self, buffer_ptr: ctypes.c_void_p, length: int) -> None:
    """Performs a hexdump of a given memory buffer.

    Note: This directly calls the C function which prints to stdout.
    """
    # For hexdump, we need to cast the void pointer to a byte pointer
    # to correctly define the argtype for `uint8_t *buf`
    byte_ptr_type = ctypes.POINTER(byte_t)
    Gateway._lib.gateway_hexdump(
        ctypes.cast(buffer_ptr, byte_ptr_type), size_t(length)
    )

  def issue_outb(self, port: int, value: int) -> None:
    """Issues an OUTB instruction (if ENABLE_ISSUE_PORTIO was enabled)."""
    if not self._has_portio:
      raise NotImplementedError(
          "gateway_issue_outb not available (library not compiled with"
          " ENABLE_ISSUE_PORTIO)."
      )
    ret = Gateway._lib.gateway_issue_outb(
        self._device_fd, ctypes.c_uint16(port), ctypes.c_uint8(value)
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_issue_outb failed for fd {self._device_fd}, port"
          f" {hex(port)}, value {hex(value)} with error code {ret}."
      )

  def issue_inb(self, port: int) -> int:
    """Issues an INB instruction (if ENABLE_ISSUE_PORTIO was enabled)."""
    if not self._has_portio:
      raise NotImplementedError(
          "gateway_issue_inb not available (library not compiled with"
          " ENABLE_ISSUE_PORTIO)."
      )
    value = ctypes.c_uint8()
    ret = Gateway._lib.gateway_issue_inb(
        self._device_fd, ctypes.c_uint16(port), ctypes.byref(value)
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_issue_inb failed for fd {self._device_fd}, port"
          f" {hex(port)} with error code {ret}."
      )
    return value.value

  def issue_outl(self, port: int, value: int) -> None:
    """Issues an OUTL instruction (if ENABLE_ISSUE_PORTIO was enabled)."""
    if not self._has_portio:
      raise NotImplementedError(
          "gateway_issue_outl not available (library not compiled with"
          " ENABLE_ISSUE_PORTIO)."
      )
    ret = Gateway._lib.gateway_issue_outl(
        self._device_fd, ctypes.c_uint16(port), ctypes.c_uint32(value)
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_issue_outl failed for fd {self._device_fd}, port"
          f" {hex(port)}, value {hex(value)} with error code {ret}."
      )

  def issue_inl(self, port: int) -> int:
    """Issues an INL instruction (if ENABLE_ISSUE_PORTIO was enabled)."""
    if not self._has_portio:
      raise NotImplementedError(
          "gateway_issue_inl not available (library not compiled with"
          " ENABLE_ISSUE_PORTIO)."
      )
    value = ctypes.c_uint32()
    ret = Gateway._lib.gateway_issue_inl(
        self._device_fd, ctypes.c_uint16(port), ctypes.byref(value)
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_issue_inl failed for fd {self._device_fd}, port"
          f" {hex(port)} with error code {ret}."
      )
    return value.value

  def issue_seamcall(
      self,
      rax: int,
      rcx: int,
      rdx: int,
      r8: int,
      r9: int,
      r10: int,
      r11: int,
      r12: int,
      r13: int,
  ) -> tuple[int, int, int, int, int, int, int, int, int]:
    """Issues a SEAMCALL (if GATEWAY_ENABLE_ISSUE_SEAMCALL_TDCALL was enabled).

    Returns a tuple of (rax, rcx, rdx, r8, r9, r10, r11).
    """
    if not self._has_seamcall:
      raise NotImplementedError(
          "gateway_issue_seamcall not available (library not compiled with"
          " GATEWAY_ENABLE_ISSUE_SEAMCALL_TDCALL)."
      )

    regs = [
        ctypes.c_uint64(rax),
        ctypes.c_uint64(rcx),
        ctypes.c_uint64(rdx),
        ctypes.c_uint64(r8),
        ctypes.c_uint64(r9),
        ctypes.c_uint64(r10),
        ctypes.c_uint64(r11),
        ctypes.c_uint64(r12),
        ctypes.c_uint64(r13),
    ]
    ret = Gateway._lib.gateway_issue_seamcall(
        self._device_fd, *[ctypes.byref(r) for r in regs]
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_issue_seamcall failed for fd {self._device_fd} with error"
          f" code {ret}."
      )
    return tuple(r.value for r in regs)

  def issue_tdcall(
      self,
      rax: int,
      rcx: int,
      rdx: int,
      r8: int,
      r9: int,
      r10: int,
      r11: int,
      r12: int,
      r13: int,
  ) -> tuple[int, int, int, int, int, int, int, int, int]:
    """Issues a TDCALL (if GATEWAY_ENABLE_ISSUE_SEAMCALL_TDCALL was enabled).

    Returns a tuple of (rax, rcx, rdx, r8, r9, r10, r11, r12, r13).
    """
    if not self._has_tdcall:
      raise NotImplementedError(
          "gateway_issue_tdcall not available (library not compiled with"
          " GATEWAY_ENABLE_ISSUE_SEAMCALL_TDCALL)."
      )

    regs = [
        ctypes.c_uint64(rax),
        ctypes.c_uint64(rcx),
        ctypes.c_uint64(rdx),
        ctypes.c_uint64(r8),
        ctypes.c_uint64(r9),
        ctypes.c_uint64(r10),
        ctypes.c_uint64(r11),
        ctypes.c_uint64(r12),
        ctypes.c_uint64(r13),
    ]

    ret = Gateway._lib.gateway_issue_tdcall(
        self._device_fd, *[ctypes.byref(r) for r in regs]
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_issue_tdcall failed for fd {self._device_fd} with error"
          f" code {ret}."
      )
    return tuple(r.value for r in regs)

  def issue_rdmsr(self, identifier: int) -> int:
    """Reads a Model Specific Register (RDMSR instruction, if GATEWAY_ENABLE_ISSUE_RDMSR_WRMSR was enabled)."""
    if not self._has_rdmsr_wrmsr:
      raise NotImplementedError(
          "gateway_issue_rdmsr not available (library not compiled with"
          " GATEWAY_ENABLE_ISSUE_RDMSR_WRMSR)."
      )
    value = ctypes.c_uint64()
    ret = Gateway._lib.gateway_issue_rdmsr(
        self._device_fd, ctypes.c_uint32(identifier), ctypes.byref(value)
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_issue_rdmsr failed for fd {self._device_fd}, identifier"
          f" {identifier} with error code {ret}."
      )
    return value.value

  def issue_wrmsr(self, identifier: int, value: int) -> None:
    """Writes to a Model Specific Register (WRMSR instruction, if GATEWAY_ENABLE_ISSUE_RDMSR_WRMSR was enabled)."""
    if not self._has_rdmsr_wrmsr:
      raise NotImplementedError(
          "gateway_issue_wrmsr not available (library not compiled with"
          " GATEWAY_ENABLE_ISSUE_RDMSR_WRMSR)."
      )
    ret = Gateway._lib.gateway_issue_wrmsr(
        self._device_fd, ctypes.c_uint32(identifier), ctypes.c_uint64(value)
    )
    if ret != 0:
      raise GatewayError(
          f"gateway_issue_wrmsr failed for fd {self._device_fd}, identifier"
          f" {identifier}, value {hex(value)} with error code {ret}."
      )

  def ipi_storm(self, cpu: int, count: int, delay: int) -> None:
    """Call an IPI storm IOCTL."""

    ret = Gateway._lib.gateway_ipi_storm(self._device_fd, cpu, count, delay)
    if ret != 0:
      raise GatewayError(
          f"gateway_ipi_storm failed for fd {self._device_fd} with error"
          f" code {ret}."
      )


from argparse import ArgumentParser

if __name__ == "__main__":

  parser = ArgumentParser(description="gateway")
  parser.add_argument(
      "pid", type=int, help="Process ID (PID) for the target process"
  )
  parser.add_argument(
      "fd",
      type=int,
      help="File descriptor (FD) for /dev/kvm in the target process",
  )

  args = parser.parse_args()

  gateway = Gateway("/dev/gateway0", "./libgateway.so")

  f, f_mode_offset, private_data_offset = gateway.fdget(args.pid, args.fd)

  gateway.fdput(f)
