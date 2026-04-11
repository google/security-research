# TDXplore Toolkit

*Note: the TDXplore Linux kernel module is not appropriate for production environments because it fundamentally undermines userspace isolation from privileged operations.*

To support analysis of the Intel TDX Module the TDX Explore Toolkit (TDXplore) was developed to provide generic access to functionality normally reserved to ring-0 host VMM software. TDXplore is composed of three main components: a Linux kernel module, C/Python library, and a set of Python scripts that provide access to Intel TDX Module interfaces.

The Linux kernel module was developed to expose privileged functionality to userspace. This includes the ability to map/unmap physical memory, read/write kernel memory, and execute privileged instructions (e.g., `RDMSR`, `WRMSR`, `VMPTRLD`, `VMCLEAR`, `VMXON`, `VMREAD`, `VMWRITE`, `SEAMCALL`, and `TDCALL`). Most functionality is accessed via a set of ioctl calls with access to physical memory being accessible through `mmap` and `munmap`. The C/Python libraries simply wrap the Linux kernel module to provide a more user-friendly layer of abstraction.

Most of the Python scripts provide direct support for a specific interface in the Intel TDX Module. When combined or chained together they can be used to perform larger activities including:

1. TD and VP Management: Initialize or create a TD and its VPs, add private memory pages, and configure the TD/VPs.
2. TD Migration: Create a migration stream, bind a service TD to a target TD, pause a TD, and abort a migration.
3. Metadata and State Control: Read and write metadata from the host VMM, service TD, and guest TD context.
4. Metadata Manipulation: create, decrypt, parse, modify, and encrypt migration bundles with a provided MSK.

The table below shows the implemented scripts and provides a brief explanation.

| Names | Description |
| :--- | :--- |
| `mig_bundle_encrypt.py`</br>`mig_bundle_decrypt.py`</br>`mig_bundle_parse.py`</br>`mig_bundle_edit.py`|Used to encrypt, decrypt, and interact with migration bundles. The MSK is provided to the encrypt and decrypt scripts as a parameter and the MBMD data is checked on decrypt and updated on encrypt. The parse and edit scripts work with decrypted immutable, td, and vp migration bundles.|
|`qemu_break.py`</br>`qemu_resume.py`</br>`qemu_stop.py`|The break script is used to watch for and suspend a QEMU process before it executes a specific `ioctl`. This is primarily used to pause execution before `KVM_TDX_FINALIZE_VM` is called to support binding a migTD using `tdh_servtd_bind.py`. The resume and stop scripts are simple wrappers for `kill` using `SIGCONT` and `SIGSTOP`.|
|`tdg_md_rd.py`</br>`tdg_md_wr.py`</br>`tdg_servtd_rd.py`</br>`tdg_servtd_wr.py`|Used to interact with TD metadata from within a TD. The `md` variant allows a TD to read and write its own metadata. The `servtd` variant supports reading and writing metadata of another TD from a service TD.|
|`tdh_export_abort.py`</br>`tdh_export_pause.py`</br>`tdh_export_state_immutable.py`</br>`tdh_export_state_td.py`</br>`tdh_export_state_vp.py`|Provides the ability to export migration bundles associated with a TD. The pause script moves a migration from the `OP_STATE_LIVE_EXPORT` to `OP_STATE_PAUSED_EXPORT` which is required to access TD and VP non-memory state.|
|`tdh_import_state_immutable.py`</br>`tdh_import_state_td.py`</br>`tdh_import_state_vp.py`|Provides the ability to import migration bundles to a previously created TD template.|
|`tdh_md_rd.py`</br>`tdh_md_wr.py`|Used to interact with TD metadata from the host VMM.|
|`global_sys_metadata.py`</br>`tdr_tdcs_metadata.py`</br>`tdvmcs_metadata.py`</br>`tdvps_metadata.py|Metadata lookup lists are ported from `include/auto_gen_1_5` in the Intel TDX module source code. These are used by various other scripts parse and display entries (e.g., `tdh_md_rd.py`, `mig_bundle_parse.py`, and `tdg_servtd_rd.py`).|
|`tdh_servtd_bind.py`</br>`tdh_mig_stream_create.py`|Used to associate a service TD with a target TD and create migration stream contexts.|
|`tdh_mng_create.py`</br>`tdh_mng_key_config.py`</br>`tdh_mng_addcx.py`</br>`tdh_mng_init.py`</br>`tdh_vp_addcx.py`</br>`tdh_vp_create.py`|Various scripts to create and configure a TD and the associated VPs. The `tdh_mng_addcx.py` and `tdh_vp_addcx.py` scripts add or assign pages of memory to be used by either the TD or its VPs.|
|`tdxtend.py`</br>`tdxamine.py`|The `tdxtend.py` script is a wrapper for the gateway script providing access to Intel TDX specific data structures, interfaces, and error codes. It’s also used to inspect processes that use KVM to extract TDR, TDCS, and TD VP Root (TDVPR) HPAs.</br></br>The `tdxamine.py` script is used to store and lookup TD associated HPAs by name or PID to be used with other scripts. It also stores shared state created by other scripts.|

**Credits: Kirk Swidowski, Daniel Moghimi, Josh Eads, and Erdem Aktas.**