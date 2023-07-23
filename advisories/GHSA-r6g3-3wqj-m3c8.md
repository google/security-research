---
title: 'CISCO: ClamAV Heap Buffer Overflow'
severity: High
ghsa_id: GHSA-r6g3-3wqj-m3c8
cve_id: CVE-2023-20032
weaknesses: []
products:
- ecosystem: CISCO
  package_name: ClamAV
  affected_versions: Multiple, Refer to CISCO Advisory at the bottom of this advisory
  patched_versions: ''
cvss: null
credits:
- github_user_id: scannells
  name: Simon Scannell
  avatar: https://avatars.githubusercontent.com/u/21333136?s=40&v=4
---

### Summary
A heap buffer overflow can be triggered in [ClamAV](https://github.com/Cisco-Talos/clamav)’s [HFSPlus](https://en.wikipedia.org/wiki/HFS_Plus) file-system parsing. The root-issue is a missing size check when copying blocks to a node buffer.

### Severity
We rate the vulnerability as high severity as (1) the buffer overflow can be triggered when a scan is run with `CL_SCAN_ARCHIVE` enabled, which is enabled by default in most configurations. This feature is typically used to scan incoming emails on the backend of mail servers. As such, (2) a remote, external, unauthenticated attacker can trigger this vulnerability.

The buffer overflow is powerful as an attacker can:

Control the size of the target buffer between 512 bytes and 32768 bytes, must be a power of 2
Control the size of the overflow, must be a power of 2
Fully control the data of the overflow
The overflow can be triggered multiple times in a loop


Furthermore, ClamAV supports recursive parsing of various file-formats. As a result, an attacker has reasonable control over the heap. Data structures with function pointers are present in the code and could be used to gain IP control.


### Proof of Concept
The following ZIP file contains a GPT file-system that has a HFS+ partition that triggers the buffer overflow and should cause a crash: [hfsplus.zip](https://drive.google.com/file/d/11Fa6XRktzqg0r_d_Ni4pglzIYj38ozEj/view?usp=share_link&resourcekey=0-ah1RRKZ1TqUkyMJa2xxcXg)

The bug can be triggered by installing ClamAV on a fresh VM and then using the clamscan command to scan the PoC file:

```
sudo apt install -y clamav
clamscan –debug hfsplus.zip
LibClamAV debug: Recognized ZIP file
# …
LibClamAV debug: in cli_magic_scan_desc_type (recursion_level: 0/17)
LibClamAV debug: Recognized Disk Image - GUID Partition Table file
LibClamAV debug: cache_check: 6ea6a4bf1c43d68f524dfbe794976395 is negative
LibClamAV debug: cli_scangpt: detected 512 sector size
LibClamAV Warning: cli_scangpt: detected a non-protective MBR
LibClamAV debug: cli_scangpt: Using primary GPT header
# …
LibClamAV debug: cli_magic_scan_nested_fmap_type: [1536, +180736)
LibClamAV debug: magic_scan_nested_fmap_type: [0, +182784), [1536, +180736)
LibClamAV debug: Recognized HFS+ partition partition
LibClamAV debug: cache_check: 579222d51f405d9822196682aed4a166 is negative
LibClamAV debug: cli_scanhfsplus: scanning partition content
LibClamAV debug: hfsplus_volumeheader: HFS+ signature matched
LibClamAV debug: HFS+ Header:
LibClamAV debug: Signature: 482b
LibClamAV debug: Attributes: 0
LibClamAV debug: File Count: 1
LibClamAV debug: Folder Count: 2
LibClamAV debug: Block Size: 16384
LibClamAV debug: Total Blocks: 1337
# …
LibClamAV debug: cli_scanhfsplus: validation successful
LibClamAV debug: hfsplus_fetch_node: need catalog block 0
LibClamAV debug: hfsplus_fetch_node: found block in extent 0
LibClamAV debug: leaf node Desc: fLink 0 bLink 0 kind 0 height 0 numRecords 0
LibClamAV debug: hfsplus_walk_catalog: invalid leaf node!
double free or corruption (!prev)
Aborted (core dumped)
```

### Further Analysis
#### Root-Cause Analysis
The entry-point for HFS+ scanning in ClamAV is ````cli_scanhfsplus()``` in [libclamav/hfsplus.c](https://github.com/Cisco-Talos/clamav/blob/cf812993b68ba42ff2253da757053cc09fc434cb/libclamav/hfsplus.c#L1423). This function receives a pointer to the current context, this context among other data structures also contains a pointer to the fully user-controlled buffer that was recognized as a HFS+ partition.

HFS+ partitions are divided into blocks, usually 512 bytes large. However, this size may vary and is indicated in the [volume header](https://developer.apple.com/library/archive/technotes/tn/tn1150.html#VolumeHeader). ClamAV parses this header to determine the block size and location of the blocks of the catalog header. The catalog is a B-Tree that contains all files and directories in a HFS+ partition and as such is walked by ClamAV to scan those files for viruses. Each node in the B-Tree also consists of one or more blocks.

``` hfsplus_walk_catalog()``` parses the catalog header and receives the nodeSize from it. A node in the catalog B-Tree contains a variable amount of file entries. These entries contain the file name and point to the block range(s) of the file.


```
<meta charset="utf-8"><b style="font-weight:normal;" id="docs-internal-guid-124c29d9-7fff-ea33-9746-f4eccf05cb27"><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#9c27b0;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">static</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;"> cl_error_t hfsplus_walk_catalog</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">(</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">cli_ctx </span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">*</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">ctx</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">,</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">&nbsp;</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">hfsPlusVolumeHeader </span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">*</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">volHeader</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">,</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">&nbsp;</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">hfsHeaderRecord </span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">*</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">catHeader</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">,</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">hfsHeaderRecord </span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">*</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">extHeader</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">,</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">hfsHeaderRecord </span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">*</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">attrHeader</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">,</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">&nbsp;</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#9c27b0;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">const</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;"> </span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#9c27b0;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">char</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;"> </span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">*</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">dirname</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">)</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">{</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">   cl_error_t ret          </span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">=</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;"> CL_SUCCESS</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">;</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">        </span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#455a64;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">// …</span></p><br /><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">   nodeLimit </span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">=</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;"> MIN</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">(</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">catHeader</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">-&gt;</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">totalNodes</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">,</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;"> HFSPLUS_NODE_LIMIT</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">);</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">   thisNode  </span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">=</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;"> catHeader</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">-&gt;</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">firstLeafNode</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">;</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">   nodeSize  </span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">=</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;"> catHeader</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">-&gt;</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#000000;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">nodeSize</span><span style="font-size:10pt;font-family:Consolas,sans-serif;color:#616161;background-color:transparent;font-weight:400;font-style:normal;font-variant:normal;text-decoration:none;vertical-align:baseline;white-space:pre;white-space:pre-wrap;">;</span></p><br /><div dir="ltr" style="margin-left:0pt;" align="left">

/* Need to buffer current node, map will keep moving */   nodeBuf = cli_malloc(nodeSize);
--


</div></b>
```

Then, the nodes are read by calling ```hfsplus_fetch_node()```. This function calculates the offset of the node into the file-system and the starting block and ending block:

```
static int hfsplus_fetch_node(
cli_ctx *ctx, 
hfsPlusVolumeHeader *volHeader, 
hfsHeaderRecord *catHeader,
hfsHeaderRecord *extHeader, 
hfsPlusForkData *catFork, 
uint32_t node, 
uint8_t *buff)
{
   int foundBlock = 0;
   uint64_t catalogOffset;
   uint32_t startBlock, startOffset;
   uint32_t endBlock, endSize;
   uint32_t curBlock;
   uint32_t extentNum = 0, realFileBlock;
   uint32_t readSize;
   size_t fileOffset = 0;
   uint32_t searchBlock;
   uint32_t buffOffset = 0;

   UNUSEDPARAM(extHeader);

   /* Make sure node is in range */
   if (node >= catHeader->totalNodes) {
       cli_dbgmsg("hfsplus_fetch_node: invalid node number " STDu32 "\n", node);
       return CL_EFORMAT;
   }

   /* Need one block */
   /* First, calculate the node's offset within the catalog */
   catalogOffset = (uint64_t)node * catHeader->nodeSize;
   /* Determine which block of the catalog we need */
   startBlock  = (uint32_t)(catalogOffset / volHeader->blockSize);
   startOffset = (uint32_t)(catalogOffset % volHeader->blockSize);
   endBlock    = (uint32_t)((catalogOffset + catHeader->nodeSize - 1) / volHeader->blockSize);
   endSize     = (uint32_t)(((catalogOffset + catHeader->nodeSize - 1) % volHeader->blockSize) + 1);

// …
   for (curBlock = startBlock; curBlock <= endBlock; ++curBlock) {
       foundBlock  = 0;
       searchBlock = curBlock;

```

As can be seen, the blocks that should be read for this node are calculated by dividing the offset into the file by the blockSize. The code then enters a loop to make sure it can actually find the blocks somewhere on the HFS+ file-system.

One interesting behavior to observe in the code snippet above is that if the blockSize is larger than the nodeSize, both startBlock and endBlock will be 0. The loop will still be entered as the condition curBlock <= endBlock can be satisfied.

When all conditions in the loop are satisfied, the blockSize is finally read into the nodeBuffer, which triggers the buffer overflow as there is no validation that buff (which points to `nodeBuffer` that was allocated in `hfsplus_walk_catalog()`) can contain blockSize:

```
 readSize   = volHeader->blockSize;  

      if (curBlock == startBlock) {
           fileOffset += startOffset;
       } else if (curBlock == endBlock) {
           readSize = endSize;
       }

       cli_dbgmsg("About to write %u bytes into buffer %p (%hu bytes large)\n", readSize, buff, catHeader->nodeSize);

       if (fmap_readn(*ctx->fmap, buff + buffOffset, fileOffset, readSize) != readSize) {
           cli_dbgmsg("hfsplus_fetch_node: not all bytes read\n");
           return CL_EFORMAT;
       }
       buffOffset += readSize;
```


### Timeline
**Date reported**: 11/08/2022
**Date fixed**: 02/15/2023
**Date disclosed**: 02/21/2023

CISCO advisory - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-q8DThCy