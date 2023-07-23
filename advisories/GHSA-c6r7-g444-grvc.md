---
title: 'NTFS-3G: Out-of-Bounds read'
severity: High
ghsa_id: GHSA-c6r7-g444-grvc
cve_id: null
weaknesses: []
products:
- ecosystem: NTFS
  package_name: 3G
  affected_versions: 3G
  patched_versions: ''
cvss: null
credits:
- github_user_id: y-zeng
  name: Yuchen Zeng
  avatar: https://avatars.githubusercontent.com/u/17460127?s=40&v=4
---

### Summary
A crafted NTFS image can cause an out-of-bounds read in ntfs_runlists_merge_i in NTFS-3G 2022.5.17


### Severity
High - the issue is similar to [CVE-2021-39253](https://nvd.nist.gov/vuln/detail/CVE-2021-39253), which was categorized as a high vulnerability in NVD.

### Proof of Concept
Mount the fuzzer crafted image with ntfs_mount(image_path, NTFS_MNT_RECOVER).

### Further Analysis
The issue is that ntfs_runlists_merge may lose the end marker of the merged runlist, causing out-of-bounds reads.

In the fuzzer reported case, ntfs_runlists_merge is trying to merge the following two run lists.

The destination list is empty, only has an end marker: [end-marker]

The source list has 2 sections, one LCN_HOLE section with a length of 1, one LCN_ENOENT section of a length of 44 and the end marker: [LCN_HOLE] -> [LCN_ENOENT] -> [end-marker].

When merging these 2 lists, ntfs_runlists_merge tries to avoid the LCN_ENOENT section. So it sets the number of nodes from the source (i.e. ss) to 1.

It later finds the end of the merged list should be from the source list, and sets finish to 1.

It then finds the merge point of the destination list is the end marker, so it does a ss++ to avoid losing an end marker.

However, due to the elimination of the [LCN_ENOENT] node, ss is 1 instead of 2 at the moment. ss++ adds the [LCN_ENOENT] node, but not the [end-marker] node. As a result, the merged runlist does not have an [end-marker] node.

Release: https://github.com/tuxera/ntfs-3g/releases/tag/2022.10.3

### Timeline
**Date reported**: 8/11/2022
**Date fixed**: 10/31/2022
**Date disclosed**: 11/30/2022