---
title: 'Apple: ImageIO renders uninitialized heap memory'
severity: Moderate
ghsa_id: GHSA-4gcf-xm6q-qph7
cve_id: CVE-2022-22611
weaknesses:
- id: CWE-119
  name: Improper Restriction of Operations within the Bounds of a Memory Buffer
- id: CWE-125
  name: Out-of-bounds Read
products:
- ecosystem: Apple
  package_name: ImageIO
  affected_versions: iPhone 6s and later, iPad Pro (all models), iPad Air 2 and later,
    iPad 5th generation and later, iPad mini 4 and later, and iPod touch (7th generation),
    MacOS
  patched_versions: iOS 15.4 and iPadOS 15.4
cvss: null
credits: []
---

### Summary

- CVE-2022-22611: Read OOB issue in ImageIO
- CVE-2022-22612: ImageIO may render uninitialized heap memory

### Severity

- CVE-2022-22611: Medium (Read OOB)
- CVE-2022-22612: Medium (Possible remote information leak)

### Proof of Concept

CVE-2022-22611 and CVE-2022-22612 were discovered by fuzzing.

- CVE-2022-22611 was an read OOB issue in `IIOPixelConverterRGB::convert` found by `libgmalloc`.
- CVE-2022-22612 was more interesting - ImageIO may render uninitialized heap memory. `IIOImageRead::getBytesAtOffset` is supposed to initialize a heap memory and pass it to its caller for image rendering later. However, a crafted image file may let it return prematurely without initializing the heap memory:

<p align="center">
<img width="400" alt="imageio_bug" src="https://user-images.githubusercontent.com/25871159/160909238-a67cd26f-ed9e-47d7-a4c5-8007c436608f.png">
</p>

### Further Analysis

CVE-2022-22612 might also be abused for (partially) recovering viewed and deleted photos. For example, here is the preview of a crafted photo if you view and delete two photos later:

<p align="center">
<img width="400" alt="imageio_bug" src="https://user-images.githubusercontent.com/25871159/160909819-25296774-bae5-463c-8a43-18933f1047ac.png">
</p>


### Timeline
**Date reported**: December 08, 2021
**Date fixed**: March 14, 2022
**Date disclosed**: March 14, 2022