# Security Research

This project hosts security advisories and their accompanying
proof-of-concepts related to research conducted at Google which impact
non-Google owned code.

We believe that vulnerability disclosure is a two-way street. Vendors,
as well as researchers, must act responsibly. This is why Google adheres
to a 90-day disclosure deadline. We notify vendors of vulnerabilities
immediately, with details shared in public with the defensive community
after 90 days, or sooner if the vendor releases a fix.

You can read up on our full policy at:
https://www.google.com/about/appsecurity/.

## Advisories

The disclosure of vulnerabilities are all in the form of security
advisories, which can be browsed in the [Security
Advisories](https://github.com/google/security-research/security/advisories?state=published)
page.

## Proof of Concepts

Accompanying proof-of-concept code will be used to demonstrate the
security vulnerabilities.

| Year | Title | Advisories | Links |
| ---- | ----- | ---------- | ----- |
| 2023 | Linux: eBPF Path Pruning gone wrong | [CVE-2023-2163](https://github.com/google/security-research/security/advisories/GHSA-j87x-j6mh-mv8v) | [PoC](pocs/linux/cve-2023-2163)
| 2023 | XGETBV is non-deterministic on Intel CPUs | | [PoC](pocs/cpus/xgetbv)
| 2023 | XSAVES Instruction May Fail to Save XMM Registers | | [PoC](pocs/cpus/errata/amd/1386)
| 2022 | RET2ASLR - Leaking ASLR from return instructions | | [PoC](pocs/cpus/ret2aslr/src)
| 2022 | Unexpected Speculation Control of RETs | | [PoC](pocs/cpus/top-of-stack)
| 2022 | Bleve Library: Traversal Vulnerabilities in Create / Delete IndexHandler | [GHSA-gc7p-j7x8-h873](https://github.com/google/security-research/security/advisories/GHSA-gc7p-j7x8-h873) | [PoC](pocs/bleve)
| 2022 | Microsoft: CBC Padding Oracle in Azure Blob Storage Encryption Library | [CVE-2022-30187](https://github.com/google/security-research/security/advisories/GHSA-6m8q-r22q-vfxh) | [PoC](pocs/azure/oracle/net/keymaterial/azure)
| 2022 | Apple: Heap-based Buffer Overflow in libresolv | [GHSA-6cjw-q72j-mh57](https://github.com/google/security-research/security/advisories/GHSA-6cjw-q72j-mh57) | [PoC](pocs/apple/libresolv)
| 2022 | Apache: Code execution in log4j2 | [CVE-2021-45046](https://github.com/google/security-research/security/advisories/GHSA-ggmf-hg75-88gg) | [PoC](pocs/log4j)
| 2021 | Surface Pro 3: BIOS False Health Attestation (TPM Carte Blanche) | [CVE-2021-42299](https://github.com/google/security-research/security/advisories/GHSA-c4qg-jj77-rcc3) | [Write-up](https://google.github.io/security-research/pocs/bios/tpm-carte-blanche/writeup.html), [PoC](pocs/bios/tpm-carte-blanche)
| 2021 | CVE-2021-22555: Turning \x00\x00 into 10000$ | [CVE-2021-22555](https://github.com/google/security-research/security/advisories/GHSA-xxx5-8mvq-3528) | [Write-up](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html), [PoC](pocs/linux/cve-2021-22555)
| 2021 | Linux: KVM VM_IO\|VM_PFNMAP vma mishandling | [CVE-2021-22543](https://github.com/google/security-research/security/advisories/GHSA-7wq5-phmq-m584) | [PoC](pocs/linux/kvm_vma)
| 2021 | BleedingTooth: Linux Bluetooth Zero-Click Remote Code Execution | [CVE-2020-24490](https://github.com/google/security-research/security/advisories/GHSA-ccx2-w2r4-x649), [CVE-2020-12351](https://github.com/google/security-research/security/advisories/GHSA-h637-c88j-47wq), [CVE-2020-12352](https://github.com/google/security-research/security/advisories/GHSA-7mh3-gq28-gfrq) | [Write-up](https://google.github.io/security-research/pocs/linux/bleedingtooth/writeup.html), [PoC](pocs/linux/bleedingtooth)

# Licence & Patents

The advisories and patches posted here are free and open source.

See [LICENSE](https://github.com/google/security-research/blob/master/LICENSE) for
further details.

# Contributing

The easiest way to contribute to our security research projects is to
correct the patches when you see mistakes.

Please read up our
[Contribution](https://github.com/google/security-research/blob/master/CONTRIBUTING.md)
policy.
