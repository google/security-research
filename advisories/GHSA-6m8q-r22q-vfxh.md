---
title: 'Microsoft: CBC Padding Oracle in Azure Blob Storage Encryption Library'
severity: Moderate
ghsa_id: GHSA-6m8q-r22q-vfxh
cve_id: CVE-2022-30187
weaknesses: []
products:
- ecosystem: NuGet
  package_name: Azure.Storage.Queues
  affected_versions: <12.11.0
  patched_versions: 12.11.0
- ecosystem: NuGet
  package_name: Azure.Storage.Blobs
  affected_versions: <12.13.0
  patched_versions: 12.13.0
cvss: null
credits:
- github_user_id: sophieschmieg
  name: Sophie Schmieg
  avatar: https://avatars.githubusercontent.com/u/53278002?s=40&v=4
---

### Summary

The Azure Storage Encryption library in Java and other languages is vulnerable to a CBC Padding Oracle attack, similar to CVE-2020-8911. The library is not vulnerable to the equivalent of CVE-2020-8912, but only because it currently only supports AES-CBC as encryption mode. 

### Severity

Moderate - The vulnerability poses insider risks/privilege escalation risks, circumventing controls for stored data.

### Further Analysis
The Java Azure Blob Storage Encryption SDK is impacted by an issue that can result in loss of confidentiality and message forgery. The attack requires write access to the container in question, and that the attacker has access to an endpoint that reveals decryption failures (without revealing the plaintext) and that when encrypting the CBC option was chosen as content cipher.

This advisory describes the plaintext revealing vulnerabilities in the Java Azure Blob Storage Encryption SDK, with a similar issue in the other blob storage SDKs being present as well.

In the current version of the Azure Blob Storage crypto SDK, the only algorithm option that allows users to encrypt files is to AES-CBC, without computing a MAC on the data.

This exposes a padding oracle vulnerability: If the attacker has write access to the blob container bucket and can observe whether or not an endpoint with access to the key can decrypt a file (without observing the file contents that the endpoint learns in the process), they can reconstruct the plaintext with (on average) 128*length(plaintext) queries to the endpoint, by exploiting CBC's ability to manipulate the bytes of the next block and PKCS5 padding errors.

### Timeline
**Date reported**: March 29 2022
**Date preview**: June 16 2022
**Date GA**: July 11 2022
**Date disclosed**: July 17 2022