---
title: Unsandboxed Password Manager
severity: High
ghsa_id: GHSA-mhhf-w9xw-pp9x
cve_id: null
weaknesses: []
products:
- ecosystem: Password Manager
  package_name: Bitwarden, DashLane, and Safari
  affected_versions: Bitwarden v2022.10.0, Dashlane 6.2242.0, Safari 15.6.1
  patched_versions: ''
cvss: null
credits:
- github_user_id: ddworken
  name: David Dworken
  avatar: https://avatars.githubusercontent.com/u/5304541?s=40&v=4
---

### Summary
Multiple password managers can be tricked into auto-filling credentials into untrusted pages. This can lead to account compromise for any users using these password managers.

### Severity
High - This vulnerability leverages password managers to auto-fill credentials into untrusted pages, without the master password. 

### Proof of Concept

1. Go to https://coop.xss.guru/sign-in and enter credentials
2. Have the password manager save the credentials 
3. Go to https://coop.xss.guru/sign-in-alt and confirm that the password manager autofills the credentials as expected 
4. Go to https://coop.xss.guru/sign-in-phish-csp-sandbox: The password manager should not auto-fill credentials since the page has a CSP sandbox response header
5. Go to https://coop.xss.guru/sign-in-phish-iframe-sandbox: The password manager should not auto-fill credentials since the form is inside of a sandboxed iframe 

### Further Analysis
Password managers should check whether content is sandboxed before auto-filling credentials. This can be done in many ways, but one way is to check [self.origin](https://developer.mozilla.org/en-US/docs/Web/API/origin) of a page and refusing to fill in credentials if self.origin is "null".

1. Bitwarden: Vulnerable - Bitwarden was found to auto-fill credentials into both types of sandboxed content as soon as the user clicked on the Bitwarden chrome extension. [Fixed](https://github.com/bitwarden/clients/pull/3860) and released on 12/14/2022. 
3. DashLane: Vulnerable  - DashLane immediately auto-fills credentials into the CSP sandboxed page. It displays a warning box before auto-filling credentials into the sandboxed iframe.  Fixed and released on 12/2/2022. 
5. Safari: Vulnerable  - Safari auto-fills credentials into both types of sandboxed content though user interaction is required. 
7. LastPass: Secure 
8. 1Password: Secure 
9. Chrome: Secure 
10. Edge: Secure 


### Timeline
**Date reported**: 10/19/2022, Vulnerability reported to Apple on 1/18/2023
**Date fixed**: Fixed in Bitwarden (12/14/2022) and DashLane (12/2/2022)
**Date disclosed**: 1/17/2023