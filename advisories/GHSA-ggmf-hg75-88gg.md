---
title: 'Apache: Code execution in log4j2'
published: '2022-02-14T06:30:38Z'
severity: High
ghsa_id: GHSA-ggmf-hg75-88gg
cve_id: CVE-2021-45046
weaknesses: []
products:
- ecosystem: Maven
  package_name: log4j2
  affected_versions: 2.15.0
  patched_versions: 2.17.0
cvss: null
credits:
- github_user_id: meder
  name: Meder Kydyraliev
  avatar: https://avatars.githubusercontent.com/u/1212257?s=40&v=4
- github_user_id: sirdarckcat
  name: Eduardo' Vela" <Nava> (sirdarckcat)
  avatar: https://avatars.githubusercontent.com/u/33089?s=40&v=4
- github_user_id: bluec0re
  name: BlueC0re
  avatar: https://avatars.githubusercontent.com/u/638422?s=40&v=4
- github_user_id: ashdoeshax
  name: ash
  avatar: https://avatars.githubusercontent.com/u/3382052?s=40&v=4
---

### Summary
Log4j 2.15.0 was released to address the widely reported JNDI Remote Code Execution (RCE) (CVE-2021-44228) vulnerability in Log4j. Shortly thereafter, 2.16.0 was released to address a Denial of Service (DoS) vulnerability (CVE-2021-45046). When examining the 2.15.0 release, Google security engineers found several issues with the Log4j 2.15.0 patch that showed that the severity of the issue addressed in 2.16 was in fact worse than initially understood. As explained below, RCE was still possible on 2.15 in some environments. This necessitated upgrading the CVSS score from the initial 3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L) to a 9.0 (AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H).

### Severity
[HIGH] - Remote Code Execution is possible in some environments with specific configurations.


### Proof of Concept
[Log4j POC](https://github.com/google/security-research/tree/master/pocs/log4j)
### Further Analysis
The following is a diff of org.apache.logging.log4j.core.net.JndiManager between log4j 2.14.0 and log4j 2.15.0. We can see that several changes were introduced to attempt to limit the exploitation of JNDI LDAP lookup.
```diff
@@ -168,7 +206,55 @@ public class JndiManager extends AbstractManager {
      * @throws  NamingException if a naming exception is encountered
      */
     @SuppressWarnings("unchecked")
-    public <T> T lookup(final String name) throws NamingException {
+    public synchronized <T> T lookup(final String name) throws NamingException {
+        try {
+            URI uri = new URI(name);
+            if (uri.getScheme() != null) {
+                if (!allowedProtocols.contains(uri.getScheme().toLowerCase(Locale.ROOT))) {
+                    LOGGER.warn("Log4j JNDI does not allow protocol {}", uri.getScheme());
+                    return null;
+                }
+                if (LDAP.equalsIgnoreCase(uri.getScheme()) || LDAPS.equalsIgnoreCase(uri.getScheme())) {
+                    if (!allowedHosts.contains(uri.getHost())) {
+                        LOGGER.warn("Attempt to access ldap server not in allowed list");
+                        return null;
+                    }
+                    Attributes attributes = this.context.getAttributes(name);
+                    if (attributes != null) {
+                        // In testing the "key" for attributes seems to be lowercase while the attribute id is
+                        // camelcase, but that may just be true for the test LDAP used here. This copies the Attributes
+                        // to a Map ignoring the "key" and using the Attribute's id as the key in the Map so it matches
+                        // the Java schema.
+                        Map<String, Attribute> attributeMap = new HashMap<>();
+                        NamingEnumeration<? extends Attribute> enumeration = attributes.getAll();
+                        while (enumeration.hasMore()) {
+                            Attribute attribute = enumeration.next();
+                            attributeMap.put(attribute.getID(), attribute);
+                        }
+                        Attribute classNameAttr = attributeMap.get(CLASS_NAME);
+                        if (attributeMap.get(SERIALIZED_DATA) != null) {
+                            if (classNameAttr != null) {
+                                String className = classNameAttr.get().toString();
+                                if (!allowedClasses.contains(className)) {
+                                    LOGGER.warn("Deserialization of {} is not allowed", className);
+                                    return null;
+                                }
+                            } else {
+                                LOGGER.warn("No class name provided for {}", name);
+                                return null;
+                            }
+                        } else if (attributeMap.get(REFERENCE_ADDRESS) != null
+                                || attributeMap.get(OBJECT_FACTORY) != null) {
+                            LOGGER.warn("Referenceable class is not allowed for {}", name);
+                            return null;
+                        }
+                    }
+                }
+            }
+        } catch (URISyntaxException ex) {
+            LOGGER.warn("Invalid JNDI URI - {}", name);
+            return null;
+        }
         return (T) this.context.lookup(name);
     }
```

These changes were intended to 

1. Limit what classes could be deserialized via JNDI LDAP 
2. Limit the LDAP server attributes supported in the JNDI lookup
3. Limit the LDAP connectivity to localhost. 

Each of these 3 controls could be bypassed in which case RCE in a victim application is possible subject to same preconditions for exploitation as initially reported for the DoS in the 2.16 release notes i.e. an attacker is required to be able to inject a JNDI lookup value via a Pattern Layout containing a context Lookup (eg $${ctx:loginId}). 

When these preconditions are met, an attacker is able to exploit the following issues in 2.15.0.

**javaClassName bypass allows arbitrary deserialization**

The changes above introduce a check to see that the javaClassName attribute provided in the LDAP response matches an allowed primitive class (e.g. java.lang.String, java.lang.Boolean). Unfortunately there is no check later on to ensure that the deserialized bytes provided in the response (the javaDeserializedData attribute) correspond to the class name provided and log4j will deserialize any class provided to it. Exploitation of this issue requires suitable classes within the classpath of the target such that an exploitable deserialization gadget chain is present.

**Localhost Restriction Bypass**
The URI class is used to parse and check the destination host for JNDI LDAP lookups using the getHost() method. Unfortunately, there is a canonicalization issue between the value that is checked as returned from URI.getHost() vs what the code will actually attempt to establish an ldap connection to. 

When provided with a string such as domain.com#fragment getHost() will return domain.com. This means a string like ldap://localhost#.appspot.com will pass validation as getHost() returns localhost. Further in the code however, a connection will be established to the entire user string, not just the host portion as returned from getHost().

Will this actually resolve and connect?

Good question! We were wondering this ourselves and the answer is yes, in some cases. On MacOS, this will resolve and connect. On Linux this is dependent upon the distribution and resolver setup in place. Our testing has indicated that this will generally fail on Glibc based systems as the libc resolver specifically checks the format of the DNS name. Other distributions however, such as Alpine, that use the musl will successfully resolve and attempt to connect to such domains. Distributions that use systemd-resolved and have an /etc/nsswitch.conf containing resolve such as Fedora are also vulnerable. We were unable to reproduce this on Windows. 

The combination of the deserialization issue and localhost bypass has been tested and confirmed exploitable on

- Alpine Linux 3.15
- Arch Linux as of 2022-01-26 after enabling the systemd-resolved service
- Arch Linux installer as of 2022-01-26
- Manjaro Linux as of 2022-01-26 after enabling the systemd-resolved service
- Fedora 34
- Fedora 35
- MacOS 12.01

**Time of check / Time of use LDAP vulnerability**

JndiManager performs an attribute lookup via LDAP to check against a set of disallowed attributes such as javaFactory and javaReferenceAddress. 
Later on in the code however, there is a subsequent call to context.lookup() which results in a 2nd request to the LDAP server at which point the server could return an entirely different set of attributes including the ones that JndiManager disallows. 
This provides attackers with an alternative method of exploitation whereby an LDAP server can return a classloaderUrl attribute that will result in an arbitrary class being loaded using java.net.URLClassLoader thus bypassing checks introduced in 2.15.
Note that in JVM 8u191 and above, one needs to set -Dcom.sun.jndi.ldap.object.trustURLCodebase=true to enable arbitrary class loading to occur over HTTP via URLClassLoader.

### Affected Versions

**Log4j 2.16.0 (published December 12 2021)**
These issues are still present in Log4j 2.16.0 however an additional configuration property, log4j.enableJndi (set to false by default) is required to enable Jndi.

**Log4j 2.17.0 (published December 17 2021)**
Log4j 2.17.0 removed support for LDAP from JNDI allowed protocols list and thus these issues no longer apply. The Log4j developers have informed us that they were already planning this prior to our report. 

### Credit
This research was performed by Ash Fox, Meder Kydyraliev, Eduardo Vela and Timo Schmid.


### Timeline
**Date reported**: December 15 2021
**Date fixed**: December 17 2021
**Date disclosed**: February 14 2022

We would like to thank the Apache Log4j team for their response efforts when dealing with the vulnerabilities and their ongoing contribution to open source software.