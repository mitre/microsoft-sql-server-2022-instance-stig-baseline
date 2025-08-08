control 'SV-271351' do
  title 'SQL Server must produce audit records when attempts to modify SQL Server configuration and privileges occur within the database(s).'
  desc 'Without auditing the enforcement of access restrictions against changes to configuration, it would be difficult to identify attempted attacks, and an audit trail would not be available for forensic investigation for after-the-fact actions.
 
Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.

Changes in the permissions, privileges, and roles granted to users and roles, as well as privileged activity, must be tracked. Without an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users.
 
A privileged function in this context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In a SQL environment, it encompasses, but is not necessarily limited to, CREATE, ALTER, DROP, GRANT, REVOKE, and DENY. 
 
There may also be Data Manipulation Language (DML) statements that, subject to context, should be regarded as privileged. Possible examples in SQL include TRUNCATE TABLE, SELECT, INSERT, UPDATE, or DELETE (to a security table executed by a user other than a security principal).
 
Depending on the capabilities of SQL Server and the design of the database and associated applications, audit logging may be achieved by means of DBMS auditing features, database triggers, other mechanisms, or a combination of these. 
 
Note that it is particularly important to audit, and tightly control, any action that weakens the implementation of this requirement, since the objective is to have a complete audit trail of all administrative activity.
 
To aid in diagnosis, it is necessary to track failed attempts in addition to the successful ones.

'
  desc 'check', "Review the SQL configuration to verify that audit records are produced when denied actions occur.

To determine if an audit is configured, execute the following script:
SELECT name AS 'Audit Name',
status_desc AS 'Audit Status',
audit_file_path AS 'Current Audit File'
FROM sys.dm_server_audit_status

If no records are returned, this is a finding.

Execute the following to verify the following events are included in the server audit specification:
APPLICATION_ROLE_CHANGE_PASSWORD_GROUP,
AUDIT_CHANGE_GROUP,
BACKUP_RESTORE_GROUP,
DATABASE_CHANGE_GROUP,
DATABASE_OBJECT_ACCESS_GROUP,
DATABASE_OBJECT_CHANGE_GROUP,
DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP,
DATABASE_OBJECT_PERMISSION_CHANGE_GROUP,
DATABASE_OWNERSHIP_CHANGE_GROUP,
DATABASE_OPERATION_GROUP,
DATABASE_PERMISSION_CHANGE_GROUP,
DATABASE_PRINCIPAL_CHANGE_GROUP,
DATABASE_PRINCIPAL_IMPERSONATION_GROUP,
DATABASE_ROLE_MEMBER_CHANGE_GROUP,
DBCC_GROUP,
LOGIN_CHANGE_PASSWORD_GROUP,
LOGOUT_GROUP,
SCHEMA_OBJECT_CHANGE_GROUP,
SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP,
SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP,
SERVER_OBJECT_CHANGE_GROUP,
SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP,
SERVER_OBJECT_PERMISSION_CHANGE_GROUP,
SERVER_OPERATION_GROUP,
SERVER_PERMISSION_CHANGE_GROUP,
SERVER_PRINCIPAL_CHANGE_GROUP,
SERVER_PRINCIPAL_IMPERSONATION_GROUP,
SERVER_ROLE_MEMBER_CHANGE_GROUP,
SERVER_STATE_CHANGE_GROUP,
TRACE_CHANGE_GROUP,
USER_CHANGE_PASSWORD_GROUP

SELECT a.name AS 'AuditName',
s.name AS 'SpecName',
d.audit_action_name AS 'ActionName',
d.audited_result AS 'Result'
FROM sys.server_audit_specifications s
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
WHERE a.is_state_enabled = 1
AND d.audit_action_name IN (
'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
'AUDIT_CHANGE_GROUP',
'BACKUP_RESTORE_GROUP',
'DATABASE_CHANGE_GROUP',
'DATABASE_OBJECT_ACCESS_GROUP',
'DATABASE_OBJECT_CHANGE_GROUP',
'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
'DATABASE_OWNERSHIP_CHANGE_GROUP',
'DATABASE_OPERATION_GROUP',
'DATABASE_PERMISSION_CHANGE_GROUP',
'DATABASE_PRINCIPAL_CHANGE_GROUP',
'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
'DATABASE_ROLE_MEMBER_CHANGE_GROUP', 
'DBCC_GROUP',
'LOGIN_CHANGE_PASSWORD_GROUP',
'LOGOUT_GROUP',
'SCHEMA_OBJECT_CHANGE_GROUP',
'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
'SERVER_OBJECT_CHANGE_GROUP',
'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
'SERVER_OPERATION_GROUP',
'SERVER_PERMISSION_CHANGE_GROUP',
'SERVER_PRINCIPAL_CHANGE_GROUP',
'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
'SERVER_ROLE_MEMBER_CHANGE_GROUP',
'SERVER_STATE_CHANGE_GROUP',
'TRACE_CHANGE_GROUP',
'USER_CHANGE_PASSWORD_GROUP'
)
Order by d.audit_action_name

If the identified groups are not returned, this is a finding."
  desc 'fix', 'Add the required events to the server audit specification to audit denied actions.

Refer to the supplemental file "SQL2022Audit.sql" script.

Reference: https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?'
  impact 0.5
  tag check_id: 'C-75394r1111085_chk'
  tag severity: 'medium'
  tag gid: 'V-271351'
  tag rid: 'SV-271351r1111086_rule'
  tag stig_id: 'SQLI-22-011800'
  tag gtitle: 'SRG-APP-000381-DB-000361'
  tag fix_id: 'F-75301r1109035_fix'
  tag satisfies: ['SRG-APP-000381-DB-000361', 'SRG-APP-000495-DB-000326', 'SRG-APP-000495-DB-000327', 'SRG-APP-000495-DB-000328', 'SRG-APP-000495-DB-000329', 'SRG-APP-000499-DB-000330', 'SRG-APP-000499-DB-000331', 'SRG-APP-000504-DB-000354', 'SRG-APP-000504-DB-000355']
  tag 'documentable'
  tag cci: ['CCI-003938', 'CCI-000172']
  tag nist: ['CM-5 (1) (b)', 'AU-12 c']
end
