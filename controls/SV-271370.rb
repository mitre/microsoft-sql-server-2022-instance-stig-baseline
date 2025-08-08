control 'SV-271370' do
  title 'SQL Server must generate audit records when successful and unsuccessful attempts to modify or delete security objects occur.'
  desc 'Changes and deletions of the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative. 
 
To aid in diagnosis, it is necessary to track failed attempts in addition to the successful ones.'
  desc 'check', "Review the SQL configuration to verify that audit records are produced when denied actions occur.

To determine if an audit is configured, execute the following script:
SELECT name AS 'Audit Name',
status_desc AS 'Audit Status',
audit_file_path AS 'Current Audit File'
FROM sys.dm_server_audit_status

If no records are returned, this is a finding.

Execute the following to verify the events below are included in the server audit specification:
SCHEMA_OBJECT_CHANGE_GROUP

SELECT a.name AS 'AuditName',
s.name AS 'SpecName',
d.audit_action_name AS 'ActionName',
d.audited_result AS 'Result'
FROM sys.server_audit_specifications s
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
WHERE a.is_state_enabled = 1
AND d.audit_action_name IN (
'SCHEMA_OBJECT_CHANGE_GROUP'
)
Order by d.audit_action_name

If the identified groups are not returned, this is a finding."
  desc 'fix', 'Add the required events to the server audit specification to audit denied actions.

Refer to the supplemental file "SQL2022Audit.sql" script.

Reference: https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?'
  impact 0.5
  tag check_id: 'C-75413r1111090_chk'
  tag severity: 'medium'
  tag gid: 'V-271370'
  tag rid: 'SV-271370r1111091_rule'
  tag stig_id: 'SQLI-22-013800'
  tag gtitle: 'SRG-APP-000496-DB-000334'
  tag fix_id: 'F-75320r1109043_fix'
  tag satisfies: ['SRG-APP-000501-DB-000336', 'SRG-APP-000496-DB-000334', 'SRG-APP-000496-DB-000335', 'SRG-APP-000501-DB-000337']
  tag 'documentable'
  tag legacy: ['SV-93987', 'V-79281']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
