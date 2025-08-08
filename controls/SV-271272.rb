control 'SV-271272' do
  title 'SQL Server must generate audit records when attempts to access privileges, categorized information, and security objects occur.'
  desc 'Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, monitoring must be possible. DBMSs typically make such information available through views or functions.
 
This requirement includes explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that SQL Server continually performs to determine if any and every action on the database is permitted. 

Changes to the security configuration must also be tracked. 

Security configuration tracking applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality. 

In a SQL environment, types of access include but are not necessarily limited to: 
SELECT 
INSERT 
UPDATE 
DELETE 
EXECUTE

Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected. 
 
For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.
 
To aid in diagnosis, it is necessary to track failed attempts in addition to the successful ones.

'
  desc 'check', "Review the system documentation to determine if SQL Server is required to audit when the following events occur:

- Attempts to retrieve privilege/permission/role membership information.
- Security objects are accessed, modified, or deleted.
- Data classifications (e.g., classification levels/security levels) are accessed, modified, or deleted.
- Any other specified objects are accessed, modified, or deleted as required by the site.

If SQL Server is not required to audit any of the above, this is not a finding. 
 
If the documentation does not exist, this is a finding. 
 
Determine if an audit is configured and started by executing the following query. If no records are returned, this is a finding. 
 
SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
 
If auditing the retrieval of the above information or objects is required, execute the following to verify the SCHEMA_OBJECT_ACCESS_GROUP is included in the server audit specification: 
 
SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' 
 
If the SCHEMA_OBJECT_ACCESS_GROUP is not returned in an active audit, this is a finding."
  desc 'fix', 'Deploy an audit to log when attempts to access privileges, categorized information, security objects, and any other specific objects occur. 

Refer to the supplemental file "SQL 2022 Audit.sql".'
  impact 0.5
  tag check_id: 'C-75315r1108988_chk'
  tag severity: 'medium'
  tag gid: 'V-271272'
  tag rid: 'SV-271272r1109110_rule'
  tag stig_id: 'SQLI-22-004600'
  tag gtitle: 'SRG-APP-000091-DB-000325'
  tag fix_id: 'F-75222r1108989_fix'
  tag satisfies: ['SRG-APP-000091-DB-000325', 'SRG-APP-000091-DB-000066', 'SRG-APP-000492-DB-000332', 'SRG-APP-000492-DB-000333', 'SRG-APP-000494-DB-000344', 'SRG-APP-000494-DB-000345', 'SRG-APP-000498-DB-000346', 'SRG-APP-000498-DB-000347', 'SRG-APP-000502-DB-000348', 'SRG-APP-000502-DB-000349', 'SRG-APP-000507-DB-000356', 'SRG-APP-000507-DB-000357']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
