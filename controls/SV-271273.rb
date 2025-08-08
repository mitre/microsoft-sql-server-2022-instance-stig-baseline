control 'SV-271273' do
  title 'SQL Server must initiate session auditing upon startup.'
  desc "Session auditing is for use when a user's activities are under investigation. To be sure of capturing all activity during those periods when session auditing is in use, it needs to be in operation for the whole time SQL Server is running."
  desc 'check', "When audits are enabled, they start up when the instance starts. Refer to https://msdn.microsoft.com/en-us/library/cc280386.aspx#Anchor_2 
 
Check if an audit is configured and enabled by executing the following query: 
 
SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
WHERE status_desc = 'STARTED' 
 
All currently defined audits for the SQL server instance will be listed. If no audits are returned, this is a finding."
  desc 'fix', "Configure the SQL audit(s) to automatically start during system startup. 
 
ALTER SERVER AUDIT [<Server Audit Name>] WITH STATE = ON 
 
Execute the following: 
 
SELECT name AS 'Audit Name', 
  status_desc AS 'Audit Status', 
  audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
WHERE status_desc = 'STARTED' 
 
Ensure the SQL STIG Audit is configured to initiate session auditing upon startup."
  impact 0.5
  tag check_id: 'C-75316r1108433_chk'
  tag severity: 'medium'
  tag gid: 'V-271273'
  tag rid: 'SV-271273r1109234_rule'
  tag stig_id: 'SQLI-22-004700'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag fix_id: 'F-75223r1109233_fix'
  tag 'documentable'
  tag legacy: ['SV-93847', 'V-79141']
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
