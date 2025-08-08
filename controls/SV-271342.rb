control 'SV-271342' do
  title 'Use of credentials and proxies must be restricted to necessary cases only.'
  desc 'In certain situations, to provide required functionality, a DBMS needs to execute internal logic (stored procedures, functions, triggers, etc.) and/or external code modules with elevated privileges. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking the functionality applications/programs, those users are indirectly provided with greater privileges than assigned by organizations. 
 
Privilege elevation must be used only where necessary and protected from misuse.'
  desc 'check', 'Review the server documentation to obtain a listing of accounts used for executing external processes. Execute the following to obtain a listing of accounts currently configured for use by external processes. 
 
SELECT C.name AS credential_name, C.credential_identity 
FROM sys.credentials C 
GO 
 
SELECT P.name AS proxy_name, C.name AS credential_name, C.credential_identity 
FROM sys.credentials C  
JOIN msdb.dbo.sysproxies P ON C.credential_id = P.credential_id 
WHERE P.enabled = 1 
GO 
 
If any Credentials or SQL Agent Proxy accounts are returned that are not documented and authorized, this is a finding.'
  desc 'fix', "Remove any SQL Agent Proxy accounts and credentials that are not authorized. 
 
DROP CREDENTIAL <Credential Name> 
GO 
 
USE [msdb] 
EXEC sp_delete_proxy @proxy_name = '<Proxy Name>' 
GO"
  impact 0.5
  tag check_id: 'C-75385r1108640_chk'
  tag severity: 'medium'
  tag gid: 'V-271342'
  tag rid: 'SV-271342r1108642_rule'
  tag stig_id: 'SQLI-22-010500'
  tag gtitle: 'SRG-APP-000342-DB-000302'
  tag fix_id: 'F-75292r1108641_fix'
  tag 'documentable'
  tag legacy: ['SV-93927', 'V-79221']
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
