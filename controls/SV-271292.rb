control 'SV-271292' do
  title 'The SQL Server Replication Xps feature must be disabled unless specifically required and approved.'
  desc 'SQL Server is capable of providing a wide range of features and services. Some of the default features and services may not be necessary and enabling them could adversely affect the security of the system.

Enabling the replication Xps opens a significant attack surface area that can be used by an attacker to gather information about the system and potentially abuse the privileges of SQL Server.'
  desc 'check', "To determine if [Replication Xps] is enabled, execute the following command:
SELECT name, value, value_in_use
FROM sys.configurations
WHERE name = 'Replication Xps'
 
If [value_in_use] is a [1], review the system documentation to determine whether the use of [Replication Xps] is approved. If it is not approved, this is a finding."
  desc 'fix', "Disable use of or remove any external application executable object definitions that are not approved.

To disable the use of [Replication Xps] option, from the query prompt:
EXEC SP_CONFIGURE 'show advanced options', 1;  
RECONFIGURE WITH OVERRIDE;
EXEC SP_CONFIGURE 'replication xps', 0;
RECONFIGURE WITH OVERRIDE;
EXEC SP_CONFIGURE 'show advanced options', 0;  
RECONFIGURE WITH OVERRIDE;
GO  
RECONFIGURE;  
GO"
  impact 0.5
  tag check_id: 'C-75335r1111141_chk'
  tag severity: 'medium'
  tag gid: 'V-271292'
  tag rid: 'SV-271292r1111143_rule'
  tag stig_id: 'SQLI-22-017900'
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag fix_id: 'F-75242r1111142_fix'
  tag 'documentable'
  tag legacy: ['SV-94057', 'V-79351']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
