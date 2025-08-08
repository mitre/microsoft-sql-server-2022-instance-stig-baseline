control 'SV-271293' do
  title 'The SQL Server External Scripts Enabled feature must be disabled, unless specifically required and approved.'
  desc 'SQL Server is capable of providing a wide range of features and services. Some of the default features and services may not be necessary and enabling them could adversely affect the security of the system.

The External Scripts Enabled feature allows scripts external to SQL such as files located in an R library to be executed.'
  desc 'check', "To determine if [External Scripts Enabled] is enabled, execute the following command:
SELECT name, value, value_in_use
FROM sys.configurations
WHERE name = 'External Scripts Enabled'
 
If [value_in_use] is a [1], review the system documentation to determine whether the use of [External Scripts Enabled] is approved. If it is not approved, this is a finding."
  desc 'fix', "Disable use of or remove any external application executable object definitions that are not approved.

To disable the use of [External Scripts Enabled] option, from the query prompt:
EXEC SP_CONFIGURE 'External Scripts Enabled', 0;
RECONFIGURE WITH OVERRIDE;"
  impact 0.5
  tag check_id: 'C-75336r1111136_chk'
  tag severity: 'medium'
  tag gid: 'V-271293'
  tag rid: 'SV-271293r1111138_rule'
  tag stig_id: 'SQLI-22-017700'
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag fix_id: 'F-75243r1111137_fix'
  tag 'documentable'
  tag legacy: ['SV-94053', 'V-79347']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
