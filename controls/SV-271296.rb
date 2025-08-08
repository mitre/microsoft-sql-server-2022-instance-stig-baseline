control 'SV-271296' do
  title 'The "Allow Polybase Export" feature must be disabled, unless specifically required and approved.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the default functions and services may not be necessary to support essential organizational operations (e.g., key missions, functions). 

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 

Applications must adhere to the principles of least functionality by providing only essential capabilities.

SQL Server may spawn additional external processes to execute procedures that are defined in the SQL Server but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than SQL Server and provide unauthorized access to the host system.

The Allow Polybase Export feature allows an export of data to an external data source such as Hadoop File System or Azure Data Lake. An exploit to the SQL Server instance could result in a compromise of the host system and external SQL Server resources.'
  desc 'check', "To determine if [Allow Polybase Export] is enabled, execute the following command:
SELECT name, value, value_in_use
FROM sys.configurations
WHERE name = 'Allow Polybase Export'
 
If [value_in_use] is a [1], review the system documentation to determine whether the use of [Allow Polybase Export] is approved. If it is not approved, this is a finding."
  desc 'fix', "Disable use of or remove any external application executable object definitions that are not approved.

To disable the use of [Allow Polybase Export] option, from the query prompt: 
EXEC SP_CONFIGURE 'Allow Polybase Export', 0;
RECONFIGURE WITH OVERRIDE;"
  impact 0.5
  tag check_id: 'C-75339r1111130_chk'
  tag severity: 'medium'
  tag gid: 'V-271296'
  tag rid: 'SV-271296r1111132_rule'
  tag stig_id: 'SQLI-22-017500'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag fix_id: 'F-75246r1111131_fix'
  tag 'documentable'
  tag legacy: ['SV-94049', 'V-79343']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
