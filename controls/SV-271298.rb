control 'SV-271298' do
  title 'The "Remote Access" feature must be disabled unless specifically required and approved.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the default functions and services may not be necessary to support essential organizational operations (e.g., key missions, functions). 

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 

Applications must adhere to the principles of least functionality by providing only essential capabilities.

SQL Server may spawn additional external processes to execute procedures that are defined in the SQL Server but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than SQL Server and provide unauthorized access to the host system.

The "Remote Access" option controls the execution of local stored procedures on remote servers or remote stored procedures on local server. Remote access functionality can be abused to launch a denial-of-service (DoS) attack on remote servers by off-loading query processing to a target.'
  desc 'check', "To determine if [Remote Access] is enabled, execute the following command:
SELECT name, value, value_in_use
FROM sys.configurations
WHERE name = 'Remote Access'
 
If [value_in_use] is a [1], review the system documentation to determine whether the use of [Remote Access] is approved. If it is not approved, this is a finding."
  desc 'fix', "Disable use of [Remote Access] if it is not authorized.
 
To disable the use of [Remote Access], from the query prompt: 
EXEC SP_CONFIGURE 'remote access', 0;
RECONFIGURE WITH OVERRIDE;"
  impact 0.5
  tag check_id: 'C-75341r1111124_chk'
  tag severity: 'medium'
  tag gid: 'V-271298'
  tag rid: 'SV-271298r1111126_rule'
  tag stig_id: 'SQLI-22-017200'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag fix_id: 'F-75248r1111125_fix'
  tag 'documentable'
  tag legacy: ['SV-94043', 'V-79337']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
