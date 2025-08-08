control 'SV-271359' do
  title 'SQL Server must maintain a separate execution domain for each executing process.'
  desc 'Database management systems can maintain separate execution domains for each executing process by assigning each process a separate address space.  
 
Each process has a distinct address space so that communication between processes is controlled through the security functions, and one process cannot modify the executing code of another process.  
 
Maintaining separate execution domains for executing processes can be achieved, for example, by implementing separate address spaces.'
  desc 'check', %q(Review the server documentation to determine whether use of CLR assemblies is required. Run the following query to determine whether CLR is enabled for the instance: 
 
SELECT name, value, value_in_use 
FROM sys.configurations 
WHERE name = 'clr enabled' 
 
If "value_in_use" is a "1" and CLR is not required, this is a finding.)
  desc 'fix', "Disable use of or remove any CLR code that is not authorized.

To disable the use of CLR, from the query prompt:  
EXEC SP_CONFIGURE 'clr enabled', 0;
RECONFIGURE WITH OVERRIDE;"
  impact 0.5
  tag check_id: 'C-75402r1111087_chk'
  tag severity: 'medium'
  tag gid: 'V-271359'
  tag rid: 'SV-271359r1111089_rule'
  tag stig_id: 'SQLI-22-012300'
  tag gtitle: 'SRG-APP-000431-DB-000388'
  tag fix_id: 'F-75309r1111088_fix'
  tag 'documentable'
  tag legacy: ['SV-93949', 'V-79243']
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
