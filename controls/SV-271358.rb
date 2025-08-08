control 'SV-271358' do
  title 'SQL Server services must be configured to run under unique dedicated user accounts.'
  desc 'Database management systems can maintain separate execution domains for each executing process by assigning each process a separate address space. Each process has a distinct address space so that communication between processes is controlled through the security functions, and one process cannot modify the executing code of another process. Maintaining separate execution domains for executing processes can be achieved, for example, by implementing separate address spaces.'
  desc 'check', 'Review the server documentation to obtain a listing of required service accounts. Review the accounts configured for all SQL Server services installed on the server. 
 
Run the following query in SSMS:

SELECT servicename,service_account FROM sys.dm_server_services
 
Review the returned results. If any services are configured with the same service account or with an account that is not documented and authorized, this is a finding.'
  desc 'fix', 'Configure SQL Server services to have a documented, dedicated account. 
 
For nondomain servers, consider using virtual service accounts (VSAs). 
For more information, refer to: https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions? 
 
For standalone domain-joined servers, consider using managed service accounts. 
For more information, refer to: https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions?
 
For clustered instances, consider using group managed service accounts. 
For more information, refer to: https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions? 
or 
https://learn.microsoft.com/en-us/archive/blogs/markweberblog/group-managed-service-accounts-gmsa-and-sql-server-2016'
  impact 0.5
  tag check_id: 'C-75401r1109039_chk'
  tag severity: 'medium'
  tag gid: 'V-271358'
  tag rid: 'SV-271358r1109129_rule'
  tag stig_id: 'SQLI-22-012400'
  tag gtitle: 'SRG-APP-000431-DB-000388'
  tag fix_id: 'F-75308r1109040_fix'
  tag 'documentable'
  tag legacy: ['SV-93951', 'V-79245']
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
