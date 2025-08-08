control 'SV-271306' do
  title 'Contained databases must use Windows principals.'
  desc 'OS/enterprise authentication and identification must be used (SRG-APP-000023-DB-000001). Native DBMS authentication may be used only when circumstances make it unavoidable and must be documented and authorizing official (AO)-approved.
 
The DOD standard for authentication is DOD-approved PKI certificates. Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate and requires AO approval.
 
In such cases, the DOD standards for password complexity and lifetime must be implemented. DBMS products that can inherit the rules for these from the operating system or access control program (e.g., Microsoft Active Directory) must be configured to do so. For other DBMSs, the rules must be enforced using available configuration parameters or custom code.'
  desc 'check', "Execute the following query to determine if Contained Databases are used: 

SELECT * FROM sys.databases WHERE containment = 1

If any records are returned, check the server documentation for a list of authorized contained database users. 

Execute the following query to ensure contained database users are not using SQL Authentication:

EXEC sp_MSforeachdb 'USE [?]; SELECT DB_NAME() AS DatabaseName, *
FROM sys.database_principals dp
inner join sys.databases d on d.name = dp.name
WHERE dp.authentication_type = 2
and d.containment = 1'

If any records are returned, this is a finding."
  desc 'fix', 'Configure SQL Server contained databases to have users originating from Microsoft Entra (Azure Active Directory) principals. Remove any users not created from Microsoft Entra principals. 

Reference Contained Databases: https://learn.microsoft.com/en-us/sql/relational-databases/databases/contained-databases?'
  impact 0.7
  tag check_id: 'C-75349r1109012_chk'
  tag severity: 'high'
  tag gid: 'V-271306'
  tag rid: 'SV-271306r1109119_rule'
  tag stig_id: 'SQLI-22-008000'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-75256r1109013_fix'
  tag 'documentable'
  tag legacy: ['SV-93899', 'V-79193']
  tag cci: ['CCI-000192', 'CCI-004066']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (h)']
end
