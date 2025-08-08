control 'SV-271290' do
  title 'Default demonstration and sample databases, database objects, and applications must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the default functions and services may not be necessary to support essential organizational operations (e.g., key missions, functions). 
 
It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software, demonstrations, or browser plugins not related to requirements or providing a wide array of functionality, not required for every mission, that cannot be disabled. 
 
DBMSs must adhere to the principles of least functionality by providing only essential capabilities. 
 
Demonstration and sample database objects and applications present publicly known attack points for malicious users. These demonstration and sample objects are meant to provide simple examples of coding specific functions and are not developed to prevent vulnerabilities from being introduced to SQL Server and host system.'
  desc 'check', "Review vendor documentation and vendor websites to identify vendor-provided demonstration or sample databases, database applications, objects, and files. Review the SQL Server to determine if any of the demonstration and sample databases, database applications, or files are installed in the database or included with the SQL Server Instance. 

Run the following query to check for names matching known sample databases. Sample databases may have been renamed, so this is not an exhaustive list.

SELECT name
FROM sys.databases
WHERE name LIKE '%pubs%'
OR name LIKE '%northwind%'
OR name LIKE '%adventureworks%'
OR name LIKE '%wideworldimporters%'
OR name LIKE '%contoso%'

If any sample databases are found, this is a finding."
  desc 'fix', 'Remove all demonstration or sample databases from production instances.'
  impact 0.5
  tag check_id: 'C-75333r1108994_chk'
  tag severity: 'medium'
  tag gid: 'V-271290'
  tag rid: 'SV-271290r1109112_rule'
  tag stig_id: 'SQLI-22-006900'
  tag gtitle: 'SRG-APP-000141-DB-000090'
  tag fix_id: 'F-75240r1108485_fix'
  tag 'documentable'
  tag legacy: ['SV-93877', 'V-79171']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
