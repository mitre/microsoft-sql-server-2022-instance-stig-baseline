control 'SV-271365' do
  title 'Microsoft SQL Server products must be a version supported by the vendor.'
  desc 'Unsupported commercial and database systems should not be used because fixes to newly identified bugs will not be implemented by the vendor. The lack of support can result in potential vulnerabilities.

Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities, which leaves them subject to exploitation.

When maintenance updates and patches are no longer available, the database software is no longer considered supported and should be upgraded or decommissioned.'
  desc 'check', 'Review the system documentation and interview the database administrator.

Identify all database software components.

Review the version and release information.

Verify the SQL Server version via one of the following methods: 

Connect to the server by using Object Explorer in SQL Server Management Studio. After Object Explorer is connected, it will show the version information in parentheses with the username used to connect to the specific instance of SQL Server.

Or, from SQL Server Management Studio execute the following:
SELECT @@VERSION;

More information for finding the version is available at the following link: https://learn.microsoft.com/en-us/troubleshoot/sql/releases/find-my-sql-version.

Access the vendor website or use other means to verify the version is still supported. Refer to https://learn.microsoft.com/en-us/lifecycle/products/sql-server-2016.

If the installed version or any of the software components are not supported by the vendor, this is a finding.'
  desc 'fix', 'Remove or decommission all unsupported software products.

Upgrade unsupported DBMS or unsupported components to a supported version of the product.'
  impact 0.7
  tag check_id: 'C-75408r1111147_chk'
  tag severity: 'high'
  tag gid: 'V-271365'
  tag rid: 'SV-271365r1111148_rule'
  tag stig_id: 'SQLI-22-018300'
  tag gtitle: 'SRG-APP-000456-DB-000400'
  tag fix_id: 'F-75315r1108710_fix'
  tag 'documentable'
  tag cci: ['CCI-003376']
  tag nist: ['SA-22 a']
end
