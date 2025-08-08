control 'SV-271291' do
  title 'Unused database components, DBMS software, and database objects must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the default functions and services may not be necessary to support essential organizational operations (e.g., key missions, functions). 
 
It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. 
 
DBMSs must adhere to the principles of least functionality by providing only essential capabilities.'
  desc 'check', 'From the server documentation, obtain a listing of required components. 
 
Generate a listing of components installed on the server. 
 
1. Click "Start".
2. Type "SQL Server 2022 Installation Center".
3. Launch the program.
4. Click "Tools".
5. Click "Installed SQL Server features discovery report". 
6. Compare the feature listing against the required components listing. 
 
If any features are installed, but are not required, this is a finding.'
  desc 'fix', 'Remove all features that are not required.'
  impact 0.5
  tag check_id: 'C-75334r1108854_chk'
  tag severity: 'medium'
  tag gid: 'V-271291'
  tag rid: 'SV-271291r1108899_rule'
  tag stig_id: 'SQLI-22-007000'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-75241r1108488_fix'
  tag 'documentable'
  tag legacy: ['SV-93879', 'V-79173']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
