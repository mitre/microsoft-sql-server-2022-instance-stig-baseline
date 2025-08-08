control 'SV-271349' do
  title 'Windows must enforce access restrictions associated with changes to the configuration of the SQL Server instance.'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system.  
 
When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system.  
 
Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Obtain a list of users who have privileged access to the server via the local administrators group. 
 
1. Launch lusrmgr.msc.
2. Select "Groups".
3. Double-click "Administrators".
 
Alternatively, execute the following command in PowerShell: 

net localgroup administrators 
 
Check the server documentation to verify the users returned are authorized. 
 
If the users are not documented and authorized, this is a finding.'
  desc 'fix', 'Remove users from the local Administrators group who are not authorized.'
  impact 0.5
  tag check_id: 'C-75392r1108937_chk'
  tag severity: 'medium'
  tag gid: 'V-271349'
  tag rid: 'SV-271349r1108938_rule'
  tag stig_id: 'SQLI-22-011500'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-75299r1108662_fix'
  tag 'documentable'
  tag legacy: ['SV-82391', 'V-67901', 'SV-93943', 'V-79237']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']

  sql = mssql_session(user: input('user'),
                      password: input('password'),
                      host: input('host'),
                      instance: input('instance'),
                      port: input('port'))

  get_server_permissions = sql.query("SELECT DISTINCT Grantee as 'result' FROM STIG.server_permissions WHERE Permission != 'CONNECT SQL';").column('result')
  get_server_permissions.each do |server_perms|
    a = server_perms.strip
    describe "sql server permissions: #{a}" do
      subject { a }
      it { should be_in ALLOWED_SERVER_PERMISSIONS }
    end
  end

  get_database_permissions = sql.query("SELECT DISTINCT Grantee as 'result' FROM STIG.database_permissions WHERE Permission LIKE '%CREATE%' OR Permission LIKE '%ALTER%' OR Permission IN ('CONTROL', 'INSERT', 'UPDATE', 'DELETE', 'EXECUTE');").column('result')
  get_database_permissions.each do |database_perms|
    a = database_perms.strip
    describe a.to_s do
      it { should be_in ALLOWED_DATABASE_PERMISSIONS }
    end
    describe "sql database permissions: #{a}" do
      subject { a }
      it { should be_in ALLOWED_DATABASE_PERMISSIONS }
    end
  end

  if get_server_permissions.empty? || get_database_permissions
    impact 0.0
    describe 'There are no server or database permissions of concern configured' do
      skip 'This control is not applicable'
    end
  end
end
