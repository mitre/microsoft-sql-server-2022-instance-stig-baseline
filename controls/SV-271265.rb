control 'SV-271265' do
  title 'SQL Server must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.'
  desc "Enterprise environments make account management for applications and databases challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. Managing accounts for the same person in multiple places is inefficient and prone to problems with consistency and synchronization. 
 
A comprehensive application account management process that includes automation helps to ensure that accounts designated as requiring attention are consistently and promptly addressed. 
 
Examples include, but are not limited to, using automation to act on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in noncentralized account stores, such as multiple servers. Account management functions can also include assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example, using email or text messaging to notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephone notification to report atypical system account usage. 
 
SQL Server must be configured to automatically use organization-level account management functions, and these functions must immediately enforce the organization's current account policy. 
 
Automation may be composed of differing technologies that when placed together contain an overall mechanism supporting an organization's automated account management requirements."
  desc 'check', %q(Determine whether SQL Server is configured to use only Windows authentication. 
 
In the Object Explorer in SQL Server Management Studio (SSMS), right-click on the server instance. 
Select "Properties", then select the Security page. 
 
If Windows Authentication Mode is selected, this is not a finding. 
 
OR 
 
In a query interface such as the SSMS Transact-SQL editor, run the statement:  
SELECT CASE SERVERPROPERTY('IsIntegratedSecurityOnly')    
WHEN 1 THEN 'Windows Authentication'    
WHEN 0 THEN 'Windows and SQL Server Authentication'    
END as [Authentication Mode]  
 
If the returned value in the "Authentication Mode" column is "Windows Authentication", this is not a finding. 
 
Mixed mode (both SQL Server authentication and Windows authentication) is in use. If the need for mixed mode has not been documented and approved by the information system security officer (ISSO)/information system security manager (ISSM), this is a finding. 
 
From the documentation, obtain the list of accounts authorized to be managed by SQL Server. 
 
Determine the accounts (SQL Logins) actually managed by SQL Server. Run the statement:  
 
SELECT name 
FROM sys.sql_logins 
WHERE type_desc = 'SQL_LOGIN' AND is_disabled = 0;  
 
If any accounts listed by the query are not listed in the documentation, this is a finding.)
  desc 'fix', %q(If mixed mode is required, document the need and justification; describe the measures taken to ensure the use of SQL Server authentication is kept to a minimum; describe the measures taken to safeguard passwords; and list or describe the SQL Logins used.

Documentation must be approved by the ISSO/ISSM.
 
If mixed mode is not required, disable it as follows:  
 
1. In the SSMS Object Explorer, right-click on the server instance. 
2. Select Properties >> Security page.
3. Click the radio button for "Windows Authentication Mode".
4. Click "OK". 
5. Restart the SQL Server instance. 
 
OR  
 
Run the statement:  

USE [master] 
EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 2 
GO 
 
Restart the SQL Server instance. 
 
For each account being managed by SQL Server but not requiring it, drop or disable the SQL Login. Replace it with an appropriately configured account, as needed. 
 
To drop or disable a login in the SSMS Object Explorer, navigate to "Security Logins". 
Right-click on the login name and click "Delete" or "Disable". 
 
To drop or disable a login by using a query:  

USE master;  
DROP LOGIN login_name; 
ALTER LOGIN login_name DISABLE; 
 
Dropping a login does not delete the equivalent database user(s). There may be more than one database containing a user mapped to the login. Drop the user(s) unless still needed. 
 
To drop a user in the SSMS Object Explorer:  
Navigate to Databases >> Security Users. 
Right-click on the username. 
Click "Delete". 
 
To drop a user via a query:  

USE database_name; 
DROP USER <user_name>;)
  impact 0.7
  tag check_id: 'C-75308r1108409_chk'
  tag severity: 'high'
  tag gid: 'V-271265'
  tag rid: 'SV-271265r1108933_rule'
  tag stig_id: 'SQLI-22-003700'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag fix_id: 'F-75215r1108932_fix'
  tag 'documentable'
  tag legacy: ['SV-82249', 'V-67759', 'SV-93827', 'V-79121']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']

  sql_managed_accounts = input('sql_managed_accounts')

  query = %(
  SELECT
      name
  FROM
      sys.sql_logins
  WHERE
      type_desc = 'SQL_LOGIN'
      AND is_disabled = 0;
)

  sql_session = mssql_session(user: input('user'),
                              password: input('password'),
                              host: input('host'),
                              instance: input('instance'),
                              port: input('port'))

  account_list = sql_session.query(query).column('name')

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft SQL Server\\MSSQL12.MSSQLSERVER\\MSSQLServer') do
    its('LoginMode') { should eq 1 }
  end

  if account_list.empty?
    impact 0.0
    desc 'There are no sql managed accounts, control not applicable'

    describe 'There are no sql managed accounts, control not applicable' do
      skip 'There are no sql managed accounts, control not applicable'
    end
  else
    account_list.each do |account|
      describe "sql managed account: #{account}" do
        subject { account }
        it { should be_in sql_managed_accounts }
      end
    end
  end
end
