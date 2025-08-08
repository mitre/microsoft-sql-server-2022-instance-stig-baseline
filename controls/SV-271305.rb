control 'SV-271305' do
  title 'SQL Server must uniquely identify and authenticate users (or processes acting on behalf of organizational users).'
  desc 'To ensure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 
 
Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following: 
 
(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and  
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals using shared accounts for detailed accountability of individual activity.'
  desc 'check', %q(Obtain the list of authorized SQL Server accounts in the system documentation. 

Determine if any accounts are shared. A shared account is defined as a username and password that are used by multiple individuals to log in to SQL Server. Active Directory groups are not shared accounts as the group itself does not have a password. 

Run the following query to return all server-level principals:

SELECT name
FROM sys.server_principals
WHERE type in ('U','S','E')
AND name NOT LIKE '%$'

If any of the returned accounts are shared, determine if individuals are first individually authenticated. 

If individuals are not individually authenticated before using the shared account (e.g., by the operating system or possibly by an application making calls to the database), this is a finding. 

The key is individual accountability. If this can be traced, this is not a finding. 

If accounts are shared, determine if they are directly accessible to end users. If so, this is a finding. 

Review contents of audit logs and data tables to confirm that the identity of the individual user performing the action is captured. 

If shared identifiers are found and not accompanied by individual identifiers, this is a finding.

Execute the following query:

SELECT name
FROM sys.server_principals
WHERE type in ('U','S','E')
AND name LIKE '%$'

If users are returned, determine whether each user is a computer account.

Launch PowerShell.

Execute the following code:

Note: <name> represents the username portion of the user. For example, if the user is "CONTOSO\user1$", the username is "user1".

([ADSISearcher]"(&(ObjectCategory=Computer)(Name=<name>))").FindAll()

If no account information is returned, this is not a finding.

If account information is returned, this is a finding.)
  desc 'fix', 'Remove all shared accounts and computer accounts.

To remove users, run the following command for each user:

DROP USER [ IF EXISTS ] <user_name>;'
  impact 0.5
  tag check_id: 'C-75348r1109006_chk'
  tag severity: 'medium'
  tag gid: 'V-271305'
  tag rid: 'SV-271305r1109239_rule'
  tag stig_id: 'SQLI-22-007800'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-75255r1109007_fix'
  tag 'documentable'
  tag legacy: ['SV-82353', 'V-67863', 'SV-93895', 'V-79189']
  tag cci: ['CCI-000764', 'CCI-000804']
  tag nist: ['IA-2', 'IA-8']

  query = %(
  select name from master.sys.server_principals where is_disabled = 0;
  )

  sql_session = mssql_session(user: input('user'),
                              password: input('password'),
                              host: input('host'),
                              instance: input('instance'),
                              port: input('port'))

  sql_users = sql_session.query(query).column('name')
  sql_users.each do |user|
    describe "authorized sql users: #{user}" do
      subject { user }
      it { should be_in input('authorized_sql_users') }
    end
  end
end
