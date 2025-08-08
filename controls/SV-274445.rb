control 'SV-274445' do
  title 'The SQL Server default account [sa] must have its name changed.'
  desc "SQL Server's [sa] account has special privileges required to administer the database. The [sa] account is a well-known SQL Server account name and is likely to be targeted by attackers, and is thus more prone to providing unauthorized access to the database.

Since the SQL Server [sa] is administrative in nature, the compromise of a default account can have catastrophic consequences, including the complete loss of control over SQL Server. Since SQL Server needs for this account to exist and it should not be removed, one way to mitigate this risk is to change the [sa] account name."
  desc 'check', %q(Verify the SQL Server default [sa] (system administrator) account name has been changed by executing the following query:

USE master;
GO
SELECT *
FROM sys.sql_logins
WHERE [name] = 'sa' OR [principal_id] = 1;
GO

If the login account name "SA" or "sa" appears in the query output, this is a finding.)
  desc 'fix', "Modify the SQL Server's [sa] (system administrator) account by running the following script:

USE master; 
GO 
ALTER LOGIN [sa] WITH NAME = <new name> 
GO"
  impact 0.5
  tag check_id: 'C-78538r1111102_chk'
  tag severity: 'medium'
  tag gid: 'V-274445'
  tag rid: 'SV-274445r1111103_rule'
  tag stig_id: 'SQLI-22-016300'
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag fix_id: 'F-78443r1109058_fix'
  tag 'documentable'
  tag legacy: ['SV-82345', 'V-67855', 'SV-94025', 'V-79319']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  query_sa = %(
    SELECT * FROM sys.sql_logins WHERE [name] = 'sa' OR [name] = 'SA';
  )

  sql_session = mssql_session(user: input('user'),
                              password: input('password'),
                              host: input('host'),
                              instance: input('instance'),
                              port: input('port'))

  describe 'The sa account in sys.sql_logs' do
    subject { sql_session.query(query_sa).column('name') }
    it { should be_empty }
  end
end
