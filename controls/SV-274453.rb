control 'SV-274453' do
  title 'SQL Server must protect against a user falsely repudiating by ensuring that only clearly unique Active Directory user accounts can connect to the database.'
  desc 'Nonrepudiation of actions taken is required to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 

Nonrepudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database.

In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables and configuring SQL Server’s audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to SQL Server, even where the application connects to the DBMS with a standard, shared account.

If the computer account of a remote computer is granted access to a SQL Server database, any service or scheduled task running as NT AUTHORITY\\SYSTEM or NT AUTHORITY\\NETWORK SERVICE can log into the instance and perform actions. These actions cannot be traced back to a specific user or process.'
  desc 'check', %q(Execute the following query:

SELECT name
FROM sys.database_principals
WHERE type in ('U','G')
AND name LIKE '%$'

If no users are returned, this is not a finding.

If users are returned, determine whether each user is a computer account.

Launch PowerShell.

Execute the following code:

Note: <name> represents the username portion of the user. For example, if the user is "CONTOSO\user1$", the username is "user1".

([ADSISearcher]"(&(ObjectCategory=Computer)(Name=<name>))").FindAll()

If no account information is returned, this is not a finding.

If account information is returned, this is a finding.)
  desc 'fix', 'Ensure all logins are uniquely identifiable and authenticate all users who log on to the system. This likely would be done via a combination of Active Directory with unique accounts and the SQL Server by ensuring mapping to individual accounts. Verify server documentation to ensure accounts are documented and unique.

Remove any undocumented accounts or shared accounts that cannot be individually authenticated.'
  impact 0.5
  tag check_id: 'C-78546r1109107_chk'
  tag severity: 'medium'
  tag gid: 'V-274453'
  tag rid: 'SV-274453r1109109_rule'
  tag stig_id: 'SQLI-22-004250'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-78451r1109108_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
