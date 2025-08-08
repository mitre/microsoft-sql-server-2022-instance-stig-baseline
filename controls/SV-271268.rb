control 'SV-271268' do
  title 'SQL Server must protect against a user falsely repudiating by ensuring the NT AUTHORITY SYSTEM account is not used for administration.'
  desc "Nonrepudiation of actions taken is required to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 
 
Nonrepudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database. 
 
In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables and configuring the DBMS's audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to the DBMS, even where the application connects to the DBMS with a standard, shared account. 
 
Any user with enough access to the server can execute a task that will be run as NT AUTHORITY\\SYSTEM either using task scheduler or other tools. At this point, NT AUTHORITY\\SYSTEM essentially becomes a shared account because the operating system and SQL Server are unable to determine who created the process. 
 
Prior to SQL Server 2012, NT AUTHORITY\\SYSTEM was a member of the sysadmin role by default. This allowed jobs/tasks to be executed in SQL Server without the approval or knowledge of the DBA because it looked like operating system activity."
  desc 'check', %q(Execute the following queries. The first query checks for clustering and availability groups being provisioned in the database engine. The second query lists permissions granted to the local system account.

SELECT
    SERVERPROPERTY('IsClustered') AS [IsClustered],
    SERVERPROPERTY('IsHadrEnabled') AS [IsHadrEnabled]

EXECUTE AS LOGIN = 'NT AUTHORITY\SYSTEM'

SELECT * FROM fn_my_permissions(NULL, 'server')

REVERT

GO

If "IsClustered" returns "1", "IsHadrEnabled" returns "0", and any permissions have been granted to the Local System account beyond "CONNECT SQL", "VIEW SERVER STATE", and "VIEW ANY DATABASE", this is a finding.
 
If "IsHadrEnabled" returns "1" and any permissions have been granted to the Local System account beyond "CONNECT SQL", "CREATE AVAILABILITY GROUP", "ALTER ANY AVAILABILITY GROUP", "VIEW SERVER STATE", "VIEW ANY DATABASE", "VIEW SERVER PERFORMANCE STATE", and "VIEW SERVER SECURITY STATE", this is a finding.
 
If both "IsClustered" and "IsHadrEnabled" return "0" and any permissions have been granted to the Local System account beyond "CONNECT SQL" and "VIEW ANY DATABASE", this is a finding.)
  desc 'fix', 'Remove permissions that were identified as not allowed in the check content.

USE Master;

REVOKE <Permission> TO [NT AUTHORITY\\SYSTEM]

GO

To grant permissions to services or applications, use the Service SID of the service or a domain service account.'
  impact 0.5
  tag check_id: 'C-75311r1109231_chk'
  tag severity: 'medium'
  tag gid: 'V-271268'
  tag rid: 'SV-271268r1109232_rule'
  tag stig_id: 'SQLI-22-004100'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-75218r1108419_fix'
  tag 'documentable'
  tag legacy: ['SV-93835', 'V-79129']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
