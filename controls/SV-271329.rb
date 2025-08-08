control 'SV-271329' do
  title 'Access to database files must be limited to relevant processes and to authorized, administrative users.'
  desc 'Applications, including SQL Server, must prevent unauthorized and unintended information transfer via shared system resources. Permitting only DBMS processes and authorized, administrative users to have access to the files where the database resides helps ensure that those files are not shared inappropriately and are not open to backdoor access and manipulation.'
  desc 'check', 'Review the permissions granted to users by the operating system/file system on the database files, database log files, and database backup files. 

To obtain the location of SQL Server data, transaction log, and backup files, open and execute the supplemental file "Get SQL Data and Backup Directories.sql".

For each of the directories returned by the above script, verify whether the correct permissions have been applied.

1. Launch Windows Explorer.
2. Navigate to the folder.
3. Right-click the folder and click "Properties".
4. Navigate to the "Security" tab.
5. Review the listing of principals and permissions.

Account Type Directory Type Permission
-----------------------------------------------------------------------------------------------
Database Administrators      ALL                   Full Control
SQL Server Service SID       Data; Log; Backup;    Full Control
SQL Server Agent Service SID Backup                Full Control
SYSTEM                       ALL                   Full Control
CREATOR OWNER                ALL                   Full Control

For information on how to determine a "Service SID", refer to https://aka.ms/sql-service-sids.

Additional permission requirements, including full directory permissions and operating system rights for SQL Server, are documented at https://aka.ms/sqlservicepermissions.

If any additional permissions are granted but not documented as authorized, this is a finding.'
  desc 'fix', 'Remove any unauthorized permission grants from SQL Server data, log, and backup directories.

1. On the "Security" tab, highlight the user entry.
2. Click "Remove".'
  impact 0.5
  tag check_id: 'C-75372r1108601_chk'
  tag severity: 'medium'
  tag gid: 'V-271329'
  tag rid: 'SV-271329r1108603_rule'
  tag stig_id: 'SQLI-22-010000'
  tag gtitle: 'SRG-APP-000243-DB-000374'
  tag fix_id: 'F-75279r1108602_fix'
  tag 'documentable'
  tag legacy: ['SV-82371', 'V-67881', 'SV-93921', 'V-79215']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']

  describe.one do
    describe file('C:\\Program Files\\Microsoft SQL Server\\MSSQL12.MSSQLSERVER\\MSSQL\\Log') do
      it { should be_allowed('full-control', by_user: 'CREATOR OWNER') }
      it { should be_allowed('full-control', by_user: 'NT AUTHORITY\\SYSTEM') }
      it { should be_allowed('full-control', by_user: 'BUILTIN\\Administrators') }
      it { should be_allowed('full-control', by_user: 'NT SERVICE\\MSSQLSERVER') }
    end
    describe file('C:\\Program Files\\Microsoft SQL Server\\MSSQL12.MSSQLSERVER\\MSSQL\\Log') do
      it { should be_allowed('full-control', by_user: 'CREATOR OWNER') }
      it { should be_allowed('full-control', by_user: 'BUILTIN\\Administrators') }
      it { should be_allowed('full-control', by_user: 'NT SERVICE\\MSSQLSERVER') }
      it { should be_allowed('read', by_user: 'NT SERVICE\\SQLSERVERAGENT') }
    end
  end

  describe.one do
    describe file('C:\\Program Files\\Microsoft SQL Server\\MSSQL12.MSSQLSERVER\\MSSQL\\Log') do
      it { should be_allowed('full-control', by_user: 'CREATOR OWNER') }
      it { should be_allowed('full-control', by_user: 'BUILTIN\\Administrators') }
      it { should be_allowed('full-control', by_user: 'NT SERVICE\\MSSQLSERVER') }
    end
    describe file('C:\\Program Files\\Microsoft SQL Server\\MSSQL12.MSSQLSERVER\\MSSQL\\Log') do
      it { should be_allowed('full-control', by_user: 'CREATOR OWNER') }
      it { should be_allowed('full-control', by_user: 'NT AUTHORITY\\SYSTEM') }
      it { should be_allowed('full-control', by_user: 'BUILTIN\\Administrators') }
      it { should be_allowed('full-control', by_user: 'NT SERVICE\\MSSQLSERVER') }
      it { should be_allowed('read', by_user: 'NT SERVICE\\SQLSERVERAGENT') }
    end
  end
end
