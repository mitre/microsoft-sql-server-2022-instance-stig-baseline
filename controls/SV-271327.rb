control 'SV-271327' do
  title 'SQL Server must prevent unauthorized and unintended information transfer via Instant File Initialization (IFI).'
  desc "The purpose of this control is to prevent information, including encrypted representations of information, produced by the actions of a prior user/role (or the actions of a process acting on behalf of a prior user/role) from being available to any current user/role (or current process) that obtains access to a shared system resource (e.g., registers, main memory, secondary storage) after the resource has been released back to the information system. Control of information in shared resources is also referred to as object reuse.

When IFI is in use, the deleted disk content is overwritten only as new data is written to the files. For this reason, the deleted content might be accessed by an unauthorized principal until some other data writes on that specific area of the data file.

Historically, transaction log files couldn't be initialized instantaneously. However, starting with SQL Server 2022 (16.x) (all editions), transaction log autogrowth events up to 64 MB can benefit from instant file initialization. The default auto growth size increment for new databases is 64 MB. Transaction log file autogrowth events larger than 64 MB can't benefit from instant file initialization.

Instant file initialization is allowed for transaction log growth on databases that have transparent data encryption (TDE) enabled, due to the nature of how the transaction log file is expanded, and the fact that the transaction log is written into in a serial fashion."
  desc 'check', 'Review system configuration to determine whether IFI support has been enabled (IFI is enabled by default).

Run the following query in SSMS:

SELECT
	servicename
	,instant_file_initialization_enabled
FROM sys.dm_server_services 

If the column instant_file_initialization_enabled returns a value of "Y", then IFI is enabled.

Alternatively, navigate to Start >> Control Panel >> System and Security >> Administrative Tools >> Local Security Policy >> Local Policies >> User Rights Assignment >> Perform volume maintenance tasks.

The default SQL service account for a default instance is NT SERVICE\\MSSQLSERVER or for a named instance is NT SERVICE\\MSSQL$InstanceName.

If the SQL service account or SQL service SID has been granted "Perform volume maintenance tasks" Local Rights Assignment, this means that IFI is enabled.

Review the system documentation to determine if IFI is required.

If IFI is enabled but not documented as required, this is a finding.

If IFI is not enabled, this is not a finding.'
  desc 'fix', 'If IFI is not documented as being required, disable instant file initialization for the instance of SQL Server by removing the SQL Service SID and/or service account from the "Perform volume maintenance tasks" local rights assignment.

To grant an account the "Perform volume maintenance tasks" permission:

1. On the computer where the data file will be created, open the Local Security Policy application (secpol.msc).
2. In the left pane, expand "Local Policies" then select "User Rights Assignment".
3. In the right pane, double-click "Perform volume maintenance tasks".
4. Select "Add User or Group" and add the SQL Server service account.
5. Select "Apply", then close all Local Security Policy dialog boxes.
6. Restart the SQL Server service.
7. Check the SQL Server error log at startup.'
  impact 0.5
  tag check_id: 'C-75370r1109026_chk'
  tag severity: 'medium'
  tag gid: 'V-271327'
  tag rid: 'SV-271327r1109250_rule'
  tag stig_id: 'SQLI-22-009900'
  tag gtitle: 'SRG-APP-000243-DB-000373'
  tag fix_id: 'F-75277r1109249_fix'
  tag 'documentable'
  tag legacy: ['SV-93919', 'V-79213']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
