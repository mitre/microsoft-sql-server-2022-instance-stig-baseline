control 'SV-271286' do
  title 'SQL Server software installation account must be restricted to authorized users.'
  desc 'When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can have significant effects on the overall security of the system. 

If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. Accordingly, only qualified and authorized individuals must be allowed access to information system components for purposes of initiating changes, including upgrades and modifications. 

DBA and other privileged administrative or application owner accounts are granted privileges that allow actions that can have a great impact on SQL Server security and operation. It is especially important to grant privileged access to only those persons who are qualified and authorized to use them.'
  desc 'check', 'From the system documentation, obtain the list of accounts authorized to install/update SQL Server. Run the following PowerShell command to list all users who have installed/modified SQL Server 2022 software and compare the list against those persons who are qualified and authorized to use the software. 
 
sl "C:\\Program files\\Microsoft SQL Server\\160\\Setup Bootstrap\\Log" 
Get-ChildItem -Recurse | Select-String -Pattern "LogonUser = " 
 
If any accounts are shown that are not authorized in the system documentation, this is a finding.'
  desc 'fix', 'From a command prompt, open lusrmgr.msc. Navigate to "Users" and right-click "Individual User". Select "Properties", then "Member Of". 
 
Configure SQL Server and OS settings and access controls to restrict user access to objects and data that the user is authorized to view/use.'
  impact 0.7
  tag check_id: 'C-75329r1108472_chk'
  tag severity: 'high'
  tag gid: 'V-271286'
  tag rid: 'SV-271286r1108474_rule'
  tag stig_id: 'SQLI-22-006700'
  tag gtitle: 'SRG-APP-000133-DB-000198'
  tag fix_id: 'F-75236r1108473_fix'
  tag 'documentable'
  tag legacy: ['SV-82301', 'V-67811', 'SV-93873', 'V-79167']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  describe "SQL Server software installation account(s) must be restricted to
  authorized users" do
    skip 'This is a manual check'
  end
end
