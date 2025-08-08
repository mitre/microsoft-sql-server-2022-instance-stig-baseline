control 'SV-271389' do
  title 'SQL Server must configure Customer Feedback and Error Reporting.'
  desc 'By default, Microsoft SQL Server enables participation in the customer experience improvement program (CEIP). This program collects information about how its customers are using the product. Specifically, SQL Server collects information about the installation experience, feature usage, and performance. This information helps Microsoft improve the product to better meet customer needs.'
  desc 'check', 'Review the values for CustomerFeedback and EnableErrorReporting.

Option 1:
Launch "Registry Editor" 
 
Navigate to:
HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft SQL Server\\[InstanceId]\\CPE 
Review the following values: CustomerFeedback, EnableErrorReporting 
 
Navigate to HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft SQL Server\\160 
Review the following values: CustomerFeedback, EnableErrorReporting 
 
Option 2:
Run the PowerShell commands:

Get-ItemProperty -Path "HKLM:\\Software\\Microsoft\\Microsoft SQL Server\\<SqlInstanceId>\\CPE"
Get-ItemProperty -Path "HKLM:\\ Software\\Microsoft\\Microsoft SQL Server\\160"

Review the following values: CustomerFeedback, EnableErrorReporting

If this is a classified system, and any of the above values are not "0", this is a finding. 
 
If this is an unclassified system, review the server documentation to determine whether CEIP participation is authorized. 
 
If CEIP participation is not authorized, and any of the above values are "1", this is a finding.'
  desc 'fix', 'To disable participation in the CEIP program, change the value of the following registry keys to "0". 
 
To enable participation in the CEIP program, change the value of the following registry keys to "1". 
 
HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft SQL Server\\[InstanceId]\\CPE\\CustomerFeedback 
HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft SQL Server\\[InstanceId]\\CPE\\EnableErrorReporting 
HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft SQL Server\\160\\CustomerFeedback 
HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft SQL Server\\160\\EnableErrorReporting

Or in PowerShell, run:

Set-ItemProperty -Path "HKLM:\\Software\\Microsoft\\Microsoft SQL Server\\[InstanceId]\\CPE" -Name CustomerFeedback -Value 0
Set-ItemProperty -Path "HKLM:\\Software\\Microsoft\\Microsoft SQL Server\\[InstanceId]\\CPE" -Name EnableErrorReporting -Value 0
Set-ItemProperty -Path "HKLM:\\Software\\Microsoft\\Microsoft SQL Server\\160" -Name CustomerFeedback -Value 0
Set-ItemProperty -Path "HKLM:\\Software\\Microsoft\\Microsoft SQL Server\\160" -Name EnableErrorReporting -Value 0'
  impact 0.5
  tag check_id: 'C-75432r1109051_chk'
  tag severity: 'medium'
  tag gid: 'V-271389'
  tag rid: 'SV-271389r1109133_rule'
  tag stig_id: 'SQLI-22-016000'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-75339r1109052_fix'
  tag 'documentable'
  tag legacy: ['SV-94019', 'V-79313']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
