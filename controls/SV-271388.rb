control 'SV-271388' do
  title 'SQL Server must configure SQL Server Usage and Error Reporting Auditing.'
  desc 'By default, Microsoft SQL Server enables participation in the customer experience improvement program (CEIP). This program collects information about how its customers are using the product. Specifically, SQL Server collects information about the installation experience, feature usage, and performance. This information helps Microsoft improve the product to better meet customer needs. The Local Audit component of SQL Server Usage Feedback collection writes data collected by the service to a designated folder, representing the data (logs) that will be sent to Microsoft. The purpose of the Local Audit is to allow customers to view all data Microsoft collects with this feature, for compliance, regulatory or privacy validation reasons.'
  desc 'check', %q(Review the server documentation to determine if auditing of the telemetry data is required. If auditing of telemetry data is not required, this is not a finding. 
 
If auditing of telemetry data is required, determine the telemetry service username by executing the following query: 
SELECT name 
FROM sys.server_principals 
WHERE name LIKE '%SQLTELEMETRY%' 
 
Review the values of the following registry key: 
Note: InstanceId refers to the type and instance of the feature (e.g., MSSQL16.SqlInstance, MSAS16.SSASInstance, MSRS16.SSRSInstance). 
 
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\[InstanceId]\CPE\UserRequestedLocalAuditDirectory 
 
If the registry key does not exist or the value is blank, this is a finding. 
 
Navigate the path defined in the "UserRequestedLocalAuditDirectory" registry key in file explorer. 
 
Right-click on the folder and choose "Properties". Open the "Security" tab.
 
Verify the SQLTELEMETRY account has the following permissions: 
- List folder contents 
- Read 
- Write 
 
If the permissions are not set properly on the folder, this is a finding. 
 
Open services.msc and find the telemetry service. 
- For Database Engine, use SQL Server CEIP service (<INSTANCENAME>). 
- For Analysis Services, use SQL Server Analysis Services CEIP (<INSTANCENAME>). 
 
Right-click on the service and choose "Properties". Verify the "Startup type" is "Automatic."  
 
If the service is not configured to automatically start, this is a finding. 
 
Review the processes and procedures for reviewing the telemetry data. If there is evidence that the telemetry data is periodically reviewed in accordance with the processes and procedures, this is not a finding. 
 
If no processes and procedures exist for reviewing telemetry data, this is a finding.)
  desc 'fix', 'Configure the instance to audit telemetry data. More information about auditing telemetry data can be found at https://msdn.microsoft.com/en-us/library/mt743085.aspx. 
 
Create a folder to store the telemetry audit data in. 
 
Grant the SQLTELEMETRY service the following permissions on the folder: 
- List folder contents 
- Read 
- Write 
 
Create and configure the following registry key: 
Note: InstanceId refers to the type and instance of the feature. (e.g., MSSQL16.SqlInstance, MSAS16.SSASInstance, MSRS16.SSRSInstance) 
 
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\[InstanceId]\\CPE\\UserRequestedLocalAuditDirectory [string] 
 
Set the "UserRequestedLocalAuditDirectory" key value to the path of the telemetry audit folder. 
 
Set the telemetry service to start automatically. Restart the service. 
- For Database Engine, use SQL Server CEIP service (<INSTANCENAME>). 
- For Analysis Services, use SQL Server Analysis Services CEIP (<INSTANCENAME>).'
  impact 0.5
  tag check_id: 'C-75431r1111096_chk'
  tag severity: 'medium'
  tag gid: 'V-271388'
  tag rid: 'SV-271388r1111098_rule'
  tag stig_id: 'SQLI-22-016100'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-75338r1111097_fix'
  tag 'documentable'
  tag legacy: ['SV-94021', 'V-79315']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
