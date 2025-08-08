control 'SV-271387' do
  title 'The SQL Server Browser service must be disabled unless specifically required and approved.'
  desc 'The SQL Server Browser simplifies the administration of SQL Server, particularly when multiple instances of SQL Server coexist on the same computer. It avoids the need to hard-assign port numbers to the instances and to set and maintain those port numbers in client systems. It enables administrators and authorized users to discover database management system instances, and the databases they support, over the network. SQL Server uses the SQL Server Browser service to enumerate instances of the Database Engine installed on the computer. This enables client applications to browse for a server, and helps clients distinguish between multiple instances of the Database Engine on the same computer.

This convenience also presents the possibility of unauthorized individuals gaining knowledge of the available SQL Server resources. Therefore, it is necessary to consider whether the SQL Server Browser is needed. Typically, if only a single instance is installed, using the default name (MSSQLSERVER) and port assignment (1433), the Browser is not adding any value. The more complex the installation, the more likely SQL Server Browser is to be helpful. 

This requirement is not intended to prohibit use of the Browser service in any circumstances.  It calls for administrators and management to consider whether the benefits of its use outweigh the potential negative consequences of it being used by an attacker to browse the current infrastructure and retrieve a list of running SQL Server instances.'
  desc 'check', %q(Open SQL Server Configuration Manager. Select SQL Server Services. Review the Start Mode and State of SQL Server Browser.

If its Start Type is shown as "Disabled", this is not a finding.

If the need for the SQL Server Browser service is documented and authorized, verify the SQL Instances that do not require use of the SQL Browser Service are hidden with the following SQL script:
DECLARE @HiddenInstance INT 
EXEC master.dbo.Xp_instance_regread 
 N'HKEY_LOCAL_MACHINE', 
 N'Software\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib', 
 N'HideInstance', 
 @HiddenInstance output 

SELECT CASE 
        WHEN @HiddenInstance = 0 
             AND Serverproperty('IsClustered') = 0 THEN 'No' 
        ELSE 'Yes' 
      END AS [Hidden]

If the value of "Hidden" is "Yes", this is not a finding.

If the value of "Hidden" is "No" and the startup type of the "SQL Server Browser" service is not "Disabled", this is a finding.)
  desc 'fix', 'If SQL Server Browser is needed, document the justification and obtain the appropriate authorization. 

Where SQL Server Browser is judged unnecessary, the Service can be disabled. 

To disable, in the Services tool, double-click "SQL Server Browser". Set "Startup Type" to "Disabled". If "Service Status" is "Running", click "Stop" and then click "OK".'
  impact 0.5
  tag check_id: 'C-75430r1111139_chk'
  tag severity: 'medium'
  tag gid: 'V-271387'
  tag rid: 'SV-271387r1111140_rule'
  tag stig_id: 'SQLI-22-017800'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-75337r1108871_fix'
  tag 'documentable'
  tag legacy: ['SV-94055', 'V-79349']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
