control 'SV-271304' do
  title 'SQL Server must be configured to prohibit or restrict the use of organization-defined protocols as defined in the Ports, Protocols, and Services Management (PPSM) Category Assurance List (CAL) and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary protocols on information systems. 
 
Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 
 
To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of protocols to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues. 
 
SQL Server using protocols deemed unsafe is open to attack through those protocols. This can allow unauthorized access to the database and through the database to other components of the information system.

'
  desc 'check', %q(To determine the protocol(s) enabled for SQL Server, open SQL Server Configuration Manager. In the left pane, expand SQL Server Network Configuration. Click on the entry for the SQL Server instance under review: "Protocols for". The right-side pane displays the protocols enabled for the instance. 

Alternatively, run the following SQL Script and review the registry_key for enabled protocols.

SELECT 
*
FROM sys.dm_server_registry
WHERE registry_key like 'HKLM\Software\Microsoft\Microsoft SQL Server\%\MSSQLServer\SuperSocketNetLib\%'
   AND value_name = 'enabled'
   AND value_data = 1
 
If any listed protocols are enabled but not documented and authorized, this is a finding.)
  desc 'fix', 'Navigate to SQL Server Configuration Manager >> SQL Server Network Configuration >> Protocols, then right-click on each listed protocol that is enabled but not authorized and select "Disable".'
  impact 0.5
  tag check_id: 'C-75347r1109265_chk'
  tag severity: 'medium'
  tag gid: 'V-271304'
  tag rid: 'SV-271304r1109265_rule'
  tag stig_id: 'SQLI-22-007600'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-75254r1108844_fix'
  tag satisfies: ['SRG-APP-000142-DB-000094', 'SRG-APP-000383-DB-000364']
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
