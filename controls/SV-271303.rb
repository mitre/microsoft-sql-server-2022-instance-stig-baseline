control 'SV-271303' do
  title 'SQL Server must be configured to prohibit or restrict the use of organization-defined ports, as defined in the Ports, Protocols, and Services Management (PPSM) Category Assurance List (CAL) and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports on information systems. 
 
Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 
 
To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues. 
 
SQL Server using ports deemed unsafe is open to attack through those ports. This can allow unauthorized access to the database and through the database to other components of the information system.'
  desc 'check', "Review SQL Server Configuration for the ports used by SQL Server. 
 
To determine whether SQL Server is configured to use a fixed port or dynamic ports, in the right-side pane, double-click on the TCP/IP entry to open the Properties dialog. (The default fixed port is 1433.) 

Alternatively, run the following SQL query to determine the port used by SQL Server:

SELECT ISNULL(CONVERT(VARCHAR(25),local_tcp_port),'Dynamic Ports are Enabled')
FROM   sys.dm_exec_connections
WHERE  session_id = @@SPID
 
If any ports in use are in conflict with PPSM guidance and not explained and approved in the system documentation, this is a finding."
  desc 'fix', 'Use SQL Server Configuration to change the ports used by SQL Server to comply with PPSM guidance, or document the need for other ports, and obtain written approval. Close ports no longer needed.'
  impact 0.5
  tag check_id: 'C-75346r1109004_chk'
  tag severity: 'medium'
  tag gid: 'V-271303'
  tag rid: 'SV-271303r1109116_rule'
  tag stig_id: 'SQLI-22-007700'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-75253r1108524_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
