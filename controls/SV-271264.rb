control 'SV-271264' do
  title 'SQL Server must be configured to use the most-secure authentication method available.'
  desc "Enterprise environments make account management for applications and databases challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. Managing accounts for the same person in multiple places is inefficient and prone to problems with consistency and synchronization. 
 
A comprehensive application account management process that includes automation helps to ensure that accounts designated as requiring attention are consistently and promptly addressed. 
 
Examples include, but are not limited to, using automation to act on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in noncentralized account stores, such as multiple servers. Account management functions can also include assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephone notification to report atypical system account usage. 
 
SQL Server must be configured to automatically use organization-level account management functions, and these functions must immediately enforce the organization's current account policy. 
 
Automation may comprise differing technologies that when placed together contain an overall mechanism supporting an organization's automated account management requirements. 
 
SQL Server supports several authentication methods to allow operation in various environments, Kerberos, NTLM, and SQL Server. An instance of SQL Server must be configured to use the most secure method available. Service accounts used by SQL Server should be unique to a given instance."
  desc 'check', 'If the SQL Server is not part of an Active Directory domain, this is Not Applicable. 

Obtain the fully qualified domain name of the SQL Server instance: 

1. Launch Windows Explorer. 
2. Right-click "Computer" or "This PC" (Varies by OS level). 
3. Click "Properties". Note the value shown for "Full computer name". 

Note: For a cluster, this value must be obtained from the Failover Cluster Manager.

Obtain the TCP port that is supporting the SQL Server instance:
 
1. Click "Start".
2. Type "SQL Server 2022 Configuration Manager".
3. From the search results, click "SQL Server 2022 Configuration Manager". 
4. From the tree on the left, expand "SQL Server Network Configuration". 
5. Click "Protocols for <Instance Name>" where <Instance Name> is the name of the instance (MSSQLSERVER is the default name). 
6. In the right pane, right-click "TCP/IP" and choose "Properties". 
7. In the window that opens, click the "IP Addresses" tab. Note the TCP port configured for the instance. 

Obtain the service account that is running the SQL Server service: 

1. Click "Start". 
2. Type "SQL Server 2022 Configuration Manager". 
3. From the search results, click "SQL Server 2022 Configuration Manager". 
4. From the tree on the left, select "SQL Server Services". Note the account listed in the "Log On As" column for the SQL Server instance being reviewed. 
5. Launch a command-line or PowerShell window. 
6. Enter the following command where <Service Account> is the identity of the service account:
      setspn -L <Service Account> 
      Example: setspn -L CONTOSO\\sql2016svc 
7. Review the Registered Service Principal Names returned. 

If the listing does not contain the following supported service principal names (SPN) formats, this is a finding. 

Named instance
   MSSQLSvc/<FQDN>:[<port> | <instancename>], where:
   MSSQLSvc is the service that is being registered.
   <FQDN> is the fully qualified domain name of the server.
   <port> is the TCP port number.
   <instancename> is the name of the SQL Server instance.

Default instance
   MSSQLSvc/<FQDN>:<port> | MSSQLSvc/<FQDN>, where:
   MSSQLSvc is the service that is being registered.
   <FQDN> is the fully qualified domain name of the server.
   <port> is the TCP port number.

If the MSSQLSvc service is registered for any fully qualified domain names that do not match the current server, this may indicate the service account is shared across SQL Server instances. Review server documentation, if the sharing of service accounts across instances is not documented and authorized, this is a finding.'
  desc 'fix', 'Ensure Service Principal Names (SPNs) are properly registered for the SQL Server instance. 

Use the Microsoft Kerberos Configuration Manager to review Kerberos configuration issues for a given SQL Server instance. 

https://www.microsoft.com/en-us/download/details.aspx?id=39046 

Alternatively, SPNs for SQL Server can be manually registered. 

For other connections that support Kerberos the SPN is registered in the format MSSQLSvc/<FQDN>/<instancename> for a named instance. The format for registering the default instance is MSSQLSvc/<FQDN>.

Using an account with permissions to register SPNs, issue the following commands from a command-prompt: 

setspn -S MSSQLSvc/<Fully Qualified Domain Name> <Service Account> 
setspn -S MSSQLSvc/<Fully Qualified Domain Name>:<TCP Port> <Service Account> 
For a named instance, use:
setspn -S MSSQLSvc/<FQDN>:<instancename> <Service Account> 
setspn -S MSSQLSvc/<FQDN>:<TCP Port> <Service Account>

Restart the SQL Server instance. 

More information regarding this process is available at https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/register-a-service-principal-name-for-kerberos-connections#Manual.'
  impact 0.7
  tag check_id: 'C-75307r1109229_chk'
  tag severity: 'high'
  tag gid: 'V-271264'
  tag rid: 'SV-271264r1111061_rule'
  tag stig_id: 'SQLI-22-003800'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag fix_id: 'F-75214r1108407_fix'
  tag 'documentable'
  tag legacy: ['SV-93829', 'V-79123']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
