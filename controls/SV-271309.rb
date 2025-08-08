control 'SV-271309' do
  title 'If passwords are used for authentication, SQL Server must transmit only encrypted representations of passwords.'
  desc 'The DOD standard for authentication is DOD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires authorizing official (AO) approval.

In such cases, passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.

DBMS passwords sent in clear text format across the network are vulnerable to discovery by unauthorized users. Disclosure of passwords may easily lead to unauthorized access to the database.'
  desc 'check', 'If SQL Server is using "Windows Authentication mode" this requirement can be marked as Not Applicable.

Open SQL Server Configuration Manager by typing "SQL Server 2022 Configuration Manager" in the search bar and pressing "Enter".

Navigate to SQL Server Configuration Manager >> SQL Server Network Configuration. Right-click on "Protocols", where there is a placeholder for the SQL Server instance name and click on "Properties". 

On the "Flags" tab, if "Force Encryption" is set to "NO", this is a finding.

On the "Flags" tab, if "Force Encryption" is set to "YES", examine the certificate used on the "Certificate" tab.

If it is not a DOD approved certificate, or if no certificate is listed, this is a finding.

For clustered instances, the Certificate will NOT be shown in the SQL Server Configuration Manager.

1. From a command prompt, navigate to the certificate store where the Full Qualified Domain Name (FQDN) certificate is stored, by typing "Manage computer certificates" in the search bar and pressing "Enter".
2. In the left side of the window, expand the "Personal" folder, and click "Certificates".
3. Verify the Certificate with the FQDN name is issued by the DOD. Double-click the certificate, click the "Details" tab, and note the value for the Thumbprint.
4. Ensure the value for the "Thumbprint" field matches the value in the registry by running regedit and looking at "HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\<instance>\\MSSQLServer\\SuperSocketNetLib\\Certificate".
5. Run this on each node of the cluster.

If any nodes have a certificate in use by SQL that is not issued or approved by DOD, this is a finding.'
  desc 'fix', 'Configure SQL Server to encrypt authentication data for remote connections using DOD-approved cryptography.

Deploy encryption to the SQL Server Network Connections.

From the search bar, open SQL Server Configuration Manager by typing "SQL Server 2022 Configuration Manager" and pressing "ENTER".

Navigate to SQL Server Configuration Manager >> SQL Server Network Configuration. Right-click on "Protocols for", where there is a placeholder for the SQL Server instance name, and click on "Properties".

In the "Protocols for Properties" dialog box, on the "Certificate" tab, select the DOD certificate from the drop down for the Certificate box, and then click "OK". On the "Flags" tab, in the "ForceEncryption" box, select "Yes", and then click "OK" to close the dialog box. Then restart the SQL Server service.

For clustered instances install the certificate after setting "Force Encryption" to "Yes" in SQL Server Configuration Manager.

1. Navigate to the certificate store where the FQDN certificate is stored, by typing "Manage computer certificates" in the search bar and pressing "ENTER".
2. On the "Properties" page for the certificate, go to the "Details" tab and copy the "thumbprint" value of the certificate to a "Notepad" window.
3. Remove the spaces between the hex characters in the "thumbprint" value in Notepad.
4. Start regedit, navigate to the following registry key, and copy the value from step 2: HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\<instance>\\MSSQLServer\\SuperSocketNetLib\\Certificate.
5. If the SQL virtual server is currently on this node, failover to another node in the cluster, and then reboot the node where the registry change occurred.
6. Repeat this procedure on all the nodes. Configure SQL Server to encrypt authentication data for remote connections using DOD-approved cryptography.

Deploy encryption to the SQL Server Network Connections.'
  impact 0.7
  tag check_id: 'C-75352r1108934_chk'
  tag severity: 'high'
  tag gid: 'V-271309'
  tag rid: 'SV-271309r1109243_rule'
  tag stig_id: 'SQLI-22-008200'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag fix_id: 'F-75259r1109242_fix'
  tag 'documentable'
  tag legacy: ['SV-93901', 'V-79195']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
