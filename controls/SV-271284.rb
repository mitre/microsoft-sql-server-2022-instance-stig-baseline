control 'SV-271284' do
  title 'SQL Server must limit privileges to change software modules, to include stored procedures, functions and triggers, and links to software external to SQL Server.'
  desc 'If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications. 
 
Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', %q(Review server documentation to determine the process by which shared software libraries are monitored for change. Ensure the process alerts for changes in a file's ownership, modification dates, and hash value at a minimum.

If alerts do not at least hash their value, this is a finding.

To determine the location for these instance-specific binaries:

1. Launch SQL Server Management Studio (SSMS).
2. Connect to the instance to be reviewed.
3. Right-click server name in Object Explorer.
4. Click "Facets".
5. Select the "Server" facet.
6. Record the value for the "RootDirectory" facet property.

Tip: Use the Get-FileHash cmdlet shipped with PowerShell 5.0 to get the SHA-2 hash of one or more files.)
  desc 'fix', 'Implement and document a process by which changes made to software libraries are monitored and alerted. A PowerShell based hashing solution is one such process. The Get-FileHash command can be used to compute the SHA-2 hash of one or more files. For more information, refer to the following link:
https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.utility/get-filehash

Using the Export-Clixml command, a baseline can be established and exported to a file:
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml?view=powershell-7.5

Using the Compare-Object command, a comparison of the latest baseline versus the original baseline can expose the differences:
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-powershell-1.0/ee156812(v=technet.10)?redirectedfrom=MSDN'
  impact 0.5
  tag check_id: 'C-75327r1108991_chk'
  tag severity: 'medium'
  tag gid: 'V-271284'
  tag rid: 'SV-271284r1109111_rule'
  tag stig_id: 'SQLI-22-006600'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-75234r1108992_fix'
  tag 'documentable'
  tag legacy: ['V-79165', 'SV-93871']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
